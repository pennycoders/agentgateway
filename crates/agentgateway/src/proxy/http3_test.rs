use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_core::strng;
use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::json;

use super::*;
use crate::proxy::request_builder::RequestBuilder;
use crate::test_helpers::proxymock::*;
use crate::types::agent::{
	Bind, BindProtocol, BindSnapshot, Listener, ListenerSet, ServerTLSConfig,
};

const CA_CERT: &[u8] = include_bytes!("../../../../examples/mcp-tls/certs/ca-cert.pem");
const CERT: &[u8] = include_bytes!("../../../../examples/mcp-tls/certs/cert.pem");
const KEY: &[u8] = include_bytes!("../../../../examples/mcp-tls/certs/key.pem");

fn server_tls(root: Option<Vec<u8>>) -> ServerTLSConfig {
	ServerTLSConfig::from_pem(
		CERT.to_vec(),
		KEY.to_vec(),
		root,
		vec![b"h2".to_vec(), b"http/1.1".to_vec()],
	)
	.unwrap()
}

fn free_udp_port() -> u16 {
	std::net::UdpSocket::bind("127.0.0.1:0")
		.unwrap()
		.local_addr()
		.unwrap()
		.port()
}

fn https_listener(tls: ServerTLSConfig) -> Listener {
	Listener {
		key: LISTENER_KEY,
		name: Default::default(),
		hostname: strng::new("*.example.com"),
		protocol: ListenerProtocol::HTTPS(tls),
		..Default::default()
	}
}

/// An HTTPS bind for `*.example.com` on a port that is free for UDP.
fn https_bind(port: u16, tls: ServerTLSConfig) -> BindSnapshot {
	BindSnapshot::new(
		Bind {
			key: BIND_KEY,
			address: SocketAddr::from(([127, 0, 0, 1], port)),
			protocol: BindProtocol::tls,
			tunnel_protocol: Default::default(),
			mode: Default::default(),
		},
		ListenerSet::from_list([https_listener(tls)]),
	)
}

async fn setup_without_serving(
	http3: Option<serde_json::Value>,
	tls: ServerTLSConfig,
) -> (wiremock::MockServer, TestBind, u16) {
	let mock = simple_mock().await;
	let port = free_udp_port();
	let mut t = setup_proxy_test("{}")
		.unwrap()
		.with_backend(*mock.address())
		.with_bind(https_bind(port, tls))
		.with_route(basic_route(*mock.address()));
	if let Some(http3) = http3 {
		t.attach_frontend_policy(json!({ "http": { "http3": http3 } }))
			.await;
	}
	(mock, t, port)
}

async fn setup(http3: Option<serde_json::Value>) -> (wiremock::MockServer, TestBind, u16) {
	let (mock, t, port) = setup_without_serving(http3, server_tls(None)).await;
	t.serve_http3(BIND_KEY);
	(mock, t, port)
}

async fn wait_for_http3(t: &TestBind, serving: bool) {
	tokio::time::timeout(Duration::from_secs(10), async {
		while t.pi.http3.alt_svc(&BIND_KEY, &LISTENER_KEY).is_some() != serving {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("HTTP/3 endpoint did not reach the expected state");
}

struct H3Client {
	send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
	driver: tokio::task::JoinHandle<h3::error::ConnectionError>,
	_conn: quinn::Connection,
	_endpoint: quinn::Endpoint,
}

async fn try_connect(port: u16, sni: &str) -> anyhow::Result<H3Client> {
	let tls: crate::http::backendtls::BackendTLS = crate::http::backendtls::ResolvedBackendTLS {
		cert: None,
		key: None,
		root: Some(CA_CERT.to_vec()),
		hostname: Some(sni.to_string()),
		insecure: false,
		// The test certificate is issued for localhost.
		insecure_host: true,
		alpn: None,
		subject_alt_names: None,
		key_exchange_groups: None,
		spiffe: false,
	}
	.try_into()?;
	let mut config = (*tls.base_config().config).clone();
	config.alpn_protocols = vec![b"h3".to_vec()];
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(config))?;
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
	let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
	// Fail fast when the server does not answer.
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(2).try_into()?));
	client_config.transport_config(Arc::new(transport));
	endpoint.set_default_client_config(client_config);
	let conn = endpoint
		.connect(SocketAddr::from(([127, 0, 0, 1], port)), sni)?
		.await?;
	let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
	let driver = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
	Ok(H3Client {
		send,
		driver,
		_conn: conn,
		_endpoint: endpoint,
	})
}

async fn connect(port: u16, sni: &str) -> H3Client {
	try_connect(port, sni).await.expect("HTTP/3 connection")
}

struct H3Response {
	status: StatusCode,
	headers: HeaderMap,
	body: Bytes,
}

impl H3Response {
	fn dump(&self) -> RequestDump {
		serde_json::from_slice(&self.body).expect("backend request dump")
	}
}

impl H3Client {
	async fn request(&mut self, req: ::http::Request<()>, body: Option<Bytes>) -> H3Response {
		let mut stream = self.send.send_request(req).await.unwrap();
		if let Some(body) = body {
			stream.send_data(body).await.unwrap();
		}
		stream.finish().await.unwrap();
		let resp = stream.recv_response().await.unwrap();
		let mut body = Vec::new();
		while let Some(mut chunk) = stream.recv_data().await.unwrap() {
			body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
		}
		H3Response {
			status: resp.status(),
			headers: resp.headers().clone(),
			body: body.into(),
		}
	}

	async fn get(&mut self, uri: &str) -> H3Response {
		let req = ::http::Request::builder().uri(uri).body(()).unwrap();
		self.request(req, None).await
	}
}

async fn https_get(t: &TestBind) -> crate::http::Response {
	let client = t.serve_https(BIND_KEY, Some("a.example.com"));
	RequestBuilder::new(Method::GET, "http://a.example.com/")
		.send(client)
		.await
		.unwrap()
}

fn remove_all_policies(t: &TestBind) {
	let keys: Vec<_> = t
		.pi
		.stores
		.read_binds()
		.all_policies()
		.iter()
		.map(|p| p.key.clone())
		.collect();
	for key in keys {
		t.pi.stores.binds.write().remove_policy(key);
	}
}

#[tokio::test]
async fn request_through_route() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;

	let mut client = connect(port, "a.example.com").await;
	let resp = client.get("https://a.example.com/foo?bar=baz").await;
	assert_eq!(resp.status, StatusCode::OK);
	let dump = resp.dump();
	assert_eq!(dump.method, Method::GET);
	assert_eq!(dump.uri.path(), "/foo");
	assert_eq!(dump.uri.query(), Some("bar=baz"));
	// The upstream request does not inherit HTTP/3 from the downstream.
	assert_eq!(dump.version, ::http::Version::HTTP_11);
	// HTTP/3 responses do not advertise HTTP/3 again.
	assert!(resp.headers.get(header::ALT_SVC).is_none());

	// Several requests share one connection.
	let resp = client.get("https://a.example.com/second").await;
	assert_eq!(resp.status, StatusCode::OK);
	assert_eq!(resp.dump().uri.path(), "/second");
}

#[tokio::test]
async fn request_body_is_forwarded() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;

	let mut client = connect(port, "a.example.com").await;
	let req = ::http::Request::builder()
		.method(Method::POST)
		.uri("https://a.example.com/upload")
		.header(header::CONTENT_TYPE, "text/plain")
		.body(())
		.unwrap();
	let resp = client
		.request(req, Some(Bytes::from_static(b"hello over quic")))
		.await;
	assert_eq!(resp.status, StatusCode::OK);
	let dump = resp.dump();
	assert_eq!(dump.method, Method::POST);
	assert_eq!(dump.body.as_ref(), b"hello over quic");
}

#[tokio::test]
async fn route_policies_apply() {
	let (_mock, mut t, port) = setup(Some(json!({}))).await;
	t.attach_route_policy(json!({
		"requestHeaderModifier": {"add": {"x-route-req": "route-req"}},
		"responseHeaderModifier": {"add": {"x-route-resp": "route-resp"}},
		"authorization": {"rules": [{"allow": "request.headers[\"x-allowed\"] == \"yes\""}]},
	}))
	.await;
	wait_for_http3(&t, true).await;

	let mut client = connect(port, "a.example.com").await;
	let denied = client.get("https://a.example.com/p").await;
	assert_eq!(denied.status, StatusCode::FORBIDDEN);

	let req = ::http::Request::builder()
		.uri("https://a.example.com/p")
		.header("x-allowed", "yes")
		.body(())
		.unwrap();
	let resp = client.request(req, None).await;
	assert_eq!(resp.status, StatusCode::OK);
	assert_eq!(resp.headers["x-route-resp"], "route-resp");
	assert_eq!(resp.dump().headers["x-route-req"], "route-req");
}

#[tokio::test]
async fn frontend_request_limit_applies() {
	let (_mock, mut t, port) = setup(None).await;
	t.attach_frontend_policy(json!({
		"http": { "http3": {}, "maxConcurrentRequests": 1 },
	}))
	.await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;

	// Keep one request in flight by not finishing its body.
	let req = ::http::Request::builder()
		.method(Method::POST)
		.uri("https://a.example.com/slow")
		.body(())
		.unwrap();
	let mut first = client.send.send_request(req).await.unwrap();
	first
		.send_data(Bytes::from_static(b"partial"))
		.await
		.unwrap();
	tokio::time::sleep(Duration::from_millis(200)).await;

	let rejected = client.get("https://a.example.com/").await;
	assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
	let shed = t
		.pi
		.metrics
		.requests_shed
		.get_or_create(&AdmissionLabels {
			bind: Some(&BIND_KEY).into(),
		})
		.get();
	assert_eq!(shed, 1);

	first.finish().await.unwrap();
	assert_eq!(
		first.recv_response().await.unwrap().status(),
		StatusCode::OK
	);
	while first.recv_data().await.unwrap().is_some() {}
	// Capacity is released once the request completes.
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
}

#[tokio::test]
async fn alt_svc_advertised_only_when_enabled() {
	// Disabled (the default): no Alt-Svc and no UDP socket.
	let (_mock, t, port) = setup(None).await;
	tokio::time::sleep(Duration::from_millis(100)).await;
	let res = https_get(&t).await;
	assert_eq!(res.status(), StatusCode::OK);
	assert!(res.headers().get(header::ALT_SVC).is_none());
	std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port)))
		.expect("the UDP port stays free while HTTP/3 is disabled");

	// Enabled: advertised on the TCP listener, with the configured max age.
	let (_mock, t, port) = setup(Some(json!({"altSvcMaxAge": "1h"}))).await;
	wait_for_http3(&t, true).await;
	let res = https_get(&t).await;
	assert_eq!(res.status(), StatusCode::OK);
	assert_eq!(
		res.headers()[header::ALT_SVC],
		format!("h3=\":{port}\"; ma=3600")
	);
}

#[tokio::test]
async fn alt_svc_requires_a_serving_endpoint() {
	// The policy alone does not advertise HTTP/3; only a bound endpoint does.
	let (_mock, t, port) = setup_without_serving(Some(json!({})), server_tls(None)).await;
	// Something else holds the UDP port, so the endpoint cannot bind.
	let _taken = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
	t.serve_http3(BIND_KEY);
	tokio::time::sleep(Duration::from_millis(200)).await;
	let res = https_get(&t).await;
	assert_eq!(res.status(), StatusCode::OK);
	assert!(res.headers().get(header::ALT_SVC).is_none());
}

#[test]
fn registry_advertises_served_listeners_only() {
	let registry = Http3Registry::default();
	registry.set(
		&BIND_KEY,
		Some(Advertisement {
			listeners: [LISTENER_KEY].into_iter().collect(),
			alt_svc: alt_svc_value(443, Duration::from_secs(60)),
		}),
	);
	let mut headers = HeaderMap::new();
	registry.advertise(&BIND_KEY, &LISTENER_KEY, &mut headers);
	assert_eq!(headers[header::ALT_SVC], "h3=\":443\"; ma=60");

	// An Alt-Svc set by the backend or a policy wins.
	let mut headers = HeaderMap::new();
	headers.insert(header::ALT_SVC, HeaderValue::from_static("clear"));
	registry.advertise(&BIND_KEY, &LISTENER_KEY, &mut headers);
	assert_eq!(headers[header::ALT_SVC], "clear");

	// Other listeners and binds are not advertised.
	let mut headers = HeaderMap::new();
	registry.advertise(&BIND_KEY, &strng::new("other"), &mut headers);
	registry.advertise(&strng::new("other"), &LISTENER_KEY, &mut headers);
	assert!(headers.is_empty());

	registry.set(&BIND_KEY, None);
	assert!(registry.alt_svc(&BIND_KEY, &LISTENER_KEY).is_none());
}

#[tokio::test]
async fn disabling_stops_serving() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);

	remove_all_policies(&t);
	wait_for_http3(&t, false).await;
	let res = https_get(&t).await;
	assert!(res.headers().get(header::ALT_SVC).is_none());

	// The open connection is asked to go away and is closed.
	let err = tokio::time::timeout(Duration::from_secs(10), client.driver)
		.await
		.expect("connection closes after GOAWAY")
		.unwrap();
	assert!(err.is_h3_no_error(), "{err}");
	// New connections are refused.
	assert!(try_connect(port, "a.example.com").await.is_err());
}

#[tokio::test]
async fn reenabling_serves_again() {
	let (_mock, mut t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	remove_all_policies(&t);
	wait_for_http3(&t, false).await;
	t.attach_frontend_policy(json!({ "http": { "http3": {} } }))
		.await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
}

#[tokio::test]
async fn sni_must_match_an_https_listener() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	assert!(try_connect(port, "not-the-domain").await.is_err());
	let mut client = connect(port, "b.example.com").await;
	assert_eq!(
		client.get("https://b.example.com/").await.status,
		StatusCode::OK
	);
}

#[tokio::test]
async fn mtls_listeners_are_not_served() {
	assert!(server_tls(None).http3_cert_resolver().is_some());
	assert!(
		server_tls(Some(CA_CERT.to_vec()))
			.http3_cert_resolver()
			.is_none()
	);
	assert!(
		ServerTLSConfig::spiffe(vec![])
			.http3_cert_resolver()
			.is_none()
	);
	assert!(
		ServerTLSConfig::istio_workload(true, vec![])
			.http3_cert_resolver()
			.is_none()
	);

	// A bind whose only HTTPS listener verifies client certificates opens no endpoint.
	let (_mock, t, _port) =
		setup_without_serving(Some(json!({})), server_tls(Some(CA_CERT.to_vec()))).await;
	assert!(desired_state(&t.pi, &BIND_KEY).unwrap().is_none());
}

#[tokio::test]
async fn tls_policy_must_allow_tls13() {
	let (_mock, mut t, _port) = setup_without_serving(None, server_tls(None)).await;
	t.attach_frontend_policy(json!({
		"http": { "http3": {} },
		"tls": { "maxVersion": "TLS_V1_2" },
	}))
	.await;
	let err = desired_state(&t.pi, &BIND_KEY).err().expect("rejected");
	assert!(err.to_string().contains("TLS 1.3"), "{err}");
}

#[tokio::test]
async fn graceful_drain_closes_connections() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);

	// The drain completes even though a client connection was open, and the client is told to
	// go away.
	t.start_drain().await;
	let err = tokio::time::timeout(Duration::from_secs(10), client.driver)
		.await
		.expect("connection closed")
		.unwrap();
	assert!(err.is_h3_no_error(), "{err}");
}

#[test]
fn connection_headers_are_stripped() {
	let mut headers = HeaderMap::new();
	headers.insert(header::CONNECTION, HeaderValue::from_static("close, x-hop"));
	headers.insert("x-hop", HeaderValue::from_static("1"));
	headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
	headers.insert(
		header::TRANSFER_ENCODING,
		HeaderValue::from_static("chunked"),
	);
	headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
	headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
	strip_connection_headers(&mut headers);
	assert_eq!(headers.len(), 1);
	assert_eq!(headers[header::CONTENT_TYPE], "text/plain");
}

#[test]
fn local_config_parses_http3() {
	let http: frontend::HTTP = serde_json::from_value(json!({
		"http3": {"altSvcMaxAge": "10m", "idleTimeout": "1m", "maxConcurrentStreams": 10}
	}))
	.unwrap();
	let http3 = http.http3.unwrap();
	assert_eq!(http3.alt_svc_max_age(), Duration::from_secs(600));
	assert_eq!(http3.idle_timeout(), Duration::from_secs(60));
	assert_eq!(http3.max_concurrent_streams(), 10);

	let http: frontend::HTTP = serde_json::from_value(json!({"http3": {}})).unwrap();
	let http3 = http.http3.unwrap();
	assert_eq!(
		http3.alt_svc_max_age(),
		frontend::HTTP3::DEFAULT_ALT_SVC_MAX_AGE
	);
	assert_eq!(http3.idle_timeout(), frontend::HTTP3::DEFAULT_IDLE_TIMEOUT);
	assert_eq!(
		http3.max_concurrent_streams(),
		frontend::HTTP3::DEFAULT_MAX_CONCURRENT_STREAMS
	);

	let http: frontend::HTTP = serde_json::from_value(json!({})).unwrap();
	assert!(http.http3.is_none());
	assert!(serde_json::from_value::<frontend::HTTP>(json!({"http3": {"unknown": true}})).is_err());
}

#[test]
fn frontend_policy_changes_notify() {
	let mut store = crate::store::BindStore::default();
	let mut changes = store.subscribe_frontend_policy_changes();
	let policy =
		|key: &str, policy: crate::types::agent::PolicyType| crate::types::agent::TargetedPolicy {
			key: strng::new(key),
			name: None,
			target: crate::types::agent::PolicyTarget::Gateway(crate::types::agent::ListenerTarget {
				gateway_name: strng::new("gw"),
				gateway_namespace: strng::new("ns"),
				listener_name: None,
				port: None,
			}),
			creation_timestamp: 0,
			inheritance: Default::default(),
			policy,
		};
	let frontend = || {
		crate::types::agent::PolicyType::Frontend(crate::types::agent::FrontendPolicy::HTTP(
			frontend::HTTP {
				http3: Some(Default::default()),
				..Default::default()
			},
		))
	};

	store.insert_policy(policy("frontend", frontend()));
	assert!(changes.has_changed().unwrap());
	changes.mark_unchanged();
	store.remove_policy(strng::new("frontend"));
	assert!(changes.has_changed().unwrap());
	changes.mark_unchanged();
	// Removing an unknown policy is not a change.
	store.remove_policy(strng::new("frontend"));
	assert!(!changes.has_changed().unwrap());
}

#[tokio::test]
async fn listener_added_after_policy() {
	let mock = simple_mock().await;
	let port = free_udp_port();
	let mut bind = https_bind(port, server_tls(None));
	bind.listeners = Arc::new(ListenerSet::default());
	let mut t = setup_proxy_test("{}")
		.unwrap()
		.with_backend(*mock.address())
		.with_bind(bind)
		.with_route(basic_route(*mock.address()));
	t.attach_frontend_policy(json!({ "http": { "http3": {} } }))
		.await;
	t.serve_http3(BIND_KEY);
	tokio::time::sleep(Duration::from_millis(100)).await;
	assert!(t.pi.http3.alt_svc(&BIND_KEY, &LISTENER_KEY).is_none());

	t.pi
		.stores
		.binds
		.write()
		.insert_listener(https_listener(server_tls(None)), BIND_KEY);
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
}

#[tokio::test]
async fn request_header_size_is_limited() {
	let (_mock, mut t, port) = setup(None).await;
	t.attach_frontend_policy(json!({
		"http": { "http3": {}, "http2MaxHeaderSize": 1024 },
	}))
	.await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	let req = ::http::Request::builder()
		.uri("https://a.example.com/")
		.header("x-large", "a".repeat(2048))
		.body(())
		.unwrap();
	let mut stream = client.send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	let resp = stream.recv_response().await.unwrap();
	assert_eq!(resp.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);

	// The connection keeps serving requests within the limit.
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
}
