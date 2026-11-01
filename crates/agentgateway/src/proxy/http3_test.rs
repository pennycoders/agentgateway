use std::future::poll_fn;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use agent_core::strng;
use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

fn bind_at(address: SocketAddr, listeners: ListenerSet) -> BindSnapshot {
	BindSnapshot::new(
		Bind {
			key: BIND_KEY,
			address,
			protocol: BindProtocol::tls,
			tunnel_protocol: Default::default(),
			mode: Default::default(),
		},
		listeners,
	)
}

/// An HTTPS bind for `*.example.com` on a port that is free for UDP.
fn https_bind(port: u16, tls: ServerTLSConfig) -> BindSnapshot {
	bind_at(
		SocketAddr::from(([127, 0, 0, 1], port)),
		ListenerSet::from_list([https_listener(tls)]),
	)
}

fn test_with(backend: SocketAddr, bind: BindSnapshot) -> TestBind {
	setup_proxy_test("{}")
		.unwrap()
		.with_backend(backend)
		.with_bind(bind)
		.with_route(basic_route(backend))
}

async fn setup_without_serving(
	http3: Option<serde_json::Value>,
	tls: ServerTLSConfig,
) -> (wiremock::MockServer, TestBind, u16) {
	let mock = simple_mock().await;
	let port = free_udp_port();
	let mut t = test_with(*mock.address(), https_bind(port, tls));
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

/// Serves HTTP/3 on `*.example.com` with the given frontend policy, proxying to `backend`.
async fn serve_with_policy(backend: SocketAddr, policy: serde_json::Value) -> (TestBind, u16) {
	let port = free_udp_port();
	let mut t = test_with(backend, https_bind(port, server_tls(None)));
	t.attach_frontend_policy(policy).await;
	t.serve_http3(BIND_KEY);
	wait_for_http3(&t, true).await;
	(t, port)
}

async fn wait_for_http3(t: &TestBind, serving: bool) {
	tokio::time::timeout(Duration::from_secs(10), async {
		while t.pi.http3.is_serving(&BIND_KEY, &LISTENER_KEY) != serving {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("HTTP/3 endpoint did not reach the expected state");
}

struct H3Client {
	send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
	driver: tokio::task::JoinHandle<h3::error::ConnectionError>,
	conn: quinn::Connection,
	_endpoint: quinn::Endpoint,
}

fn client_tls(sni: &str) -> anyhow::Result<rustls::ClientConfig> {
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
	Ok(config)
}

fn client_endpoint(config: rustls::ClientConfig) -> anyhow::Result<quinn::Endpoint> {
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(config))?;
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
	let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
	// Fail fast when the server does not answer.
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(2).try_into()?));
	client_config.transport_config(Arc::new(transport));
	endpoint.set_default_client_config(client_config);
	Ok(endpoint)
}

async fn try_connect(port: u16, sni: &str) -> anyhow::Result<H3Client> {
	let endpoint = client_endpoint(client_tls(sni)?)?;
	let conn = endpoint
		.connect(SocketAddr::from(([127, 0, 0, 1], port)), sni)?
		.await?;
	let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
	let driver = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
	Ok(H3Client {
		send,
		driver,
		conn,
		_endpoint: endpoint,
	})
}

async fn connect(port: u16, sni: &str) -> H3Client {
	try_connect(port, sni).await.expect("HTTP/3 connection")
}

/// Connects and sends one GET, reporting any failure instead of panicking.
async fn try_get(port: u16, sni: &str) -> anyhow::Result<StatusCode> {
	let mut client = try_connect(port, sni).await?;
	let req = ::http::Request::builder()
		.uri(format!("https://{sni}/"))
		.body(())?;
	let mut stream = client.send.send_request(req).await?;
	stream.finish().await?;
	Ok(stream.recv_response().await?.status())
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

/// Waits for the client connection to be closed by the server, gracefully.
async fn expect_graceful_close(client: H3Client) {
	let err = tokio::time::timeout(Duration::from_secs(10), client.driver)
		.await
		.expect("connection closes after GOAWAY")
		.unwrap();
	assert!(err.is_h3_no_error(), "{err}");
}

/// A raw HTTP/1.1 backend that answers every request with `response` and then closes the
/// connection. Reports each request it read.
async fn raw_backend(
	response: &'static [u8],
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<()>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
	tokio::spawn(async move {
		while let Ok((mut conn, _)) = listener.accept().await {
			let tx = tx.clone();
			tokio::spawn(async move {
				read_request_head(&mut conn).await;
				let _ = tx.send(());
				let _ = conn.write_all(response).await;
			});
		}
	});
	(addr, rx)
}

async fn read_request_head(conn: &mut tokio::net::TcpStream) {
	let mut head = Vec::new();
	let mut buf = [0u8; 1024];
	while !head.windows(4).any(|w| w == b"\r\n\r\n") {
		let n = conn.read(&mut buf).await.unwrap();
		assert_ne!(n, 0, "connection closed before the request head");
		head.extend_from_slice(&buf[..n]);
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
	// A request without a body is forwarded without one (RFC 9114, section 4.1).
	assert!(
		dump.headers.get(header::TRANSFER_ENCODING).is_none(),
		"{:?}",
		dump.headers
	);
	assert!(dump.headers.get(header::CONTENT_LENGTH).is_none());
	// HTTP/3 responses do not advertise HTTP/3 again.
	assert!(resp.headers.get(header::ALT_SVC).is_none());

	// Several requests share one connection.
	let resp = client.get("https://a.example.com/second").await;
	assert_eq!(resp.status, StatusCode::OK);
	assert_eq!(resp.dump().uri.path(), "/second");

	// Connections are labelled as HTTP/3.
	let labels = TCPLabels {
		bind: Some(&BIND_KEY).into(),
		gateway: Some(Listener::default().name.as_gateway_name()).into(),
		listener: Listener::default().name.listener_name.clone().into(),
		protocol: TransportProtocol::http3,
	};
	assert_eq!(
		t.pi
			.metrics
			.downstream_connection
			.get_or_create(&labels)
			.get(),
		1
	);

	// The bytes of the connection are recorded once it is closed.
	client.conn.close(0u32.into(), b"");
	let metrics = &t.pi.metrics;
	tokio::time::timeout(Duration::from_secs(5), async {
		while metrics.tcp_downstream_rx_bytes.get_or_create(&labels).get() == 0 {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("received bytes are recorded");
	assert!(metrics.tcp_downstream_tx_bytes.get_or_create(&labels).get() > 0);
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

	// With a content-length, the body is forwarded with that length.
	let req = ::http::Request::builder()
		.method(Method::POST)
		.uri("https://a.example.com/upload")
		.header(header::CONTENT_LENGTH, "5")
		.body(())
		.unwrap();
	let resp = client
		.request(req, Some(Bytes::from_static(b"hello")))
		.await;
	assert_eq!(resp.status, StatusCode::OK);
	let dump = resp.dump();
	assert_eq!(dump.body.as_ref(), b"hello");
	assert_eq!(dump.headers[header::CONTENT_LENGTH], "5");
	assert!(dump.headers.get(header::TRANSFER_ENCODING).is_none());
}

#[tokio::test]
async fn content_length_must_match_the_body() {
	let (mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	for body in [&b"hi"[..], &b"too long"[..]] {
		let req = ::http::Request::builder()
			.method(Method::POST)
			.uri("https://a.example.com/upload")
			.header(header::CONTENT_LENGTH, "5")
			.body(())
			.unwrap();
		let mut stream = client.send.send_request(req).await.unwrap();
		stream
			.send_data(Bytes::copy_from_slice(body))
			.await
			.unwrap();
		stream.finish().await.unwrap();
		// The request is malformed (RFC 9114, section 4.1.2); it never succeeds.
		if let Ok(resp) = stream.recv_response().await {
			assert_ne!(resp.status(), StatusCode::OK);
		}
	}
	let received = mock.received_requests().await.unwrap_or_default();
	assert!(
		received
			.iter()
			.all(|r| r.body.len() == 5 || r.body.is_empty()),
		"a body not matching its content-length reached the backend"
	);
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
async fn ipv4_clients_on_a_dual_stack_bind_are_canonical() {
	let mock = simple_mock().await;
	let port = std::net::UdpSocket::bind("[::]:0")
		.unwrap()
		.local_addr()
		.unwrap()
		.port();
	let bind = bind_at(
		SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
		ListenerSet::from_list([https_listener(server_tls(None))]),
	);
	let mut t = test_with(*mock.address(), bind);
	t.attach_frontend_policy(json!({
		"http": { "http3": {} },
		// The client connects from 127.0.0.1, which a dual-stack socket reports as ::ffff:127.0.0.1.
		"networkAuthorization": {
			"rules": ["cidr('127.0.0.0/8').containsIP(source.address) && cidr('127.0.0.0/8').containsIP(destination.address)"],
		},
	}))
	.await;
	t.serve_http3(BIND_KEY);
	wait_for_http3(&t, true).await;

	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
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
async fn request_capacity_is_taken_after_headers() {
	let mock = simple_mock().await;
	let (t, port) = serve_with_policy(
		*mock.address(),
		json!({ "http": { "http3": {}, "maxConcurrentRequests": 1, "http1IdleTimeout": "1s" } }),
	)
	.await;
	let mut client = connect(port, "a.example.com").await;

	// A request stream whose headers never complete: only the type of a HEADERS frame.
	let (mut send, mut recv) = client.conn.open_bi().await.unwrap();
	send.write_all(&[0x01]).await.unwrap();
	tokio::time::sleep(Duration::from_millis(200)).await;

	// It does not hold the only request slot.
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
	// It is rejected once the header timeout passes.
	let err = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
		.await
		.expect("the stream is reset after the header timeout")
		.expect_err("no response is sent");
	assert!(
		matches!(
			err,
			quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))
				if code.into_inner() == Code::H3_REQUEST_REJECTED.value()
		),
		"{err:?}"
	);
	// The client is asked to stop sending the request with the same code (RFC 9114, section
	// 4.1.1).
	let stopped = tokio::time::timeout(Duration::from_secs(5), send.stopped())
		.await
		.expect("the client is asked to stop sending")
		.unwrap();
	assert_eq!(
		stopped.map(quinn::VarInt::into_inner),
		Some(Code::H3_REQUEST_REJECTED.value())
	);
	drop(t);
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

	// The advertised port can differ from the bound one, for NAT or load balancers.
	let (_mock, t, _port) = setup(Some(json!({"altSvcPort": 443}))).await;
	wait_for_http3(&t, true).await;
	assert_eq!(
		https_get(&t).await.headers()[header::ALT_SVC],
		"h3=\":443\"; ma=86400"
	);
}

#[tokio::test]
async fn binding_is_retried_until_the_port_is_free() {
	// The policy alone does not advertise HTTP/3; only a bound endpoint does.
	let (_mock, t, port) = setup_without_serving(Some(json!({})), server_tls(None)).await;
	// Something else holds the UDP port, so the endpoint cannot bind.
	let taken = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
	t.serve_http3(BIND_KEY);
	tokio::time::sleep(Duration::from_millis(200)).await;
	let res = https_get(&t).await;
	assert_eq!(res.status(), StatusCode::OK);
	assert!(res.headers().get(header::ALT_SVC).is_none());

	// Once the port is free, the endpoint binds without any configuration change.
	drop(taken);
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
}

#[test]
fn registry_advertises_served_listeners_only() {
	let registry = Http3Registry::default();
	let advertisement = || Advertisement {
		listeners: [LISTENER_KEY].into_iter().collect(),
		alt_svc: alt_svc_value(443, Duration::from_secs(60)),
		max_age: Duration::from_secs(60),
	};
	registry.set(&BIND_KEY, 0, Some(advertisement()));
	let mut headers = HeaderMap::new();
	registry.advertise(&BIND_KEY, &LISTENER_KEY, &mut headers);
	assert_eq!(headers[header::ALT_SVC], "h3=\":443\"; ma=60");
	assert!(registry.is_serving(&BIND_KEY, &LISTENER_KEY));

	// An Alt-Svc set by the backend or a policy wins.
	let mut headers = HeaderMap::new();
	headers.insert(header::ALT_SVC, HeaderValue::from_static("h2=\":8443\""));
	registry.advertise(&BIND_KEY, &LISTENER_KEY, &mut headers);
	assert_eq!(headers[header::ALT_SVC], "h2=\":8443\"");

	// Other listeners and binds are not advertised.
	let mut headers = HeaderMap::new();
	registry.advertise(&BIND_KEY, &strng::new("other"), &mut headers);
	registry.advertise(&strng::new("other"), &LISTENER_KEY, &mut headers);
	assert!(headers.is_empty());

	// Once HTTP/3 stops, clients are told to forget it for as long as they may have cached it.
	registry.set(&BIND_KEY, 0, None);
	assert!(!registry.is_serving(&BIND_KEY, &LISTENER_KEY));
	assert_eq!(
		registry.alt_svc(&BIND_KEY, &LISTENER_KEY),
		Some(ALT_SVC_CLEAR)
	);
	// Serving again advertises again.
	registry.set(&BIND_KEY, 0, Some(advertisement()));
	assert!(registry.is_serving(&BIND_KEY, &LISTENER_KEY));

	// A listener that is no longer served is cleared, the others stay advertised.
	registry.set(
		&BIND_KEY,
		0,
		Some(Advertisement {
			listeners: [strng::new("other")].into_iter().collect(),
			..advertisement()
		}),
	);
	assert_eq!(
		registry.alt_svc(&BIND_KEY, &LISTENER_KEY),
		Some(ALT_SVC_CLEAR)
	);
	assert!(registry.is_serving(&BIND_KEY, &strng::new("other")));

	// The supervisor of a bind that was replaced does not clear its successor.
	registry.set(&BIND_KEY, 1, Some(advertisement()));
	registry.remove(&BIND_KEY, 0);
	assert!(registry.is_serving(&BIND_KEY, &LISTENER_KEY));
	// A removed bind is forgotten.
	registry.remove(&BIND_KEY, 1);
	assert!(registry.alt_svc(&BIND_KEY, &LISTENER_KEY).is_none());
	assert!(!registry.any.load(Ordering::Relaxed));
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
	// Clients that cached the advertisement are told to forget it (RFC 7838, section 3).
	let res = https_get(&t).await;
	assert_eq!(res.headers()[header::ALT_SVC], "clear");

	// The open connection is asked to go away and is closed.
	expect_graceful_close(client).await;
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
	let mock = simple_mock().await;
	let port = free_udp_port();
	let passthrough = Listener {
		key: strng::new("passthrough"),
		name: Default::default(),
		hostname: strng::new("pass.example.com"),
		protocol: ListenerProtocol::TLS(None),
		..Default::default()
	};
	let bind = bind_at(
		SocketAddr::from(([127, 0, 0, 1], port)),
		ListenerSet::from_list([https_listener(server_tls(None)), passthrough]),
	);
	let mut t = test_with(*mock.address(), bind);
	t.attach_frontend_policy(json!({ "http": { "http3": {} } }))
		.await;
	t.serve_http3(BIND_KEY);
	wait_for_http3(&t, true).await;

	assert!(try_connect(port, "not-the-domain").await.is_err());
	// The TCP listener passes TLS for this name through; HTTP/3 must not terminate it with the
	// certificate of the wildcard HTTPS listener.
	assert!(try_connect(port, "pass.example.com").await.is_err());
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
async fn listener_requiring_client_certificates_drains_connections() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);

	// The listener starts verifying client certificates, which HTTP/3 cannot: the connection that
	// was established without one must not keep serving requests.
	t.pi
		.stores
		.binds
		.write()
		.insert_listener(https_listener(server_tls(Some(CA_CERT.to_vec()))), BIND_KEY);
	expect_graceful_close(client).await;
	assert!(try_get(port, "a.example.com").await.is_err());
}

#[tokio::test]
async fn listener_change_drains_connections() {
	let (_mock, t, port) = setup(Some(json!({}))).await;
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);

	// The listener changes but is still served over HTTP/3: connections made with the previous
	// listener are drained, like on the TCP listener, and new ones use the new listener.
	let mut listener = https_listener(server_tls(None));
	listener.hostname = strng::new("a.example.com");
	t.pi
		.stores
		.binds
		.write()
		.insert_listener(listener, BIND_KEY);
	expect_graceful_close(client).await;
	assert!(t.pi.http3.is_serving(&BIND_KEY, &LISTENER_KEY));
	assert_eq!(
		try_get(port, "a.example.com").await.unwrap(),
		StatusCode::OK
	);
	assert!(try_get(port, "b.example.com").await.is_err());
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
async fn binds_that_change_the_tcp_stream_are_not_served() {
	for (policy, expected) in [
		(
			json!({ "proxyProtocol": { "version": "all", "mode": "optional" } }),
			"PROXY",
		),
		(json!({ "connect": { "mode": "tunnel" } }), "CONNECT"),
		(json!({ "connect": { "mode": "route" } }), "CONNECT"),
	] {
		let (_mock, mut t, _port) = setup_without_serving(None, server_tls(None)).await;
		let mut policy = policy;
		policy["http"] = json!({ "http3": {} });
		t.attach_frontend_policy(policy).await;
		let err = desired_state(&t.pi, &BIND_KEY).err().expect("rejected");
		assert!(err.to_string().contains(expected), "{err}");
	}

	// CONNECT requests that are only denied do not change the stream.
	let (_mock, mut t, _port) = setup_without_serving(None, server_tls(None)).await;
	t.attach_frontend_policy(json!({ "http": { "http3": {} }, "connect": { "mode": "deny" } }))
		.await;
	assert!(desired_state(&t.pi, &BIND_KEY).unwrap().is_some());

	// Neither are tunnel binds.
	let mock = simple_mock().await;
	let mut bind = https_bind(free_udp_port(), server_tls(None));
	Arc::make_mut(&mut bind.bind).tunnel_protocol = TunnelProtocol::Proxy;
	let mut t = test_with(*mock.address(), bind);
	t.attach_frontend_policy(json!({ "http": { "http3": {} } }))
		.await;
	let err = desired_state(&t.pi, &BIND_KEY).err().expect("rejected");
	assert!(err.to_string().contains("tunnel protocol"), "{err}");
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
	expect_graceful_close(client).await;
}

#[tokio::test]
async fn graceful_drain_delivers_in_flight_responses() {
	const SIZE: usize = 8 * 1024 * 1024;
	let mock = wiremock::MockServer::start().await;
	wiremock::Mock::given(wiremock::matchers::any())
		.respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![b'x'; SIZE]))
		.mount(&mock)
		.await;
	let (t, port) = serve_with_policy(*mock.address(), json!({ "http": { "http3": {} } })).await;
	let mut client = connect(port, "a.example.com").await;
	let req = ::http::Request::builder()
		.uri("https://a.example.com/large")
		.body(())
		.unwrap();
	let mut stream = client.send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	assert_eq!(
		stream.recv_response().await.unwrap().status(),
		StatusCode::OK
	);
	let mut received = stream
		.recv_data()
		.await
		.unwrap()
		.map(|c| c.remaining())
		.unwrap_or_default();

	// Drain while most of the response is still in flight.
	let reader = tokio::spawn(async move {
		while let Some(chunk) = stream.recv_data().await.unwrap() {
			received += chunk.remaining();
		}
		received
	});
	t.start_drain().await;
	assert_eq!(reader.await.unwrap(), SIZE);
	expect_graceful_close(client).await;
}

#[tokio::test]
async fn upstream_body_error_resets_the_response() {
	// The backend announces more body than it sends, then closes the connection.
	let (backend, _requests) =
		raw_backend(b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\nonly a part").await;
	let (_t, port) = serve_with_policy(backend, json!({ "http": { "http3": {} } })).await;
	let mut client = connect(port, "a.example.com").await;
	let req = ::http::Request::builder()
		.uri("https://a.example.com/")
		.body(())
		.unwrap();
	let mut stream = client.send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	// The truncated response must not end like a complete one: the stream is reset, which may
	// even discard the response headers before they are read.
	let err = async {
		let resp = stream.recv_response().await?;
		assert_eq!(resp.status(), StatusCode::OK);
		while stream.recv_data().await?.is_some() {}
		Ok::<_, h3::error::StreamError>(())
	}
	.await
	.expect_err("the stream is reset, not finished");
	assert!(err.to_string().contains("H3_INTERNAL_ERROR"), "{err}");
}

#[tokio::test]
async fn client_cancellation_cancels_the_upstream_request() {
	// The backend never answers; it reports when the gateway gives up on the request.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let backend = listener.local_addr().unwrap();
	let (received_tx, received) = tokio::sync::oneshot::channel();
	let (closed_tx, closed) = tokio::sync::oneshot::channel();
	tokio::spawn(async move {
		let (mut conn, _) = listener.accept().await.unwrap();
		read_request_head(&mut conn).await;
		received_tx.send(()).unwrap();
		let mut buf = [0u8; 1024];
		while conn.read(&mut buf).await.is_ok_and(|n| n > 0) {}
		closed_tx.send(()).unwrap();
	});
	let (_t, port) = serve_with_policy(backend, json!({ "http": { "http3": {} } })).await;
	let mut client = connect(port, "a.example.com").await;
	let req = ::http::Request::builder()
		.uri("https://a.example.com/")
		.body(())
		.unwrap();
	let mut stream = client.send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	tokio::time::timeout(Duration::from_secs(5), received)
		.await
		.expect("the request reaches the backend")
		.unwrap();

	// The client cancels the request (RFC 9114, section 4.1.1).
	stream.stop_sending(Code::H3_REQUEST_CANCELLED);
	drop(stream);
	tokio::time::timeout(Duration::from_secs(5), closed)
		.await
		.expect("the upstream request is cancelled")
		.unwrap();
}

/// A certificate verifier that blocks, keeping a QUIC handshake in progress, and then rejects the
/// server certificate unless `accept` is set.
#[derive(Debug)]
struct SlowVerifier {
	delay: Duration,
	accept: bool,
}

impl rustls::client::danger::ServerCertVerifier for SlowVerifier {
	fn verify_server_cert(
		&self,
		_end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>,
		_ocsp_response: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		std::thread::sleep(self.delay);
		if self.accept {
			Ok(rustls::client::danger::ServerCertVerified::assertion())
		} else {
			Err(rustls::Error::General("hung up".to_string()))
		}
	}

	fn verify_tls12_signature(
		&self,
		_message: &[u8],
		_cert: &rustls::pki_types::CertificateDer<'_>,
		_dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Err(rustls::Error::General("unused".to_string()))
	}

	fn verify_tls13_signature(
		&self,
		_message: &[u8],
		_cert: &rustls::pki_types::CertificateDer<'_>,
		_dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		if self.accept {
			Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
		} else {
			Err(rustls::Error::General("unused".to_string()))
		}
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		vec![
			rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
			rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
			rustls::SignatureScheme::RSA_PSS_SHA256,
			rustls::SignatureScheme::RSA_PKCS1_SHA256,
			rustls::SignatureScheme::ED25519,
		]
	}
}

fn slow_client_tls(delay: Duration, accept: bool) -> rustls::ClientConfig {
	let mut config = rustls::ClientConfig::builder_with_provider(crate::transport::tls::provider())
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(SlowVerifier { delay, accept }))
		.with_no_client_auth();
	config.alpn_protocols = vec![b"h3".to_vec()];
	config
}

#[tokio::test]
async fn handshakes_do_not_take_connection_capacity() {
	let mock = simple_mock().await;
	let (t, port) = serve_with_policy(
		*mock.address(),
		json!({ "http": { "http3": {} }, "tcp": { "maxConnections": 1 } }),
	)
	.await;

	// A client whose handshake hangs, on its own runtime since the verifier blocks.
	let stuck = std::thread::spawn(move || {
		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();
		rt.block_on(async move {
			let endpoint = client_endpoint(slow_client_tls(Duration::from_secs(3), false)).unwrap();
			let res = endpoint
				.connect(SocketAddr::from(([127, 0, 0, 1], port)), "a.example.com")
				.unwrap()
				.await;
			assert!(res.is_err());
		});
	});
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!stuck.is_finished(), "the handshake is still in progress");

	// The pending handshake does not hold the only connection slot.
	let mut client = connect(port, "a.example.com").await;
	assert_eq!(
		client.get("https://a.example.com/").await.status,
		StatusCode::OK
	);
	// The established connection does: a second one is closed once its handshake completes.
	assert!(try_get(port, "a.example.com").await.is_err());
	let shed = t
		.pi
		.metrics
		.downstream_connections_shed
		.get_or_create(&AdmissionLabels {
			bind: Some(&BIND_KEY).into(),
		})
		.get();
	assert_eq!(shed, 1);
	stuck.join().unwrap();
}

#[test]
fn address_validation_is_required_under_load() {
	// Unvalidated clients are asked to retry once enough handshakes are pending.
	assert!(!requires_address_validation(false, true, 127, 128));
	assert!(requires_address_validation(false, true, 128, 128));
	// A validated client, or one that already retried, is never asked again.
	assert!(!requires_address_validation(true, true, 1000, 128));
	assert!(!requires_address_validation(false, false, 1000, 128));
	// Tests always validate, exercising the Retry path in every test.
	assert!(requires_address_validation(
		false,
		true,
		0,
		ADDRESS_VALIDATION_THRESHOLD
	));
}

#[test]
fn transport_limits() {
	let http3 = frontend::HTTP3::default();
	let limits = TransportLimits::new(&http3, &frontend::HTTP::default());
	assert_eq!(
		limits,
		TransportLimits {
			max_concurrent_bidi_streams: 100,
			max_concurrent_uni_streams: MAX_CONCURRENT_UNI_STREAMS,
			receive_window: 1024 * 1024,
			stream_receive_window: 256 * 1024,
			send_window: 1024 * 1024,
			idle_timeout: Duration::from_secs(30),
		}
	);
	assert!(limits.transport_config().is_ok());

	// The HTTP/2 flow-control windows of the frontend policy apply to QUIC too.
	let http: frontend::HTTP = serde_json::from_value(json!({
		"http2WindowSize": 65536,
		"http2ConnectionWindowSize": 131072,
		"http3": { "maxConcurrentStreams": 10, "idleTimeout": "5s" },
	}))
	.unwrap();
	let limits = TransportLimits::new(http.http3.as_ref().unwrap(), &http);
	assert_eq!(
		limits,
		TransportLimits {
			max_concurrent_bidi_streams: 10,
			max_concurrent_uni_streams: MAX_CONCURRENT_UNI_STREAMS,
			receive_window: 131072,
			stream_receive_window: 65536,
			send_window: 4 * 65536,
			idle_timeout: Duration::from_secs(5),
		}
	);
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
		"http3": {"altSvcMaxAge": "10m", "idleTimeout": "1m", "maxConcurrentStreams": 10, "altSvcPort": 443}
	}))
	.unwrap();
	let http3 = http.http3.unwrap();
	assert_eq!(http3.alt_svc_max_age(), Duration::from_secs(600));
	assert_eq!(http3.idle_timeout(), Duration::from_secs(60));
	assert_eq!(http3.max_concurrent_streams().get(), 10);
	assert_eq!(http3.alt_svc_port.map(|p| p.get()), Some(443));

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
	assert_eq!(http3.alt_svc_port, None);

	let http: frontend::HTTP = serde_json::from_value(json!({})).unwrap();
	assert!(http.http3.is_none());
	assert!(serde_json::from_value::<frontend::HTTP>(json!({"http3": {"unknown": true}})).is_err());
	// A connection that accepts no request is not useful.
	assert!(
		serde_json::from_value::<frontend::HTTP>(json!({"http3": {"maxConcurrentStreams": 0}}))
			.is_err()
	);
	assert!(serde_json::from_value::<frontend::HTTP>(json!({"http3": {"altSvcPort": 0}})).is_err());
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
	let mut t = test_with(*mock.address(), bind);
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

#[test]
fn connections_are_served_by_the_listeners_of_their_handshake() {
	let served = |listeners: ListenerSet| {
		let served = listeners.iter().map(|l| l.key.clone()).collect();
		ServedListeners {
			listeners: Arc::new(listeners),
			served,
		}
	};
	let handshake = served(ListenerSet::from_list([https_listener(server_tls(None))]));
	let unchanged = ListenerSet::from_list([https_listener(server_tls(None))]);
	assert_eq!(
		handshake.select(&unchanged, "a.example.com").unwrap().key,
		LISTENER_KEY
	);
	assert!(handshake.select(&unchanged, "a.other.com").is_err());

	// The listener started verifying client certificates during the handshake.
	let mtls = ListenerSet::from_list([https_listener(server_tls(Some(CA_CERT.to_vec())))]);
	assert!(handshake.select(&mtls, "a.example.com").is_err());

	// A more specific listener was added during the handshake.
	let specific = Listener {
		key: strng::new("specific"),
		hostname: strng::new("a.example.com"),
		..https_listener(server_tls(Some(CA_CERT.to_vec())))
	};
	let added = ListenerSet::from_list([https_listener(server_tls(None)), specific]);
	assert!(handshake.select(&added, "a.example.com").is_err());
	assert!(handshake.select(&added, "b.example.com").is_ok());

	// The listener was removed during the handshake.
	assert!(
		handshake
			.select(&ListenerSet::default(), "a.example.com")
			.is_err()
	);

	// A listener the configuration does not serve never serves a connection.
	let mut not_served = served(ListenerSet::from_list([https_listener(server_tls(None))]));
	not_served.served.clear();
	assert!(not_served.select(&unchanged, "a.example.com").is_err());
}

#[tokio::test]
async fn listener_requiring_client_certificates_during_the_handshake_is_not_served() {
	let mock = simple_mock().await;
	let port = free_udp_port();
	// Another listener keeps the endpoint serving once the first one requires client certificates.
	let other = Listener {
		key: strng::new("other"),
		hostname: strng::new("other.test"),
		..https_listener(server_tls(None))
	};
	let bind = bind_at(
		SocketAddr::from(([127, 0, 0, 1], port)),
		ListenerSet::from_list([https_listener(server_tls(None)), other]),
	);
	let mut t = test_with(*mock.address(), bind);
	t.attach_frontend_policy(json!({ "http": { "http3": {} } }))
		.await;
	t.serve_http3(BIND_KEY);
	wait_for_http3(&t, true).await;

	// A client whose handshake is still in progress when the listener changes.
	let client = std::thread::spawn(move || {
		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();
		rt.block_on(async move {
			let endpoint = client_endpoint(slow_client_tls(Duration::from_secs(1), true))?;
			let conn = endpoint
				.connect(SocketAddr::from(([127, 0, 0, 1], port)), "a.example.com")?
				.await?;
			let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
			tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
			let req = ::http::Request::builder()
				.uri("https://a.example.com/")
				.body(())?;
			let mut stream = send.send_request(req).await?;
			stream.finish().await?;
			Ok::<_, anyhow::Error>(stream.recv_response().await?.status())
		})
	});
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert!(!client.is_finished(), "the handshake is still in progress");
	t.pi
		.stores
		.binds
		.write()
		.insert_listener(https_listener(server_tls(Some(CA_CERT.to_vec()))), BIND_KEY);

	// The handshake completes with the certificate of the previous listener, but the connection is
	// not served without the client certificate the listener now requires.
	let res = tokio::task::spawn_blocking(move || client.join().unwrap())
		.await
		.unwrap();
	assert!(res.is_err(), "served without a client certificate: {res:?}");
	assert!(t.pi.http3.is_serving(&BIND_KEY, &strng::new("other")));
}

#[tokio::test]
async fn removing_the_bind_drains_connections() {
	const SIZE: usize = 8 * 1024 * 1024;
	let mock = wiremock::MockServer::start().await;
	wiremock::Mock::given(wiremock::matchers::any())
		.respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![b'x'; SIZE]))
		.mount(&mock)
		.await;
	let port = free_udp_port();
	let mut t = test_with(*mock.address(), https_bind(port, server_tls(None)));
	t.attach_frontend_policy(json!({ "http": { "http3": {} } }))
		.await;
	let stop = tokio_util::sync::CancellationToken::new();
	let supervisor = t.serve_http3_until(BIND_KEY, stop.clone());
	wait_for_http3(&t, true).await;
	let mut client = connect(port, "a.example.com").await;
	let req = ::http::Request::builder()
		.uri("https://a.example.com/large")
		.body(())
		.unwrap();
	let mut stream = client.send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	assert_eq!(
		stream.recv_response().await.unwrap().status(),
		StatusCode::OK
	);
	let mut received = stream
		.recv_data()
		.await
		.unwrap()
		.map(|c| c.remaining())
		.unwrap_or_default();

	// The bind goes away while most of the response is still in flight: like on the TCP listener,
	// the response is delivered and the connection is asked to go away.
	let reader = tokio::spawn(async move {
		while let Some(chunk) = stream.recv_data().await.unwrap() {
			received += chunk.remaining();
		}
		received
	});
	stop.cancel();
	wait_for_http3(&t, false).await;
	assert!(try_connect(port, "a.example.com").await.is_err());
	assert_eq!(reader.await.unwrap(), SIZE);
	expect_graceful_close(client).await;
	// The UDP socket is released once the connection is gone.
	tokio::time::timeout(Duration::from_secs(10), supervisor)
		.await
		.expect("the supervisor ends")
		.unwrap();
	std::net::UdpSocket::bind(("127.0.0.1", port)).expect("the UDP port is released");
}

#[test]
fn replaced_supervisor_does_not_clear_its_successor() {
	let registry = Http3Registry::default();
	let advertisement = || Advertisement {
		listeners: [LISTENER_KEY].into_iter().collect(),
		alt_svc: alt_svc_value(443, Duration::from_secs(60)),
		max_age: Duration::from_secs(60),
	};
	let old = registry.owner();
	let new = registry.owner();
	registry.set(&BIND_KEY, old, Some(advertisement()));
	registry.set(&BIND_KEY, new, Some(advertisement()));
	// The replaced supervisor stops serving while it drains its connections.
	registry.set(&BIND_KEY, old, None);
	registry.remove(&BIND_KEY, old);
	assert!(registry.is_serving(&BIND_KEY, &LISTENER_KEY));
}

#[tokio::test]
async fn requests_after_goaway_are_rejected() {
	// The backend holds the first request, keeping the connection open while it drains.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let backend = listener.local_addr().unwrap();
	let (received_tx, received) = tokio::sync::oneshot::channel();
	let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
	tokio::spawn(async move {
		let mut received_tx = Some(received_tx);
		while let Ok((mut conn, _)) = listener.accept().await {
			read_request_head(&mut conn).await;
			let _ = requests_tx.send(());
			if let Some(tx) = received_tx.take() {
				let _ = tx.send(());
			}
			tokio::spawn(async move {
				let mut buf = [0u8; 1024];
				while conn.read(&mut buf).await.is_ok_and(|n| n > 0) {}
			});
		}
	});
	let (t, port) = serve_with_policy(backend, json!({ "http": { "http3": {} } })).await;
	// The client never reads its control stream, so it does not learn about the GOAWAY and keeps
	// opening requests, like a client whose request crossed the GOAWAY.
	let endpoint = client_endpoint(client_tls("a.example.com").unwrap()).unwrap();
	let conn = endpoint
		.connect(SocketAddr::from(([127, 0, 0, 1], port)), "a.example.com")
		.unwrap()
		.await
		.unwrap();
	let (_driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
		.await
		.unwrap();
	let get = || {
		::http::Request::builder()
			.uri("https://a.example.com/")
			.body(())
			.unwrap()
	};
	let mut first = send.send_request(get()).await.unwrap();
	first.finish().await.unwrap();
	tokio::time::timeout(Duration::from_secs(5), received)
		.await
		.expect("the first request reaches the backend")
		.unwrap();
	requests.recv().await.unwrap();

	// The listener changes: the connection sends a GOAWAY naming the next request stream.
	let mut listener = https_listener(server_tls(None));
	listener.hostname = strng::new("a.example.com");
	t.pi
		.stores
		.binds
		.write()
		.insert_listener(listener, BIND_KEY);
	tokio::time::sleep(Duration::from_millis(200)).await;

	let mut second = send.send_request(get()).await.unwrap();
	second.finish().await.unwrap();
	let err = tokio::time::timeout(Duration::from_secs(5), second.recv_response())
		.await
		.expect("the request after the GOAWAY is rejected")
		.expect_err("the request after the GOAWAY is not processed");
	assert!(err.to_string().contains("H3_REQUEST_REJECTED"), "{err}");
	assert!(
		requests.try_recv().is_err(),
		"the request after the GOAWAY reached the backend"
	);
}

#[tokio::test]
async fn listeners_with_their_own_tls_settings_are_not_served() {
	use crate::transport::tls::CipherSuite;
	let tls_with = |max_version, cipher_suites| {
		ServerTLSConfig::from_pem_with_profile(
			CERT.to_vec(),
			KEY.to_vec(),
			None,
			vec![b"h2".to_vec(), b"http/1.1".to_vec()],
			None,
			max_version,
			cipher_suites,
			None,
			false,
		)
		.unwrap()
	};
	let serves = async |tls: ServerTLSConfig, frontend_tls: Option<serde_json::Value>| {
		let (_mock, mut t, _port) = setup_without_serving(None, tls).await;
		let mut policy = json!({ "http": { "http3": {} } });
		if let Some(frontend_tls) = frontend_tls {
			policy["tls"] = frontend_tls;
		}
		t.attach_frontend_policy(policy).await;
		desired_state(&t.pi, &BIND_KEY).unwrap().is_some()
	};

	assert!(serves(tls_with(None, None), None).await);
	// The listener only allows TLS 1.2 on TCP; QUIC would negotiate TLS 1.3.
	assert!(
		!serves(
			tls_with(Some(crate::types::agent::TLSVersion::TLS_V1_2), None),
			None
		)
		.await
	);
	// The listener restricts its cipher suites; QUIC would offer the default ones.
	let restricted = || tls_with(None, Some(vec![CipherSuite::TLS_AES_128_GCM_SHA256]));
	assert!(!serves(restricted(), None).await);
	// The frontend TLS policy restricts them for every listener, QUIC included.
	let frontend_suites = json!({ "cipherSuites": ["TLS_AES_128_GCM_SHA256"] });
	assert!(serves(restricted(), Some(frontend_suites.clone())).await);
	assert!(serves(tls_with(None, None), Some(frontend_suites)).await);
}

#[test]
fn handshakes_are_limited_per_source() {
	let sources = SourceHandshakes::default();
	let a: IpAddr = [192, 0, 2, 1].into();
	let b: IpAddr = [192, 0, 2, 2].into();
	let mut permits: Vec<_> = (0..3)
		.map(|_| sources.try_acquire(a, 3).expect("under the limit"))
		.collect();
	assert!(sources.try_acquire(a, 3).is_none(), "one source is limited");
	let other = sources.try_acquire(b, 3).expect("other sources are not");
	permits.pop();
	let _again = sources
		.try_acquire(a, 3)
		.expect("a completed handshake frees its slot");
	drop(permits);
	drop(other);
	drop(_again);
	assert_eq!(sources.len(), 0, "sources without handshakes are forgotten");
}

#[tokio::test]
async fn connection_migration_is_disabled() {
	let (_mock, t, _port) = setup_without_serving(Some(json!({})), server_tls(None)).await;
	let desired = desired_state(&t.pi, &BIND_KEY).unwrap().unwrap();
	// quinn only exposes the setting through Debug.
	let config = format!("{:?}", desired.server_config);
	assert!(config.contains("migration: false"), "{config}");
}
