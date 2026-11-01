//! End-to-end HTTP/3 through a gateway started from a local configuration file.

use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{Method, StatusCode, Version, header};
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;
use wiremock::{Mock, ResponseTemplate};

use crate::common::gateway::AgentGateway;

const CERTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/mcp-tls/certs");

fn client_tls(alpn: &[u8]) -> rustls::ClientConfig {
	let tls: agentgateway::http::backendtls::BackendTLS =
		agentgateway::http::backendtls::ResolvedBackendTLS {
			cert: None,
			key: None,
			root: Some(std::fs::read(format!("{CERTS}/ca-cert.pem")).unwrap()),
			hostname: Some("localhost".to_string()),
			insecure: false,
			insecure_host: false,
			alpn: None,
			subject_alt_names: None,
			key_exchange_groups: None,
			spiffe: false,
		}
		.try_into()
		.unwrap();
	let mut config = (*tls.base_config().config).clone();
	config.alpn_protocols = vec![alpn.to_vec()];
	config
}

async fn gateway(http3: &str, backend: SocketAddr) -> AgentGateway {
	AgentGateway::new(format!(
		r#"config: {{}}
frontendPolicies:
  http: {http3}
binds:
- port: $PORT
  listeners:
  - name: default
    protocol: HTTPS
    tls:
      cert: {CERTS}/cert.pem
      key: {CERTS}/key.pem
    routes:
    - name: default
      policies:
        requestHeaderModifier:
          add:
            x-route-req: route-req
        responseHeaderModifier:
          add:
            x-route-resp: route-resp
      backends:
      - host: {backend}
"#
	))
	.await
	.unwrap()
}

async fn backend() -> wiremock::MockServer {
	let mock = wiremock::MockServer::start().await;
	Mock::given(wiremock::matchers::header("x-route-req", "route-req"))
		.respond_with(ResponseTemplate::new(200).set_body_string("routed"))
		.mount(&mock)
		.await;
	mock
}

/// Sends one HTTP/1.1 request over TLS to the TCP listener.
async fn https_request(port: u16) -> http::Response<Bytes> {
	let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
		.await
		.unwrap();
	let tls = TlsConnector::from(Arc::new(client_tls(b"http/1.1")))
		.connect(ServerName::try_from("localhost").unwrap(), tcp)
		.await
		.unwrap();
	let (mut sender, conn) = http1::handshake(TokioIo::new(tls)).await.unwrap();
	tokio::spawn(conn);
	let resp = sender
		.send_request(
			http::Request::builder()
				.uri("/")
				.version(Version::HTTP_11)
				.header(header::HOST, "localhost")
				.body(http_body_util::Empty::<Bytes>::new())
				.unwrap(),
		)
		.await
		.unwrap();
	let (parts, body) = resp.into_parts();
	http::Response::from_parts(parts, body.collect().await.unwrap().to_bytes())
}

/// Sends one HTTP/3 request to the UDP port of the listener.
async fn h3_request(port: u16) -> anyhow::Result<http::Response<Bytes>> {
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls(b"h3")))?;
	let mut config = quinn::ClientConfig::new(Arc::new(crypto));
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(2).try_into()?));
	config.transport_config(Arc::new(transport));
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
	endpoint.set_default_client_config(config);
	let conn = endpoint
		.connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost")?
		.await?;
	let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
	tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
	let mut stream = send
		.send_request(
			http::Request::builder()
				.method(Method::GET)
				.uri("https://localhost/")
				.body(())?,
		)
		.await?;
	stream.finish().await?;
	let resp = stream.recv_response().await?;
	let mut body = Vec::new();
	while let Some(mut chunk) = stream.recv_data().await? {
		body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
	}
	let (parts, ()) = resp.into_parts();
	Ok(http::Response::from_parts(parts, body.into()))
}

async fn eventually_h3(port: u16) -> http::Response<Bytes> {
	let start = std::time::Instant::now();
	loop {
		match h3_request(port).await {
			Ok(resp) => return resp,
			Err(e) if start.elapsed() < Duration::from_secs(10) => {
				tracing::debug!("HTTP/3 not ready yet: {e:#}");
				tokio::time::sleep(Duration::from_millis(50)).await;
			},
			Err(e) => panic!("HTTP/3 request failed: {e:#}"),
		}
	}
}

#[tokio::test]
async fn http3_from_local_config() {
	let mock = backend().await;
	let gw = gateway("{ http3: { altSvcMaxAge: 1h } }", *mock.address()).await;
	let port = gw.port();

	let resp = eventually_h3(port).await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert_eq!(resp.headers()["x-route-resp"], "route-resp");
	assert_eq!(resp.body().as_ref(), b"routed");

	let resp = https_request(port).await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert_eq!(
		resp.headers()[header::ALT_SVC],
		format!("h3=\":{port}\"; ma=3600")
	);
	gw.shutdown().await;
}

#[tokio::test]
async fn http3_disabled_by_default() {
	let mock = backend().await;
	let gw = gateway("{}", *mock.address()).await;
	let port = gw.port();

	let resp = https_request(port).await;
	assert_eq!(resp.status(), StatusCode::OK);
	assert!(resp.headers().get(header::ALT_SVC).is_none());
	assert!(h3_request(port).await.is_err());
	gw.shutdown().await;
}
