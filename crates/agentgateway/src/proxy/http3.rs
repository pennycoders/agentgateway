//! Downstream HTTP/3 (QUIC).
//!
//! When the frontend HTTP policy of a bind enables `http3`, a QUIC endpoint is bound on the UDP
//! port matching the bind's TCP port. It terminates QUIC with the certificates of the bind's HTTPS
//! listeners, selecting the listener by SNI exactly like the TCP listener, and hands every request
//! to the same [`HTTPProxy`] used for HTTP/1.1 and HTTP/2, so routing and every policy apply
//! identically. While the endpoint serves a listener, responses on the TCP listener advertise it
//! with `Alt-Svc`.
//!
//! The endpoint follows the frontend policy and the bind's listeners: it is created when HTTP/3 is
//! enabled, its TLS configuration is replaced when listeners or certificates change, and it stops
//! accepting connections (sending a GOAWAY to existing ones) when HTTP/3 is disabled. With HTTP/3
//! disabled, which is the default, no UDP socket is opened.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use agent_core::drain::{self, DrainWatcher};
use agent_core::telemetry;
use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, header};
use http_body::Frame;
use http_body_util::BodyExt;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::Gateway;
use super::httpproxy::HTTPProxy;
use crate::proxy::{ProxyError, dtrace};
use crate::store::FrontendPolices;
use crate::telemetry::metrics::{AdmissionLabels, TCPLabels};
use crate::transport::BufferLimit;
use crate::transport::stream::{Alpn, Extension, TCPConnectionInfo, TLSConnectionInfo};
use crate::types::agent::{
	BindKey, BindMode, Listener, ListenerKey, ListenerProtocol, ListenerSet, TransportProtocol,
};
use crate::types::frontend;
use crate::{ProxyInputs, client};

/// The ALPN protocol identifier for HTTP/3 (RFC 9114).
const H3_ALPN: &[u8] = b"h3";
/// H3_NO_ERROR (RFC 9114, section 8.1).
const H3_NO_ERROR: u32 = 0x100;
/// Default limit on the size of request headers, matching the HTTP/2 default.
const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;
/// How often an endpoint that no longer serves HTTP/3 checks whether its connections are gone,
/// so its UDP socket can be released.
const RETIRED_ENDPOINT_POLL: Duration = Duration::from_secs(1);

/// Tracks the binds that currently serve HTTP/3, so the TCP listener can advertise them.
#[derive(Debug, Default)]
pub struct Http3Registry {
	// Fast path for the common case where no bind serves HTTP/3.
	any: AtomicBool,
	binds: RwLock<HashMap<BindKey, Arc<Advertisement>>>,
}

#[derive(Debug)]
struct Advertisement {
	/// HTTPS listeners whose certificates the QUIC endpoint serves.
	listeners: HashSet<ListenerKey>,
	alt_svc: HeaderValue,
}

impl Http3Registry {
	/// Adds an `Alt-Svc` header advertising HTTP/3 when the bind serves the listener over HTTP/3.
	/// An `Alt-Svc` header set by the backend or a policy is left untouched.
	pub fn advertise(&self, bind: &BindKey, listener: &ListenerKey, headers: &mut HeaderMap) {
		if let Some(alt_svc) = self.alt_svc(bind, listener) {
			headers.entry(header::ALT_SVC).or_insert(alt_svc);
		}
	}

	pub fn alt_svc(&self, bind: &BindKey, listener: &ListenerKey) -> Option<HeaderValue> {
		if !self.any.load(Ordering::Relaxed) {
			return None;
		}
		let binds = self.binds.read().expect("http3 registry poisoned");
		let advertisement = binds.get(bind)?;
		advertisement
			.listeners
			.contains(listener)
			.then(|| advertisement.alt_svc.clone())
	}

	fn set(&self, bind: &BindKey, advertisement: Option<Advertisement>) {
		let mut binds = self.binds.write().expect("http3 registry poisoned");
		match advertisement {
			Some(advertisement) => {
				binds.insert(bind.clone(), Arc::new(advertisement));
			},
			None => {
				binds.remove(bind);
			},
		}
		self.any.store(!binds.is_empty(), Ordering::Relaxed);
	}
}

/// The `Alt-Svc` value advertising HTTP/3 on `port` (RFC 7838, RFC 9114 section 3.1.1).
fn alt_svc_value(port: u16, max_age: Duration) -> HeaderValue {
	HeaderValue::try_from(format!("h3=\":{port}\"; ma={}", max_age.as_secs()))
		.expect("alt-svc value is always valid")
}

/// Selects the certificate of the HTTPS listener matching the SNI, using the same listener
/// matching as the TCP listener.
#[derive(Debug)]
struct SniCertResolver {
	listeners: Arc<ListenerSet>,
	resolvers: HashMap<ListenerKey, Arc<dyn ResolvesServerCert>>,
}

impl ResolvesServerCert for SniCertResolver {
	fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		let key = {
			let sni = client_hello.server_name().unwrap_or_default();
			let listener = select_listener(&self.listeners, sni)?;
			listener.key.clone()
		};
		self.resolvers.get(&key)?.resolve(client_hello)
	}
}

fn select_listener(listeners: &ListenerSet, sni: &str) -> Option<Arc<Listener>> {
	listeners.best_match_filtered(sni, |protocol| {
		matches!(protocol, ListenerProtocol::HTTPS(_))
	})
}

/// What the QUIC endpoint of a bind should currently serve.
struct Desired {
	address: SocketAddr,
	server_config: quinn::ServerConfig,
	advertisement: Advertisement,
}

fn desired_state(pi: &ProxyInputs, bind_key: &BindKey) -> anyhow::Result<Option<Desired>> {
	let binds = pi.stores.read_binds();
	let Some(bind) = binds.bind(bind_key) else {
		return Ok(None);
	};
	if bind.mode == BindMode::Internal {
		return Ok(None);
	}
	let policies = binds.frontend_policies(pi.cfg.gateway_port_ref(bind.address.port()));
	drop(binds);
	let Some(settings) = policies.http.as_ref().and_then(|h| h.http3.as_ref()) else {
		return Ok(None);
	};

	let mut resolvers = HashMap::new();
	for listener in bind.listeners.iter() {
		let ListenerProtocol::HTTPS(tls) = &listener.protocol else {
			continue;
		};
		match tls.http3_cert_resolver() {
			Some(resolver) => {
				resolvers.insert(listener.key.clone(), resolver);
			},
			None => {
				debug!(bind=%bind_key, listener=%listener.key, "listener is not served over HTTP/3: client certificate verification or workload identity is not supported");
			},
		}
	}
	if resolvers.is_empty() {
		return Ok(None);
	}

	let tls_policy = policies.tls.clone().unwrap_or_default();
	if tls_policy
		.max_version
		.is_some_and(|v| v != frontend::TLSVersion::TLS_V1_3)
	{
		anyhow::bail!(
			"HTTP/3 requires TLS 1.3, but the frontend TLS policy limits the maximum version"
		);
	}
	let provider = crate::transport::tls::provider_with_options_validated(
		tls_policy.cipher_suites.as_deref().unwrap_or_default(),
		tls_policy
			.key_exchange_groups
			.as_deref()
			.unwrap_or_default(),
	)?;
	let listener_keys = resolvers.keys().cloned().collect();
	let resolver = SniCertResolver {
		listeners: bind.listeners.clone(),
		resolvers,
	};
	let mut tls = rustls::ServerConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13])?
		.with_no_client_auth()
		.with_cert_resolver(Arc::new(resolver));
	tls.alpn_protocols = vec![H3_ALPN.to_vec()];
	tls.key_log = crate::transport::tls::key_log();
	// 0-RTT data can be replayed; it stays disabled (rustls default).
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
	let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
	let mut transport = quinn::TransportConfig::default();
	transport
		.max_concurrent_bidi_streams(settings.max_concurrent_streams().into())
		.max_idle_timeout(Some(settings.idle_timeout().try_into()?));
	server_config.transport_config(Arc::new(transport));

	Ok(Some(Desired {
		address: bind.address,
		server_config,
		advertisement: Advertisement {
			listeners: listener_keys,
			alt_svc: alt_svc_value(bind.address.port(), settings.alt_svc_max_age()),
		},
	}))
}

/// A bound QUIC endpoint.
struct Endpoint {
	endpoint: quinn::Endpoint,
	/// Set to true when the endpoint stops serving HTTP/3; its connections then drain.
	/// Replaced by a fresh channel if HTTP/3 is enabled again.
	retired: watch::Sender<bool>,
	serving: bool,
}

impl Endpoint {
	fn bind(address: SocketAddr, server_config: quinn::ServerConfig) -> anyhow::Result<Self> {
		let socket = std::net::UdpSocket::bind(address)?;
		let endpoint = quinn::Endpoint::new(
			quinn::EndpointConfig::default(),
			Some(server_config),
			socket,
			Arc::new(quinn::TokioRuntime),
		)?;
		Ok(Self {
			endpoint,
			retired: watch::channel(false).0,
			serving: true,
		})
	}

	fn serve(&mut self, server_config: quinn::ServerConfig) {
		self.endpoint.set_server_config(Some(server_config));
		if !self.serving {
			self.serving = true;
			self.retired = watch::channel(false).0;
		}
	}

	fn retire(&mut self) {
		if self.serving {
			self.serving = false;
			// Refuse new connections; ask the existing ones to finish.
			self.endpoint.set_server_config(None);
			self.retired.send_replace(true);
		}
	}
}

impl Drop for Endpoint {
	fn drop(&mut self) {
		self.endpoint.close(H3_NO_ERROR.into(), b"");
	}
}

/// Runs the HTTP/3 endpoint of a bind for as long as the bind exists.
pub(crate) async fn run_bind(
	pi: Arc<ProxyInputs>,
	drain: DrainWatcher,
	bind_key: BindKey,
) -> anyhow::Result<()> {
	let min_deadline = pi.cfg.termination_min_deadline;
	let max_deadline = pi.cfg.termination_max_deadline;
	let component = format!("http3 bind {bind_key}");
	let pi = if pi.cfg.threading_mode == crate::ThreadingMode::ThreadPerCore {
		// The upstream client of the per-core TCP listeners is bound to their runtimes; this endpoint
		// runs on the main runtime and needs its own.
		let mut pi = Arc::unwrap_or_clone(pi);
		pi.upstream = client::Client::new_with_h2_config(
			&pi.cfg.dns,
			None,
			Arc::new(pi.cfg.hbone.h2.clone()),
			pi.cfg.backend.clone(),
			Some(pi.metrics.clone()),
		);
		Arc::new(pi)
	} else {
		pi
	};
	let registry = pi.http3.clone();
	let registry_key = bind_key.clone();
	drain::run_with_drain(
		component,
		drain,
		max_deadline,
		min_deadline,
		|drain, force_shutdown| async move {
			supervise(pi, drain, force_shutdown, bind_key).await;
		},
	)
	.await;
	registry.set(&registry_key, None);
	Ok(())
}

async fn supervise(
	pi: Arc<ProxyInputs>,
	drain: DrainWatcher,
	force_shutdown: watch::Receiver<()>,
	bind_key: BindKey,
) {
	let wait = drain.clone().wait_for_drain();
	tokio::pin!(wait);
	let (mut upgrader, weak) = drain.into_weak();
	let (mut listener_changes, mut policy_changes) = {
		let binds = pi.stores.read_binds();
		(
			binds.subscribe_listener_set_changes(),
			binds.subscribe_frontend_policy_changes(),
		)
	};
	let admission = pi.admission.bind(&bind_key);
	let connection_shed = pi
		.metrics
		.downstream_connections_shed
		.get_or_create(&AdmissionLabels {
			bind: Some(&bind_key).into(),
		})
		.clone();
	let mut endpoint: Option<Endpoint> = None;
	let mut retired_poll = tokio::time::interval(RETIRED_ENDPOINT_POLL);

	let drain_mode = 'outer: loop {
		reconcile(&pi, &bind_key, &mut endpoint);
		loop {
			let accept = async {
				match endpoint.as_ref().filter(|e| e.serving) {
					Some(e) => e.endpoint.accept().await,
					None => std::future::pending().await,
				}
			};
			let retired = endpoint.as_ref().is_some_and(|e| !e.serving);
			tokio::select! {
				res = &mut wait => break 'outer res,
				res = listener_changes.changed() => {
					if res.is_err() {
						break 'outer (&mut wait).await;
					}
					break;
				},
				res = policy_changes.changed() => {
					if res.is_err() {
						break 'outer (&mut wait).await;
					}
					break;
				},
				incoming = accept => {
					let Some(incoming) = incoming else {
						// The endpoint was closed; bind it again on the next reconcile.
						endpoint = None;
						break;
					};
					let policies = Gateway::frontend_policies_for_bind(&bind_key, &pi);
					let max_connections = policies.tcp.as_ref().and_then(|tcp| tcp.max_connections);
					let Some(permit) = admission.connections.try_acquire(max_connections) else {
						connection_shed.inc();
						debug!(bind=%bind_key, src.addr=%incoming.remote_address(), "downstream QUIC connection rejected: connection limit");
						incoming.refuse();
						continue;
					};
					let Some(e) = endpoint.as_ref() else {
						continue;
					};
					let connection = Connection {
						pi: pi.clone(),
						bind_key: bind_key.clone(),
						policies,
						drain: upgrader.upgrade(weak.clone()),
						retired: e.retired.subscribe(),
						force_shutdown: force_shutdown.clone(),
					};
					tokio::spawn(telemetry::connection_scope(async move {
						connection.serve(incoming).await;
						drop(permit);
					}));
				},
				_ = retired_poll.tick(), if retired => {
					if endpoint.as_ref().is_some_and(|e| e.endpoint.open_connections() == 0) {
						debug!(bind=%bind_key, "HTTP/3 endpoint has no connections left, releasing the UDP socket");
						endpoint = None;
					}
				},
			}
		}
	};
	pi.http3.set(&bind_key, None);
	if let Some(e) = endpoint.as_ref() {
		// Stop accepting; the connections watch their drain handles and finish on their own.
		e.endpoint.set_server_config(None);
	}
	upgrader.disable();
	drop(drain_mode);
	// Keep the endpoint (and its socket) alive until run_with_drain decides that every connection
	// finished or the deadline passed; dropping it closes all connections immediately.
	let _endpoint = endpoint;
	std::future::pending::<()>().await;
}

fn reconcile(pi: &ProxyInputs, bind_key: &BindKey, endpoint: &mut Option<Endpoint>) {
	let desired = match desired_state(pi, bind_key) {
		Ok(desired) => desired,
		Err(e) => {
			warn!(bind=%bind_key, "HTTP/3 is not served: {e:#}");
			None
		},
	};
	let Some(desired) = desired else {
		pi.http3.set(bind_key, None);
		if let Some(e) = endpoint.as_mut()
			&& e.serving
		{
			info!(bind=%bind_key, "stopped serving HTTP/3");
			e.retire();
		}
		return;
	};
	match endpoint.as_mut() {
		Some(e) => e.serve(desired.server_config),
		None => match Endpoint::bind(desired.address, desired.server_config) {
			Ok(e) => {
				info!(bind=%bind_key, address=%desired.address, "serving HTTP/3");
				*endpoint = Some(e);
			},
			Err(e) => {
				warn!(bind=%bind_key, address=%desired.address, "failed to bind HTTP/3 endpoint: {e:#}");
				pi.http3.set(bind_key, None);
				return;
			},
		},
	}
	pi.http3.set(bind_key, Some(desired.advertisement));
}

/// One downstream QUIC connection.
struct Connection {
	pi: Arc<ProxyInputs>,
	bind_key: BindKey,
	policies: FrontendPolices,
	/// Drain handle of the gateway; holding it delays shutdown until the connection is done.
	drain: DrainWatcher,
	retired: watch::Receiver<bool>,
	force_shutdown: watch::Receiver<()>,
}

impl Connection {
	async fn serve(self, incoming: quinn::Incoming) {
		let peer_addr = incoming.remote_address();
		let handshake_timeout = self
			.policies
			.tls
			.as_ref()
			.map(|t| t.handshake_timeout)
			.unwrap_or_else(crate::defaults::tls_handshake_timeout);
		let tls_start = Instant::now();
		let conn = match tokio::time::timeout(handshake_timeout, incoming).await {
			Ok(Ok(conn)) => conn,
			Ok(Err(e)) => {
				debug!(bind=%self.bind_key, src.addr=%peer_addr, "QUIC handshake failed: {e}");
				return;
			},
			Err(_) => {
				debug!(bind=%self.bind_key, src.addr=%peer_addr, "QUIC handshake timed out");
				return;
			},
		};
		let bind_key = self.bind_key.clone();
		if let Err(e) = self.serve_connection(conn.clone(), tls_start).await {
			debug!(bind=%bind_key, src.addr=%peer_addr, "HTTP/3 connection error: {e:#}");
			conn.close(H3_NO_ERROR.into(), b"");
		}
	}

	async fn serve_connection(
		self,
		conn: quinn::Connection,
		tls_start: Instant,
	) -> anyhow::Result<()> {
		let Connection {
			pi,
			bind_key,
			policies,
			drain,
			mut retired,
			mut force_shutdown,
		} = self;
		let sni = conn
			.handshake_data()
			.and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
			.and_then(|d| d.server_name)
			.unwrap_or_default();
		let Some(bind) = pi.stores.read_binds().bind(&bind_key) else {
			anyhow::bail!("bind not found");
		};
		// The certificate was chosen with the same listener selection.
		let listener = select_listener(&bind.listeners, &sni)
			.ok_or_else(|| anyhow::anyhow!("no HTTPS listener match for {sni}"))?;

		let tcp = TCPConnectionInfo {
			peer_addr: conn.remote_address(),
			local_addr: SocketAddr::new(
				conn.local_ip().unwrap_or_else(|| bind.address.ip()),
				bind.address.port(),
			),
			start: Instant::now(),
			raw_peer_addr: None,
		};
		let labels = TCPLabels {
			bind: Some(&bind_key).into(),
			gateway: Some(listener.name.as_gateway_name()).into(),
			listener: listener.name.listener_name.clone().into(),
			protocol: TransportProtocol::https,
		};
		pi.metrics
			.tls_handshake_duration
			.get_or_create(&labels)
			.observe(tls_start.elapsed().as_secs_f64());
		pi.metrics
			.downstream_connection
			.get_or_create(&labels)
			.inc();

		let unverified_workload =
			crate::cel::WorkloadContext::from_stores(&pi.stores, &pi.cfg.network, tcp.peer_addr.ip());
		let src = crate::cel::SourceContext::from_tcp_connection(&tcp, None, unverified_workload);
		let dst = crate::cel::DestinationContext::from_tcp_connection(&tcp);
		Gateway::authorize_downstream_connection(&pi, &policies, &src, &dst).await?;

		let mut ext = Extension::new();
		ext.insert(tcp);
		ext.insert(TLSConnectionInfo {
			src_identity: None,
			server_name: Some(sni),
			negotiated_alpn: Some(Alpn::Other),
		});
		ext.insert(src);
		ext.insert(dst);
		ext.insert(drain.observer());
		let connection = Arc::new(ext);

		let http = policies.http.clone().unwrap_or_default();
		let max_requests = http.max_concurrent_requests;
		let buffer = http.max_buffer_size;
		let request_admission = pi.admission.bind(&bind_key);
		let request_shed = pi
			.metrics
			.requests_shed
			.get_or_create(&AdmissionLabels {
				bind: Some(&bind_key).into(),
			})
			.clone();
		let proxy = HTTPProxy {
			bind_name: bind_key.clone(),
			inputs: pi.clone(),
			selected_listener: Some(listener),
			target_address: bind.address,
		};

		let max_field_section_size = http
			.http2_max_header_size
			.map(u64::from)
			.unwrap_or(DEFAULT_MAX_FIELD_SECTION_SIZE);
		let mut h3 = h3::server::builder()
			.max_field_section_size(max_field_section_size)
			.build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
			.await?;

		let max_connection_duration = async {
			match http.max_connection_duration.map(client::jittered) {
				Some(d) => tokio::time::sleep(d).await,
				None => std::future::pending().await,
			}
		};
		tokio::pin!(max_connection_duration);
		let gateway_drain = drain.wait_for_drain();
		tokio::pin!(gateway_drain);
		// Held until the connection is done, so a gateway drain waits for it.
		let mut drain_blocker = None;
		let mut draining = false;
		let mut requests = JoinSet::new();
		let connection_id = telemetry::current_connection_id();
		loop {
			tokio::select! {
				_ = force_shutdown.changed() => {
					info!(bind=%bind_key, "HTTP/3 connection forcefully terminated");
					requests.abort_all();
					break;
				},
				blocker = &mut gateway_drain, if drain_blocker.is_none() => {
					drain_blocker = Some(blocker);
					if !draining {
						draining = true;
						h3.shutdown(1).await?;
					}
				},
				_ = wait_retired(&mut retired), if !draining => {
					draining = true;
					h3.shutdown(1).await?;
				},
				_ = &mut max_connection_duration, if !draining => {
					debug!("max connection duration reached, closing connection after in-flight requests");
					draining = true;
					h3.shutdown(1).await?;
				},
				Some(_) = requests.join_next(), if !requests.is_empty() => {},
				_ = std::future::ready(()), if draining && requests.is_empty() => break,
				res = h3.accept() => match res {
					Ok(Some(resolver)) => {
						let Some(permit) = request_admission.requests.try_acquire(max_requests) else {
							request_shed.inc();
							debug!(bind=%bind_key, "request rejected: request limit");
							requests.spawn(reject_request(resolver));
							continue;
						};
						let proxy = proxy.clone();
						let connection = connection.clone();
						let serve = serve_request(proxy, connection, resolver, buffer, permit);
						match connection_id {
							Some(id) => requests.spawn(telemetry::connection_scope_with(id, serve)),
							None => requests.spawn(serve),
						};
					},
					// The client sent a GOAWAY and every request completed.
					Ok(None) => break,
					Err(e) => {
						if !e.is_h3_no_error() {
							debug!(bind=%bind_key, "HTTP/3 connection closed: {e}");
						}
						break;
					},
				},
			}
		}
		// Let in-flight requests finish unless the connection must terminate now.
		tokio::select! {
			_ = async { while requests.join_next().await.is_some() {} } => {},
			_ = force_shutdown.changed() => requests.abort_all(),
		}
		conn.close(H3_NO_ERROR.into(), b"");
		drop(drain_blocker);
		Ok(())
	}
}

async fn wait_retired(retired: &mut watch::Receiver<bool>) {
	if retired.wait_for(|retired| *retired).await.is_err() {
		// The endpoint is gone; the connection is closed with it.
		std::future::pending::<()>().await;
	}
}

type H3Resolver = h3::server::RequestResolver<h3_quinn::Connection, Bytes>;
type H3SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

async fn reject_request(resolver: H3Resolver) {
	let Ok((req, stream)) = resolver.resolve_request().await else {
		return;
	};
	let is_grpc = crate::http::is_grpc_request(&req);
	let (mut send, _recv) = stream.split();
	let response = ProxyError::RequestLimitExceeded.into_response_with_grpc(is_grpc);
	let _ = send_response(&mut send, response).await;
}

async fn serve_request(
	proxy: HTTPProxy,
	connection: Arc<Extension>,
	resolver: H3Resolver,
	buffer: Option<usize>,
	permit: super::admission::Permit,
) {
	let (req, stream) = match resolver.resolve_request().await {
		Ok(r) => r,
		Err(e) => {
			debug!("failed to read HTTP/3 request: {e}");
			return;
		},
	};
	let (mut send, recv) = stream.split();
	let mut req = req.map(|()| {
		crate::http::Body::new(RequestBody {
			stream: recv,
			data_done: false,
		})
	});
	if let Some(buffer) = buffer {
		req.extensions_mut().insert(BufferLimit::new(buffer));
	}
	let response =
		telemetry::request_scope(dtrace::DebugTracer::maybe_scope(req, |req| async move {
			proxy.proxy(connection, req).await
		}))
		.await;
	if let Err(e) = send_response(&mut send, response).await {
		debug!("failed to send HTTP/3 response: {e:#}");
	}
	drop(permit);
}

async fn send_response(
	send: &mut H3SendStream,
	response: crate::http::Response,
) -> anyhow::Result<()> {
	let (mut parts, mut body) = response.into_parts();
	strip_connection_headers(&mut parts.headers);
	send
		.send_response(http::Response::from_parts(parts, ()))
		.await?;
	while let Some(frame) = body.frame().await {
		let frame = frame.map_err(|e| anyhow::anyhow!("response body: {e}"))?;
		match frame.into_data() {
			Ok(data) => {
				if !data.is_empty() {
					send.send_data(data).await?;
				}
			},
			Err(frame) => {
				if let Ok(trailers) = frame.into_trailers() {
					send.send_trailers(trailers).await?;
					return Ok(());
				}
			},
		}
	}
	send.finish().await?;
	Ok(())
}

/// Removes connection-specific header fields, which HTTP/3 forbids (RFC 9114, section 4.2).
fn strip_connection_headers(headers: &mut HeaderMap) {
	if let Some(connection) = headers.remove(header::CONNECTION)
		&& let Ok(connection) = connection.to_str()
	{
		for name in connection.split(',') {
			headers.remove(name.trim());
		}
	}
	headers.remove(header::TRANSFER_ENCODING);
	headers.remove(header::UPGRADE);
	headers.remove("keep-alive");
	headers.remove("proxy-connection");
}

/// The body of a downstream HTTP/3 request.
struct RequestBody {
	stream: H3RecvStream,
	data_done: bool,
}

impl http_body::Body for RequestBody {
	type Data = Bytes;
	type Error = h3::error::StreamError;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.get_mut();
		if !this.data_done {
			match this.stream.poll_recv_data(cx) {
				Poll::Pending => return Poll::Pending,
				Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
				Poll::Ready(Ok(Some(mut data))) => {
					let data = data.copy_to_bytes(data.remaining());
					return Poll::Ready(Some(Ok(Frame::data(data))));
				},
				Poll::Ready(Ok(None)) => this.data_done = true,
			}
		}
		this.stream.poll_recv_trailers(cx).map(|res| {
			res
				.map(|trailers| trailers.map(Frame::trailers))
				.transpose()
		})
	}
}

#[cfg(test)]
#[path = "http3_test.rs"]
mod tests;
