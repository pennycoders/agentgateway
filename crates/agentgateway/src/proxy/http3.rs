//! Downstream HTTP/3 (QUIC).
//!
//! When the frontend HTTP policy of a bind enables `http3`, a QUIC endpoint is bound on the UDP
//! port matching the bind's TCP port. It terminates QUIC with the certificates of the bind's HTTPS
//! listeners, selecting the listener by SNI exactly like the TCP listener, and hands every request
//! to the same [`HTTPProxy`] used for HTTP/1.1 and HTTP/2, so routing and every policy apply
//! identically. While the endpoint serves a listener, responses on the TCP listener advertise it
//! with `Alt-Svc` (RFC 7838, RFC 9114 section 3.1.1).
//!
//! The endpoint follows the frontend policy and the bind's listeners: it is created when HTTP/3 is
//! enabled, its TLS configuration is replaced when listeners or certificates change, and it stops
//! accepting connections (sending a GOAWAY to existing ones) when HTTP/3 is disabled. Like on the
//! TCP listener, a connection is also drained when the listener serving it changes. With HTTP/3
//! disabled, which is the default, no UDP socket is opened.

#[path = "http3_quic.rs"]
mod quic;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use agent_core::drain::{self, DrainWatcher};
use agent_core::telemetry;
use bytes::{Buf, Bytes};
use h3::error::Code;
use http::{HeaderMap, HeaderValue, header};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use prometheus_client::metrics::counter::Counter;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::Gateway;
use super::admission::{BindAdmission, Limiter, Permit};
use super::httpproxy::HTTPProxy;
use crate::proxy::{ProxyError, dtrace};
use crate::store::FrontendPolices;
use crate::telemetry::metrics::{AdmissionLabels, TCPLabels};
use crate::transport::BufferLimit;
use crate::transport::stream::{
	Alpn, Extension, TCPConnectionInfo, TLSConnectionInfo, to_canonical,
};
use crate::types::agent::{
	BindKey, BindMode, Listener, ListenerKey, ListenerProtocol, ListenerSet, TransportProtocol,
	TunnelProtocol,
};
use crate::types::frontend;
use crate::{ProxyInputs, client};

/// The ALPN protocol identifier for HTTP/3 (RFC 9114, section 3.1).
const H3_ALPN: &[u8] = b"h3";
/// Default limit on the size of request headers, matching the HTTP/2 default.
const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;
/// Default QUIC connection flow-control window (RFC 9000, section 4), used unless the frontend
/// policy sets `http2ConnectionWindowSize`. quinn's own default is unbounded.
const DEFAULT_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// Default QUIC stream flow-control window, used unless the frontend policy sets
/// `http2WindowSize`.
const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
/// Unidirectional streams a client may open at once: its control stream (RFC 9114, section 6.2.1)
/// and QPACK encoder and decoder streams (RFC 9204, section 4.2), plus room for reserved stream
/// types used for greasing (RFC 9114, section 6.2.3). Push streams are server-initiated.
const MAX_CONCURRENT_UNI_STREAMS: u32 = 8;
/// Upper bound on the QUIC handshakes in progress per endpoint. Handshakes do not take a
/// connection permit until they complete.
const MAX_PENDING_HANDSHAKES: u32 = 1024;
/// Once this many handshakes are in progress, clients must prove that they own their address with
/// a Retry round trip (RFC 9000, section 8.1.2) before the server does any handshake work for
/// them, so spoofed Initial packets cannot fill the handshake budget. Tests always validate.
const ADDRESS_VALIDATION_THRESHOLD: usize = if cfg!(test) { 0 } else { 128 };
/// How long the first attempt to bind the UDP socket again waits after a failure; doubled after
/// every further failure, up to [`BIND_RETRY_MAX`].
const BIND_RETRY_INITIAL: Duration = Duration::from_millis(500);
const BIND_RETRY_MAX: Duration = Duration::from_secs(30);
/// How often an endpoint that no longer serves HTTP/3 checks whether its connections are gone,
/// so its UDP socket can be released.
const RETIRED_ENDPOINT_POLL: Duration = Duration::from_secs(1);
/// Invalidates the alternative services clients cached for the origin (RFC 7838, section 3).
const ALT_SVC_CLEAR: HeaderValue = HeaderValue::from_static("clear");

/// Tracks the binds that currently serve HTTP/3, so the TCP listener can advertise them.
#[derive(Debug, Default)]
pub struct Http3Registry {
	// Fast path for the common case where no bind serves HTTP/3.
	any: AtomicBool,
	binds: RwLock<HashMap<BindKey, BindAdvertisement>>,
	/// Identifies the supervisors of the binds, so a replaced one cannot clear its successor.
	next_owner: AtomicU64,
}

#[derive(Debug, Default)]
struct BindAdvertisement {
	/// The supervisor that last updated the bind.
	owner: u64,
	serving: Option<Arc<Advertisement>>,
	/// Listeners that stopped being served over HTTP/3, with the time until which clients may
	/// still have them cached. Their responses carry `Alt-Svc: clear` until then.
	cleared: HashMap<ListenerKey, Instant>,
}

#[derive(Debug)]
struct Advertisement {
	/// HTTPS listeners whose certificates the QUIC endpoint serves.
	listeners: HashSet<ListenerKey>,
	alt_svc: HeaderValue,
	max_age: Duration,
}

impl Http3Registry {
	/// Adds an `Alt-Svc` header advertising HTTP/3 when the bind serves the listener over HTTP/3,
	/// or clearing an advertisement clients may still have cached after it stopped.
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
		let entry = binds.get(bind)?;
		if let Some(serving) = &entry.serving
			&& serving.listeners.contains(listener)
		{
			return Some(serving.alt_svc.clone());
		}
		entry
			.cleared
			.get(listener)
			.is_some_and(|until| *until > Instant::now())
			.then_some(ALT_SVC_CLEAR)
	}

	/// Whether the bind currently serves the listener over HTTP/3.
	pub fn is_serving(&self, bind: &BindKey, listener: &ListenerKey) -> bool {
		self
			.alt_svc(bind, listener)
			.is_some_and(|v| v != ALT_SVC_CLEAR)
	}

	fn owner(&self) -> u64 {
		self.next_owner.fetch_add(1, Ordering::Relaxed)
	}

	fn set(&self, bind: &BindKey, owner: u64, advertisement: Option<Advertisement>) {
		let mut binds = self.binds.write().expect("http3 registry poisoned");
		let entry = binds.entry(bind.clone()).or_default();
		// A supervisor that is still draining after the bind was replaced must not override its
		// successor, which has a larger id.
		if entry.owner > owner {
			return;
		}
		entry.owner = owner;
		let now = Instant::now();
		if let Some(old) = entry.serving.take() {
			for listener in &old.listeners {
				if advertisement
					.as_ref()
					.is_none_or(|new| !new.listeners.contains(listener))
				{
					entry.cleared.insert(listener.clone(), now + old.max_age);
				}
			}
		}
		if let Some(new) = &advertisement {
			for listener in &new.listeners {
				entry.cleared.remove(listener);
			}
		}
		entry.cleared.retain(|_, until| *until > now);
		entry.serving = advertisement.map(Arc::new);
		if entry.serving.is_none() && entry.cleared.is_empty() {
			binds.remove(bind);
		}
		self.any.store(!binds.is_empty(), Ordering::Relaxed);
	}

	/// Forgets a bind whose supervisor ended, unless another supervisor took it over.
	fn remove(&self, bind: &BindKey, owner: u64) {
		let mut binds = self.binds.write().expect("http3 registry poisoned");
		if binds.get(bind).is_some_and(|entry| entry.owner == owner) {
			binds.remove(bind);
		}
		self.any.store(!binds.is_empty(), Ordering::Relaxed);
	}
}

/// The `Alt-Svc` value advertising HTTP/3 on `port` (RFC 7838 section 3, RFC 9114 section 3.1.1).
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

/// Selects the listener for an SNI like the TCP listener does, among HTTPS and TLS listeners.
/// When the SNI selects a TLS listener, which passes TLS through or serves raw TCP, HTTP/3 is not
/// served for it and the handshake fails.
fn select_listener(listeners: &ListenerSet, sni: &str) -> Option<Arc<Listener>> {
	listeners
		.best_match_tls(sni)
		.filter(|l| matches!(l.protocol, ListenerProtocol::HTTPS(_)))
}

/// Limits of the QUIC transport of an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TransportLimits {
	max_concurrent_bidi_streams: u32,
	max_concurrent_uni_streams: u32,
	receive_window: u32,
	stream_receive_window: u32,
	idle_timeout: Duration,
}

impl TransportLimits {
	fn new(settings: &frontend::HTTP3, http: &frontend::HTTP) -> Self {
		Self {
			max_concurrent_bidi_streams: settings.max_concurrent_streams().get(),
			max_concurrent_uni_streams: MAX_CONCURRENT_UNI_STREAMS,
			receive_window: http
				.http2_connection_window_size
				.unwrap_or(DEFAULT_RECEIVE_WINDOW),
			stream_receive_window: http
				.http2_window_size
				.unwrap_or(DEFAULT_STREAM_RECEIVE_WINDOW),
			idle_timeout: settings.idle_timeout(),
		}
	}

	fn transport_config(&self) -> anyhow::Result<quinn::TransportConfig> {
		let mut transport = quinn::TransportConfig::default();
		transport
			.max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.into())
			.max_concurrent_uni_streams(self.max_concurrent_uni_streams.into())
			.receive_window(self.receive_window.into())
			.stream_receive_window(self.stream_receive_window.into())
			// HTTP/3 datagrams (RFC 9297) are not supported; do not buffer any.
			.datagram_receive_buffer_size(None)
			.max_idle_timeout(Some(self.idle_timeout.try_into()?));
		Ok(transport)
	}
}

/// What the QUIC endpoint of a bind should currently serve.
struct Desired {
	address: SocketAddr,
	server_config: Arc<quinn::ServerConfig>,
	served: Arc<ServedListeners>,
	advertisement: Advertisement,
}

/// The listeners a QUIC server configuration was built from.
///
/// A handshake completes with the configuration that was current when it started, up to the TLS
/// handshake timeout earlier, so its connection must be served by these listeners, not by those
/// that are in the store by the time it completes.
#[derive(Debug)]
struct ServedListeners {
	listeners: Arc<ListenerSet>,
	/// The HTTPS listeners whose certificates the configuration serves.
	served: HashSet<ListenerKey>,
}

impl ServedListeners {
	/// Selects the listener serving a connection whose handshake used these listeners, and checks
	/// that the store still serves the connection with it. Otherwise the connection could be served
	/// by a listener that changed during the handshake, for example to verify client certificates,
	/// or that a more specific listener added during the handshake now takes over.
	fn select(&self, current: &ListenerSet, sni: &str) -> anyhow::Result<Arc<Listener>> {
		let listener = select_listener(&self.listeners, sni)
			.filter(|l| self.served.contains(&l.key))
			.ok_or_else(|| anyhow::anyhow!("no HTTPS listener served over HTTP/3 matches {sni}"))?;
		match select_listener(current, sni) {
			Some(current) if current.serving_eq(&listener) => Ok(listener),
			_ => anyhow::bail!("the listener for {sni} changed during the handshake"),
		}
	}
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
	if cfg!(feature = "crypto-symcrypt") {
		anyhow::bail!(
			"HTTP/3 is not supported by this build: the SymCrypt crypto provider does not implement QUIC"
		);
	}
	// These change what a TCP connection carries before HTTP, or how its source is identified;
	// none of them exists for QUIC, so serving HTTP/3 would bypass them.
	if bind.tunnel_protocol != TunnelProtocol::Direct {
		anyhow::bail!(
			"HTTP/3 is not served on binds with tunnel protocol {:?}",
			bind.tunnel_protocol
		);
	}
	if policies.proxy.is_some() {
		anyhow::bail!("HTTP/3 cannot be combined with the PROXY protocol frontend policy");
	}
	if policies
		.connect
		.as_ref()
		.is_some_and(|c| c.mode != frontend::ConnectMode::Deny)
	{
		anyhow::bail!("HTTP/3 cannot be combined with a CONNECT frontend policy");
	}
	if policies.substrate_egress_actor_resolution.is_some() {
		anyhow::bail!("HTTP/3 cannot be combined with egress actor resolution");
	}

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
	let listener_keys: HashSet<ListenerKey> = resolvers.keys().cloned().collect();
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
	let http = policies.http.clone().unwrap_or_default();
	server_config.transport_config(Arc::new(
		TransportLimits::new(settings, &http).transport_config()?,
	));

	let max_age = settings.alt_svc_max_age();
	let port = settings
		.alt_svc_port
		.map_or(bind.address.port(), std::num::NonZeroU16::get);
	Ok(Some(Desired {
		address: bind.address,
		server_config: Arc::new(server_config),
		served: Arc::new(ServedListeners {
			listeners: bind.listeners.clone(),
			served: listener_keys.clone(),
		}),
		advertisement: Advertisement {
			listeners: listener_keys,
			alt_svc: alt_svc_value(port, max_age),
			max_age,
		},
	}))
}

/// A bound QUIC endpoint.
struct Endpoint {
	endpoint: quinn::Endpoint,
	/// The configuration new connections are accepted with, and the listeners it was built from.
	server_config: Arc<quinn::ServerConfig>,
	served: Arc<ServedListeners>,
	/// Set to true when the endpoint stops serving HTTP/3; its connections then drain.
	/// Replaced by a fresh channel if HTTP/3 is enabled again.
	retired: watch::Sender<bool>,
	serving: bool,
	/// Handshakes in progress.
	handshakes: Limiter,
}

impl Endpoint {
	fn bind(
		address: SocketAddr,
		server_config: Arc<quinn::ServerConfig>,
		served: Arc<ServedListeners>,
	) -> anyhow::Result<Self> {
		let socket = std::net::UdpSocket::bind(address)?;
		let endpoint = quinn::Endpoint::new(
			quinn::EndpointConfig::default(),
			Some((*server_config).clone()),
			socket,
			Arc::new(quinn::TokioRuntime),
		)?;
		Ok(Self {
			endpoint,
			server_config,
			served,
			retired: watch::channel(false).0,
			serving: true,
			handshakes: Default::default(),
		})
	}

	fn serve(&mut self, server_config: Arc<quinn::ServerConfig>, served: Arc<ServedListeners>) {
		self
			.endpoint
			.set_server_config(Some((*server_config).clone()));
		self.server_config = server_config;
		self.served = served;
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
		self.endpoint.close(varint(Code::H3_NO_ERROR), b"");
	}
}

/// Whether a client must complete a Retry round trip before its handshake starts (RFC 9000,
/// section 8.1.2). Validation costs every client a round trip, so it is only required once many
/// handshakes are in progress.
fn requires_address_validation(
	address_validated: bool,
	may_retry: bool,
	pending_handshakes: usize,
	threshold: usize,
) -> bool {
	!address_validated && may_retry && pending_handshakes >= threshold
}

/// Clears the advertisement of a bind when its HTTP/3 supervisor ends, including when it is
/// aborted because the bind was removed or replaced.
struct RegistryGuard {
	registry: Arc<Http3Registry>,
	bind_key: BindKey,
	owner: u64,
}

impl Drop for RegistryGuard {
	fn drop(&mut self) {
		self.registry.remove(&self.bind_key, self.owner);
	}
}

/// Runs the HTTP/3 endpoint of a bind for as long as the bind exists.
///
/// Cancelling `stop`, when the bind is removed or replaced, stops accepting connections and asks
/// the existing ones to finish, like TCP connections whose listener is gone. The UDP socket is
/// released once they are done, or after the termination deadline.
pub(crate) async fn run_bind(
	pi: Arc<ProxyInputs>,
	drain: DrainWatcher,
	bind_key: BindKey,
	stop: CancellationToken,
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
	let owner = pi.http3.owner();
	let _registry = RegistryGuard {
		registry: pi.http3.clone(),
		bind_key: bind_key.clone(),
		owner,
	};
	drain::run_with_drain(
		component,
		drain,
		max_deadline,
		min_deadline,
		|drain, force_shutdown| async move {
			supervise(pi, drain, force_shutdown, bind_key, owner, stop).await;
		},
	)
	.await;
	Ok(())
}

async fn supervise(
	pi: Arc<ProxyInputs>,
	drain: DrainWatcher,
	force_shutdown: watch::Receiver<()>,
	bind_key: BindKey,
	owner: u64,
	stop: CancellationToken,
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
	// Set while the UDP socket cannot be bound: the delay before the next attempt.
	let mut bind_retry: Option<Duration> = None;

	let drain_mode = 'outer: loop {
		bind_retry = match reconcile(&pi, &bind_key, owner, &mut endpoint, bind_retry) {
			BindState::Failed(next) => Some(next),
			BindState::Ok => None,
		};
		let retry_bind = async {
			match bind_retry {
				Some(delay) => tokio::time::sleep(delay).await,
				None => std::future::pending().await,
			}
		};
		tokio::pin!(retry_bind);
		loop {
			let accept = async {
				match endpoint.as_ref().filter(|e| e.serving) {
					Some(e) => e.endpoint.accept().await,
					None => std::future::pending().await,
				}
			};
			let retired = endpoint.as_ref().is_some_and(|e| !e.serving);
			tokio::select! {
				res = &mut wait => break 'outer Some(res),
				_ = stop.cancelled() => break 'outer None,
				res = listener_changes.changed() => {
					if res.is_err() {
						break 'outer Some((&mut wait).await);
					}
					break;
				},
				res = policy_changes.changed() => {
					if res.is_err() {
						break 'outer Some((&mut wait).await);
					}
					break;
				},
				_ = &mut retry_bind => break,
				incoming = accept => {
					let Some(incoming) = incoming else {
						// The endpoint was closed; bind it again on the next reconcile.
						endpoint = None;
						break;
					};
					let Some(e) = endpoint.as_ref() else {
						continue;
					};
					let peer_addr = to_canonical(incoming.remote_address());
					if requires_address_validation(
						incoming.remote_address_validated(),
						incoming.may_retry(),
						e.handshakes.active(),
						ADDRESS_VALIDATION_THRESHOLD,
					) {
						debug!(bind=%bind_key, src.addr=%peer_addr, "QUIC address validation: sending Retry");
						if let Err(err) = incoming.retry() {
							err.into_incoming().refuse();
						}
						continue;
					}
					let policies = Gateway::frontend_policies_for_bind(&bind_key, &pi);
					let max_connections = policies.tcp.as_ref().and_then(|tcp| tcp.max_connections);
					// Shed early when the bind is already at its connection limit, but only take a
					// connection permit once the handshake completed: until then, the client may not
					// even own its address.
					let handshake = if admission.connections.has_capacity(max_connections) {
						e.handshakes.try_acquire(NonZeroU32::new(MAX_PENDING_HANDSHAKES))
					} else {
						None
					};
					let Some(handshake) = handshake else {
						connection_shed.inc();
						debug!(bind=%bind_key, src.addr=%peer_addr, "downstream QUIC connection rejected: connection limit");
						incoming.refuse();
						continue;
					};
					let connection = Connection {
						pi: pi.clone(),
						bind_key: bind_key.clone(),
						policies,
						peer_addr,
						server_config: e.server_config.clone(),
						served: e.served.clone(),
						drain: upgrader.upgrade(weak.clone()),
						retired: e.retired.subscribe(),
						force_shutdown: force_shutdown.clone(),
						admission: admission.clone(),
						connection_shed: connection_shed.clone(),
					};
					tokio::spawn(telemetry::connection_scope(connection.serve(incoming, handshake)));
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
	pi.http3.set(&bind_key, owner, None);
	let Some(drain_mode) = drain_mode else {
		// The bind was removed or replaced. Its connections are asked to finish; returning would
		// force them to shut down, and dropping the endpoint would close them.
		if let Some(mut e) = endpoint {
			if e.serving {
				info!(bind=%bind_key, "bind removed, draining HTTP/3 connections");
			}
			e.retire();
			if tokio::time::timeout(pi.cfg.termination_max_deadline, e.endpoint.wait_idle())
				.await
				.is_err()
			{
				warn!(bind=%bind_key, "HTTP/3 connections did not finish in time, closing them");
			}
		}
		return;
	};
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

enum BindState {
	Ok,
	/// The UDP socket could not be bound; try again after the delay.
	Failed(Duration),
}

fn reconcile(
	pi: &ProxyInputs,
	bind_key: &BindKey,
	owner: u64,
	endpoint: &mut Option<Endpoint>,
	bind_retry: Option<Duration>,
) -> BindState {
	let desired = match desired_state(pi, bind_key) {
		Ok(desired) => desired,
		Err(e) => {
			warn!(bind=%bind_key, "HTTP/3 is not served: {e:#}");
			None
		},
	};
	let Some(desired) = desired else {
		pi.http3.set(bind_key, owner, None);
		if let Some(e) = endpoint.as_mut()
			&& e.serving
		{
			info!(bind=%bind_key, "stopped serving HTTP/3");
			e.retire();
		}
		return BindState::Ok;
	};
	match endpoint.as_mut() {
		Some(e) => e.serve(desired.server_config, desired.served),
		None => match Endpoint::bind(desired.address, desired.server_config, desired.served) {
			Ok(e) => {
				info!(bind=%bind_key, address=%desired.address, "serving HTTP/3");
				*endpoint = Some(e);
			},
			Err(e) => {
				let next = bind_retry
					.map(|d| (d * 2).min(BIND_RETRY_MAX))
					.unwrap_or(BIND_RETRY_INITIAL);
				warn!(bind=%bind_key, address=%desired.address, "failed to bind HTTP/3 endpoint, retrying in {next:?}: {e:#}");
				pi.http3.set(bind_key, owner, None);
				return BindState::Failed(next);
			},
		},
	}
	pi.http3.set(bind_key, owner, Some(desired.advertisement));
	BindState::Ok
}

/// One downstream QUIC connection.
struct Connection {
	pi: Arc<ProxyInputs>,
	bind_key: BindKey,
	policies: FrontendPolices,
	peer_addr: SocketAddr,
	/// The configuration the handshake uses, and the listeners it was built from.
	server_config: Arc<quinn::ServerConfig>,
	served: Arc<ServedListeners>,
	/// Drain handle of the gateway; holding it delays shutdown until the connection is done.
	drain: DrainWatcher,
	retired: watch::Receiver<bool>,
	force_shutdown: watch::Receiver<()>,
	admission: Arc<BindAdmission>,
	connection_shed: Counter,
}

impl Connection {
	async fn serve(self, incoming: quinn::Incoming, handshake: Permit) {
		let peer_addr = self.peer_addr;
		let handshake_timeout = self
			.policies
			.tls
			.as_ref()
			.map(|t| t.handshake_timeout)
			.unwrap_or_else(crate::defaults::tls_handshake_timeout);
		let tls_start = Instant::now();
		let server_config = self.server_config.clone();
		let accept = async { incoming.accept_with(server_config)?.await };
		let conn = match tokio::time::timeout(handshake_timeout, accept).await {
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
		drop(handshake);
		let max_connections = self
			.policies
			.tcp
			.as_ref()
			.and_then(|tcp| tcp.max_connections);
		let Some(permit) = self.admission.connections.try_acquire(max_connections) else {
			self.connection_shed.inc();
			debug!(bind=%self.bind_key, src.addr=%peer_addr, "downstream QUIC connection rejected: connection limit");
			conn.close(varint(Code::H3_NO_ERROR), b"connection limit reached");
			return;
		};
		let bind_key = self.bind_key.clone();
		if let Err(e) = self.serve_connection(conn.clone(), tls_start).await {
			debug!(bind=%bind_key, src.addr=%peer_addr, "HTTP/3 connection error: {e:#}");
			conn.close(varint(Code::H3_NO_ERROR), b"");
		}
		drop(permit);
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
			peer_addr,
			server_config: _,
			served,
			drain,
			mut retired,
			mut force_shutdown,
			admission,
			connection_shed: _,
		} = self;
		// Subscribe before reading the listener, so no change is missed.
		let listener_changes = pi.stores.read_binds().subscribe_listener_changes();
		let sni = conn
			.handshake_data()
			.and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
			.and_then(|d| d.server_name)
			.unwrap_or_default();
		let Some(bind) = pi.stores.read_binds().bind(&bind_key) else {
			anyhow::bail!("bind not found");
		};
		// The certificate was chosen with the same listener selection, among the listeners the
		// handshake's configuration was built from.
		let listener = served.select(&bind.listeners, &sni)?;

		// A `[::]` bind sees IPv4 clients as IPv4-mapped IPv6 addresses; canonicalize them like the
		// TCP listener does, so authorization, rate limits, workload lookup and logs see IPv4.
		let tcp = TCPConnectionInfo {
			peer_addr,
			local_addr: SocketAddr::new(
				conn
					.local_ip()
					.unwrap_or_else(|| bind.address.ip())
					.to_canonical(),
				bind.address.port(),
			),
			start: Instant::now(),
			raw_peer_addr: None,
		};
		let labels = TCPLabels {
			bind: Some(&bind_key).into(),
			gateway: Some(listener.name.as_gateway_name()).into(),
			listener: listener.name.listener_name.clone().into(),
			protocol: TransportProtocol::http3,
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
		let idle_timeout = http
			.http3
			.as_ref()
			.map(frontend::HTTP3::idle_timeout)
			.unwrap_or(frontend::HTTP3::DEFAULT_IDLE_TIMEOUT);
		let requests_ctx = Arc::new(RequestContext {
			proxy: HTTPProxy {
				bind_name: bind_key.clone(),
				inputs: pi.clone(),
				selected_listener: Some(listener.clone()),
				target_address: bind.address,
			},
			connection,
			buffer: http.max_buffer_size,
			// Bounds header reads like `header_read_timeout` on the TCP listener's HTTP/1 server.
			header_timeout: http.http1_idle_timeout,
			idle_timeout,
			max_requests: http.max_concurrent_requests,
			admission,
			request_shed: pi
				.metrics
				.requests_shed
				.get_or_create(&AdmissionLabels {
					bind: Some(&bind_key).into(),
				})
				.clone(),
		});

		let max_field_section_size = http
			.http2_max_header_size
			.map(u64::from)
			.unwrap_or(DEFAULT_MAX_FIELD_SECTION_SIZE);
		let streams = quic::StreamRegistry::default();
		let mut h3 = h3::server::builder()
			.max_field_section_size(max_field_section_size)
			.build::<_, Bytes>(quic::Connection::new(conn.clone(), streams.clone()))
			.await?;

		let max_connection_duration = async {
			match http.max_connection_duration.map(client::jittered) {
				Some(d) => tokio::time::sleep(d).await,
				None => std::future::pending().await,
			}
		};
		tokio::pin!(max_connection_duration);
		let listener_changed = Gateway::wait_for_listener_change(
			pi.stores.clone(),
			bind_key.clone(),
			listener.clone(),
			listener_changes,
		);
		tokio::pin!(listener_changed);
		let gateway_drain = drain.wait_for_drain();
		tokio::pin!(gateway_drain);
		// Held until the connection is done, so a gateway drain waits for it.
		let mut drain_blocker = None;
		// Set once a GOAWAY was sent. `h3.shutdown(1)` announces the stream after the last accepted
		// one, so that every accepted request may still be processed (RFC 9114, section 5.2).
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
				_ = &mut listener_changed, if !draining => {
					info!(bind=%bind_key, listener=%listener.key, "listener changed, draining downstream HTTP/3 connection");
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
						// `h3` accepts one request stream per call, so this is the stream of `resolver`.
						let handle = streams.take_accepted();
						if draining {
							// The GOAWAY announced that streams from the one after the last accepted
							// stream on are not processed (RFC 9114, section 5.2), but `h3` still accepts
							// that one. Reject it, so the client can safely retry it elsewhere.
							if let Some(handle) = handle {
								handle.abort_on_drop(Code::H3_REQUEST_REJECTED);
							}
							drop(resolver);
							continue;
						}
						let serve = serve_request(requests_ctx.clone(), resolver, handle);
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
		// Let in-flight requests finish unless the connection must terminate now. Each request
		// waits until the client acknowledged its response, since closing the connection discards
		// stream data that was not delivered yet (RFC 9000, section 10.2).
		tokio::select! {
			_ = async { while requests.join_next().await.is_some() {} } => {},
			_ = force_shutdown.changed() => requests.abort_all(),
		}
		conn.close(varint(Code::H3_NO_ERROR), b"");
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

type H3Resolver = h3::server::RequestResolver<quic::Connection, Bytes>;
type H3SendStream = h3::server::RequestStream<quic::SendStream<Bytes>, Bytes>;
type H3RecvStream = h3::server::RequestStream<quic::RecvStream, Bytes>;

/// What every request of a connection shares.
struct RequestContext {
	proxy: HTTPProxy,
	connection: Arc<Extension>,
	buffer: Option<usize>,
	header_timeout: Duration,
	idle_timeout: Duration,
	max_requests: Option<NonZeroU32>,
	admission: Arc<BindAdmission>,
	request_shed: Counter,
}

async fn serve_request(
	ctx: Arc<RequestContext>,
	resolver: H3Resolver,
	handle: Option<quic::StreamHandle>,
) {
	let mut handle = handle.unwrap_or_else(quic::StreamHandle::detached);
	let resolve = resolver.resolve_request();
	tokio::pin!(resolve);
	let resolved = tokio::select! {
		resolved = &mut resolve => resolved,
		_ = tokio::time::sleep(ctx.header_timeout) => {
			debug!("timed out reading HTTP/3 request headers");
			// Set before the stream is dropped with `resolve`. The request was not processed, so
			// the client may retry it (RFC 9114, section 4.1.1).
			handle.abort_on_drop(Code::H3_REQUEST_REJECTED);
			return;
		},
	};
	let (req, stream) = match resolved {
		Ok(r) => r,
		Err(e) => {
			debug!("failed to read HTTP/3 request: {e}");
			return;
		},
	};
	let content_length = match request_content_length(req.headers()) {
		Ok(length) => length,
		Err(e) => {
			// Malformed requests are stream errors (RFC 9114, section 4.1.2).
			debug!("malformed HTTP/3 request: {e}");
			handle.abort_on_drop(Code::H3_MESSAGE_ERROR);
			return;
		},
	};
	// From here on, a response that is not finished is reset, never presented as complete.
	handle.reset_on_drop(Code::H3_INTERNAL_ERROR);
	let (mut send, recv) = stream.split();
	// Capacity is only taken for requests whose headers arrived.
	let Some(permit) = ctx.admission.requests.try_acquire(ctx.max_requests) else {
		ctx.request_shed.inc();
		debug!(bind=%ctx.proxy.bind_name, "request rejected: request limit");
		let is_grpc = crate::http::is_grpc_request(&req);
		let response = ProxyError::RequestLimitExceeded.into_response_with_grpc(is_grpc);
		let _ = send_response(&mut send, response).await;
		return;
	};
	let body = RequestBody::new(recv, content_length);
	let mut req = req.map(|()| crate::http::Body::new(body));
	if let Some(buffer) = ctx.buffer {
		req.extensions_mut().insert(BufferLimit::new(buffer));
	}
	let proxy = ctx.proxy.clone();
	let connection = ctx.connection.clone();
	let response =
		telemetry::request_scope(dtrace::DebugTracer::maybe_scope(req, |req| async move {
			proxy.proxy(connection, req).await
		}));
	// Stop proxying once the client cancels the request (RFC 9114, section 4.1.1).
	let response = tokio::select! {
		response = response => response,
		code = &mut handle.stopped => {
			debug!(code=?code, "HTTP/3 request cancelled by the client");
			handle.abort_on_drop(Code::H3_REQUEST_CANCELLED);
			return;
		},
	};
	let sent = send_response(&mut send, response).await;
	drop(permit);
	match sent {
		Ok(()) => {
			// Wait until the client acknowledged the response (or stopped reading it), so closing
			// the connection afterwards does not lose its tail. A client that went away is bounded
			// by the idle timeout.
			let _ = tokio::time::timeout(ctx.idle_timeout, &mut handle.stopped).await;
		},
		Err(e) => debug!("failed to send HTTP/3 response: {e:#}"),
	}
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
		let frame = match frame {
			Ok(frame) => frame,
			Err(e) => {
				// Finishing the stream would present the truncated response as complete.
				send.stop_stream(Code::H3_INTERNAL_ERROR);
				anyhow::bail!("response body: {e}");
			},
		};
		match frame.into_data() {
			Ok(data) => {
				if !data.is_empty() {
					send.send_data(data).await?;
				}
			},
			Err(frame) => {
				if let Ok(trailers) = frame.into_trailers() {
					send.send_trailers(trailers).await?;
					break;
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

fn varint(code: Code) -> quinn::VarInt {
	quinn::VarInt::from_u64(code.value()).unwrap_or(quinn::VarInt::MAX)
}

/// The body of a downstream HTTP/3 request.
///
/// It reports its exact length when the request has a `content-length`, and an empty body when
/// the client finished the stream with the headers, so bodyless requests are forwarded without a
/// body. The DATA frames must add up to the `content-length` (RFC 9114, section 4.1.2).
struct RequestBody {
	stream: H3RecvStream,
	/// Data read ahead while checking whether the body is empty.
	buffered: Option<Bytes>,
	trailers: Option<HeaderMap>,
	data_done: bool,
	end: bool,
	/// Bytes the `content-length` still announces.
	remaining: Option<u64>,
}

/// The `content-length` of a request, which must be unambiguous.
fn request_content_length(headers: &HeaderMap) -> anyhow::Result<Option<u64>> {
	let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
	let Some(value) = lengths.next() else {
		return Ok(None);
	};
	let length = parse_content_length(value)?;
	if lengths.any(|other| parse_content_length(other).ok() != Some(length)) {
		anyhow::bail!("conflicting content-length values");
	}
	Ok(Some(length))
}

impl RequestBody {
	/// `remaining` is the `content-length` of the request.
	fn new(stream: H3RecvStream, remaining: Option<u64>) -> Self {
		let mut body = Self {
			stream,
			buffered: None,
			trailers: None,
			data_done: false,
			end: false,
			remaining,
		};
		body.read_ahead();
		body
	}

	/// Reads what already arrived, without waiting, to learn whether the body is empty.
	fn read_ahead(&mut self) {
		let mut cx = Context::from_waker(Waker::noop());
		match self.stream.poll_recv_data(&mut cx) {
			Poll::Ready(Ok(Some(mut data))) => {
				self.buffered = Some(data.copy_to_bytes(data.remaining()));
				return;
			},
			Poll::Ready(Ok(None)) => self.data_done = true,
			// Errors are reported when the body is read.
			Poll::Ready(Err(_)) | Poll::Pending => return,
		}
		if let Poll::Ready(Ok(trailers)) = self.stream.poll_recv_trailers(&mut cx) {
			match trailers {
				Some(trailers) => self.trailers = Some(trailers),
				// A content-length announcing data that never came is reported when reading.
				None => self.end = self.remaining.is_none_or(|r| r == 0),
			}
		}
	}

	fn account(&mut self, len: usize) -> Result<(), axum_core::BoxError> {
		if let Some(remaining) = self.remaining.as_mut() {
			*remaining = remaining
				.checked_sub(len as u64)
				.ok_or("request body is longer than its content-length")?;
		}
		Ok(())
	}
}

fn parse_content_length(value: &HeaderValue) -> anyhow::Result<u64> {
	value
		.to_str()
		.ok()
		.and_then(|v| v.parse::<u64>().ok())
		.ok_or_else(|| anyhow::anyhow!("invalid content-length"))
}

impl http_body::Body for RequestBody {
	type Data = Bytes;
	type Error = axum_core::BoxError;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.get_mut();
		if let Some(data) = this.buffered.take() {
			this.account(data.len())?;
			return Poll::Ready(Some(Ok(Frame::data(data))));
		}
		if !this.data_done {
			match this.stream.poll_recv_data(cx) {
				Poll::Pending => return Poll::Pending,
				Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
				Poll::Ready(Ok(Some(mut data))) => {
					let data = data.copy_to_bytes(data.remaining());
					this.account(data.len())?;
					return Poll::Ready(Some(Ok(Frame::data(data))));
				},
				Poll::Ready(Ok(None)) => this.data_done = true,
			}
		}
		if this.remaining.is_some_and(|r| r > 0) {
			this.remaining = Some(0);
			this.end = true;
			return Poll::Ready(Some(Err(
				"request body is shorter than its content-length".into(),
			)));
		}
		if let Some(trailers) = this.trailers.take() {
			this.end = true;
			return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
		}
		if this.end {
			return Poll::Ready(None);
		}
		let trailers = std::task::ready!(this.stream.poll_recv_trailers(cx));
		this.end = true;
		Poll::Ready(
			trailers
				.map_err(Into::into)
				.map(|t| t.map(Frame::trailers))
				.transpose(),
		)
	}

	fn is_end_stream(&self) -> bool {
		self.end && self.buffered.is_none() && self.trailers.is_none()
	}

	fn size_hint(&self) -> SizeHint {
		if self.is_end_stream() {
			return SizeHint::with_exact(0);
		}
		match self.remaining {
			Some(remaining) => SizeHint::with_exact(remaining),
			None => SizeHint::default(),
		}
	}
}

#[cfg(test)]
#[path = "http3_test.rs"]
mod tests;
