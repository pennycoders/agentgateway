//! The QUIC transport of the HTTP/3 server.
//!
//! This mirrors `h3_quinn::Connection`, which it reuses for unidirectional (control and QPACK)
//! streams, but implements request streams itself so the server can observe them:
//!
//! - every request stream exposes a future that resolves once the client stops reading the
//!   response (STOP_SENDING, RFC 9000 section 3.5) or acknowledged all of it, so cancelled requests
//!   are not proxied to completion and connections are only closed once responses are delivered;
//! - a response stream dropped before being finished can be reset instead of being finished (as
//!   quinn does), so a truncated response is never presented as complete (RFC 9114 section 4.1);
//! - a request that is rejected or cancelled asks the client to stop sending it with the same error
//!   code as the reset of its response (RFC 9114 section 4.1.1).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{self, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::stream::{self, Stream, StreamExt};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use quinn::VarInt;

type BoxStream<T> = Pin<Box<dyn Stream<Item = T> + Send + Sync>>;

/// Resolves when the client stops reading a response (`Some` with its error code) or acknowledged
/// all of it (`None`). It also resolves (with `Some`) when the connection is lost.
pub(super) type Stopped = Pin<Box<dyn Future<Output = Option<VarInt>> + Send + Sync>>;

/// Observes and controls one request stream while `h3` owns it.
pub(super) struct StreamHandle {
	pub(super) stopped: Stopped,
	codes: Arc<StreamCodes>,
}

/// The error codes a request stream is terminated with when it is dropped. Zero means none.
#[derive(Default)]
struct StreamCodes {
	/// Resets the response if it is not finished.
	reset: AtomicU64,
	/// Asks the client to stop sending the request if it is not received entirely. Otherwise
	/// H3_NO_ERROR is used, as when the response is complete without the rest of the request.
	stop: AtomicU64,
}

impl StreamHandle {
	/// A handle that observes nothing, for a stream whose handle is missing.
	pub(super) fn detached() -> Self {
		Self {
			stopped: Box::pin(std::future::pending()),
			codes: Default::default(),
		}
	}

	/// Resets the response with `code` if it is dropped before being finished, instead of
	/// finishing it, which would present a truncated response as complete.
	pub(super) fn reset_on_drop(&self, code: Code) {
		self.codes.reset.store(code.value(), Ordering::Relaxed);
	}

	/// Terminates both directions of the stream with `code` when it is dropped: the request is
	/// rejected or cancelled, so the client must neither wait for the response nor keep sending
	/// the request (RFC 9114 section 4.1.1).
	pub(super) fn abort_on_drop(&self, code: Code) {
		self.reset_on_drop(code);
		self.codes.stop.store(code.value(), Ordering::Relaxed);
	}
}

/// Hands the server the [`StreamHandle`] of the request stream `h3` accepted last. `h3` accepts
/// one request stream per call to `accept`, so the handle is taken right after `accept` returns.
#[derive(Clone, Default)]
pub(super) struct StreamRegistry(Arc<Mutex<Option<StreamHandle>>>);

impl StreamRegistry {
	pub(super) fn take_accepted(&self) -> Option<StreamHandle> {
		self.0.lock().expect("stream registry poisoned").take()
	}

	fn accepted(&self, handle: StreamHandle) {
		*self.0.lock().expect("stream registry poisoned") = Some(handle);
	}
}

pub(super) struct Connection {
	conn: quinn::Connection,
	/// Serves the unidirectional streams and opens the server's own.
	inner: h3_quinn::Connection,
	incoming_bi: BoxStream<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>,
	streams: StreamRegistry,
}

impl Connection {
	pub(super) fn new(conn: quinn::Connection, streams: StreamRegistry) -> Self {
		Self {
			inner: h3_quinn::Connection::new(conn.clone()),
			incoming_bi: Box::pin(stream::unfold(conn.clone(), |conn| async {
				Some((conn.accept_bi().await, conn))
			})),
			conn,
			streams,
		}
	}
}

impl<B: Buf> quic::Connection<B> for Connection {
	type RecvStream = h3_quinn::RecvStream;
	type OpenStreams = OpenStreams;

	fn poll_accept_recv(
		&mut self,
		cx: &mut task::Context<'_>,
	) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
		<h3_quinn::Connection as quic::Connection<B>>::poll_accept_recv(&mut self.inner, cx)
	}

	fn poll_accept_bidi(
		&mut self,
		cx: &mut task::Context<'_>,
	) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
		let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
			.expect("the accept stream never ends")
			.map_err(convert_connection_error)?;
		let codes = Arc::new(StreamCodes::default());
		let send = SendStream::new(send, codes.clone(), &self.streams);
		Poll::Ready(Ok(BidiStream {
			send,
			recv: RecvStream::new(recv, codes),
		}))
	}

	fn opener(&self) -> Self::OpenStreams {
		OpenStreams {
			inner: <h3_quinn::Connection as quic::Connection<B>>::opener(&self.inner),
		}
	}
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
	type BidiStream = BidiStream<B>;
	type SendStream = h3_quinn::SendStream<B>;

	fn poll_open_bidi(
		&mut self,
		_cx: &mut task::Context<'_>,
	) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
		Poll::Ready(Err(server_opens_no_request_streams()))
	}

	fn poll_open_send(
		&mut self,
		cx: &mut task::Context<'_>,
	) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
		<h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_send(&mut self.inner, cx)
	}

	fn close(&mut self, code: Code, reason: &[u8]) {
		self.conn.close(varint(code), reason);
	}
}

pub(super) struct OpenStreams {
	inner: h3_quinn::OpenStreams,
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
	type BidiStream = BidiStream<B>;
	type SendStream = h3_quinn::SendStream<B>;

	fn poll_open_bidi(
		&mut self,
		_cx: &mut task::Context<'_>,
	) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
		Poll::Ready(Err(server_opens_no_request_streams()))
	}

	fn poll_open_send(
		&mut self,
		cx: &mut task::Context<'_>,
	) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
		self.inner.poll_open_send(cx)
	}

	fn close(&mut self, code: Code, reason: &[u8]) {
		<h3_quinn::OpenStreams as quic::OpenStreams<B>>::close(&mut self.inner, code, reason)
	}
}

/// Only clients open request streams (RFC 9114 section 6.1).
fn server_opens_no_request_streams() -> StreamErrorIncoming {
	StreamErrorIncoming::ConnectionErrorIncoming {
		connection_error: ConnectionErrorIncoming::InternalError(
			"an HTTP/3 server does not open request streams".to_string(),
		),
	}
}

/// A request stream.
pub(super) struct BidiStream<B: Buf> {
	send: SendStream<B>,
	recv: RecvStream,
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
	type SendStream = SendStream<B>;
	type RecvStream = RecvStream;

	fn split(self) -> (Self::SendStream, Self::RecvStream) {
		(self.send, self.recv)
	}
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
	type Buf = Bytes;

	fn poll_data(
		&mut self,
		cx: &mut task::Context<'_>,
	) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
		self.recv.poll_data(cx)
	}

	fn stop_sending(&mut self, error_code: u64) {
		self.recv.stop_sending(error_code)
	}

	fn recv_id(&self) -> StreamId {
		self.recv.recv_id()
	}
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
	fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.send.poll_ready(cx)
	}

	fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
		self.send.send_data(data)
	}

	fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.send.poll_finish(cx)
	}

	fn reset(&mut self, reset_code: u64) {
		self.send.reset(reset_code)
	}

	fn send_id(&self) -> StreamId {
		self.send.send_id()
	}
}

/// The receiving half of a request stream.
pub(super) struct RecvStream {
	// Owned outside of any read future, so that dropping the stream while a read is pending still
	// stops it with the intended error code.
	stream: quinn::RecvStream,
	id: StreamId,
	finished: bool,
	codes: Arc<StreamCodes>,
}

impl RecvStream {
	fn new(stream: quinn::RecvStream, codes: Arc<StreamCodes>) -> Self {
		Self {
			id: stream_id(stream.id()),
			stream,
			finished: false,
			codes,
		}
	}
}

impl quic::RecvStream for RecvStream {
	type Buf = Bytes;

	fn poll_data(
		&mut self,
		cx: &mut task::Context<'_>,
	) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
		// Reading a chunk is cancel-safe, so a pending read needs no state of its own.
		let read = std::pin::pin!(self.stream.read_chunk(usize::MAX, true));
		let chunk = ready!(read.poll(cx)).map_err(convert_read_error)?;
		if chunk.is_none() {
			self.finished = true;
		}
		Poll::Ready(Ok(chunk.map(|c| c.bytes)))
	}

	fn stop_sending(&mut self, error_code: u64) {
		let _ = self
			.stream
			.stop(VarInt::from_u64(error_code).unwrap_or(VarInt::MAX));
		self.finished = true;
	}

	fn recv_id(&self) -> StreamId {
		self.id
	}
}

impl Drop for RecvStream {
	fn drop(&mut self) {
		// Unless the request was rejected or cancelled, the response is complete without the rest
		// of the request: ask the client to stop sending it with H3_NO_ERROR (RFC 9114 section 4.1)
		// rather than quinn's default code 0.
		if !self.finished {
			let code = match self.codes.stop.load(Ordering::Relaxed) {
				0 => varint(Code::H3_NO_ERROR),
				code => VarInt::from_u64(code).unwrap_or(VarInt::MAX),
			};
			let _ = self.stream.stop(code);
		}
	}
}

/// The sending half of a request stream.
pub(super) struct SendStream<B: Buf> {
	stream: quinn::SendStream,
	writing: Option<WriteBuf<B>>,
	id: StreamId,
	/// Set once the stream was finished or reset.
	done: bool,
	/// When the reset code is non-zero, a stream dropped before being finished is reset with it.
	/// Otherwise it is finished, as `h3` expects for the error responses it sends itself (such as
	/// 431).
	codes: Arc<StreamCodes>,
}

impl<B: Buf> SendStream<B> {
	fn new(stream: quinn::SendStream, codes: Arc<StreamCodes>, streams: &StreamRegistry) -> Self {
		let id = stream_id(stream.id());
		let stopped = stream.stopped();
		streams.accepted(StreamHandle {
			stopped: Box::pin(async move {
				match stopped.await {
					Ok(code) => code,
					// The connection is gone; nobody reads the response anymore.
					Err(_) => Some(varint(Code::H3_REQUEST_CANCELLED)),
				}
			}),
			codes: codes.clone(),
		});
		Self {
			stream,
			writing: None,
			id,
			done: false,
			codes,
		}
	}
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
	fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		if let Some(data) = self.writing.as_mut() {
			while data.has_remaining() {
				let written = ready!(Pin::new(&mut self.stream).poll_write(cx, data.chunk()))
					.map_err(convert_write_error)?;
				data.advance(written);
			}
		}
		self.writing = None;
		Poll::Ready(Ok(()))
	}

	fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
		if self.writing.is_some() {
			return Err(StreamErrorIncoming::ConnectionErrorIncoming {
				connection_error: ConnectionErrorIncoming::InternalError(
					"send_data called while the stream is not ready".to_string(),
				),
			});
		}
		self.writing = Some(data.into());
		Ok(())
	}

	fn poll_finish(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
		self.done = true;
		Poll::Ready(
			self
				.stream
				.finish()
				.map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
		)
	}

	fn reset(&mut self, reset_code: u64) {
		self.done = true;
		let _ = self
			.stream
			.reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
	}

	fn send_id(&self) -> StreamId {
		self.id
	}
}

impl<B: Buf> Drop for SendStream<B> {
	fn drop(&mut self) {
		// quinn finishes a dropped stream, which would present a truncated response as complete.
		let code = self.codes.reset.load(Ordering::Relaxed);
		if !self.done && code != 0 {
			let _ = self
				.stream
				.reset(VarInt::from_u64(code).unwrap_or(VarInt::MAX));
		}
	}
}

fn varint(code: Code) -> VarInt {
	VarInt::from_u64(code.value()).unwrap_or(VarInt::MAX)
}

fn stream_id(id: quinn::StreamId) -> StreamId {
	let id: u64 = id.into();
	id.try_into().expect("QUIC stream ids are valid varints")
}

fn convert_connection_error(e: quinn::ConnectionError) -> ConnectionErrorIncoming {
	match e {
		quinn::ConnectionError::ApplicationClosed(close) => ConnectionErrorIncoming::ApplicationClose {
			error_code: close.error_code.into(),
		},
		quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
		error => ConnectionErrorIncoming::Undefined(Arc::new(error)),
	}
}

fn convert_read_error(e: quinn::ReadError) -> StreamErrorIncoming {
	match e {
		quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
			error_code: code.into_inner(),
		},
		quinn::ReadError::ConnectionLost(e) => StreamErrorIncoming::ConnectionErrorIncoming {
			connection_error: convert_connection_error(e),
		},
		error => StreamErrorIncoming::Unknown(Box::new(error)),
	}
}

fn convert_write_error(e: quinn::WriteError) -> StreamErrorIncoming {
	match e {
		quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
			error_code: code.into_inner(),
		},
		quinn::WriteError::ConnectionLost(e) => StreamErrorIncoming::ConnectionErrorIncoming {
			connection_error: convert_connection_error(e),
		},
		error => StreamErrorIncoming::Unknown(Box::new(error)),
	}
}
