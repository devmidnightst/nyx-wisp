use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use wisp_core::{CloseReason, Frame, Packet, StreamType};

use super::driver::{Command, FlowState, StreamEvent, Window};
use super::{close_reason_error, Shared};
use crate::error::{Error, Result};

/// Largest DATA payload a single `poll_write` sends. Bigger writes are split across packets.
pub const MAX_DATA_PAYLOAD: usize = 64 * 1024;

/// One wisp stream. Implements `AsyncRead` and `AsyncWrite` like a socket, and also exposes
/// packet level [`send_packet`](WispStream::send_packet) and [`recv_packet`](WispStream::recv_packet),
/// which keep datagram boundaries on UDP streams.
///
/// TCP writes respect the server's CONTINUE window and wait when it is used up. Shutting down
/// the write side or dropping the stream sends CLOSE, since wisp has no half-close.
pub struct WispStream {
    stream_id: u32,
    token: u64,
    stream_type: StreamType,
    events: mpsc::UnboundedReceiver<StreamEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_state: ReadState,
    flow: Arc<FlowState>,
    sender: PollSender<Command>,
    ctrl_tx: mpsc::UnboundedSender<Command>,
    shared: Arc<Shared>,
    locally_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Open,
    /// The server closed the stream.
    Closed(CloseReason),
    ConnectionLost,
}

impl WispStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stream_id: u32,
        token: u64,
        stream_type: StreamType,
        events: mpsc::UnboundedReceiver<StreamEvent>,
        flow: Arc<FlowState>,
        out_tx: mpsc::Sender<Command>,
        ctrl_tx: mpsc::UnboundedSender<Command>,
        shared: Arc<Shared>,
    ) -> Self {
        WispStream {
            stream_id,
            token,
            stream_type,
            events,
            read_buf: Vec::new(),
            read_pos: 0,
            read_state: ReadState::Open,
            flow,
            sender: PollSender::new(out_tx),
            ctrl_tx,
            shared,
            locally_closed: false,
        }
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    /// Packets this stream may still send before it has to wait for a CONTINUE. `None` for UDP.
    pub fn send_window(&self) -> Option<u32> {
        self.flow.remaining()
    }

    /// The reason the server closed this stream, once it has.
    pub fn close_reason(&self) -> Option<CloseReason> {
        match self.read_state {
            ReadState::Closed(reason) => Some(reason),
            _ => None,
        }
    }

    /// Sends `payload` as exactly one DATA packet, waiting for window space on TCP streams.
    pub async fn send_packet(&mut self, payload: &[u8]) -> Result<()> {
        std::future::poll_fn(|cx| self.poll_send_data(cx, payload, usize::MAX)).await?;
        Ok(())
    }

    /// The next DATA payload from the server, bypassing the `AsyncRead` buffer. `Ok(None)` once
    /// the server closed the stream voluntarily.
    pub async fn recv_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if self.read_pos < self.read_buf.len() {
            let rest = self.read_buf.split_off(self.read_pos);
            self.read_buf.clear();
            self.read_pos = 0;
            return Ok(Some(rest));
        }
        match self.read_state {
            ReadState::Open => {}
            ReadState::Closed(CloseReason::Voluntary) => return Ok(None),
            ReadState::Closed(reason) => return Err(Error::StreamClosed(reason)),
            ReadState::ConnectionLost => return Err(Error::MuxClosed),
        }
        match self.events.recv().await {
            Some(StreamEvent::Data(payload)) => Ok(Some(payload)),
            Some(StreamEvent::Closed(reason)) => {
                self.read_state = ReadState::Closed(reason);
                if reason == CloseReason::Voluntary {
                    Ok(None)
                } else {
                    Err(Error::StreamClosed(reason))
                }
            }
            Some(StreamEvent::ConnectionLost) | None => {
                self.read_state = ReadState::ConnectionLost;
                Err(Error::MuxClosed)
            }
        }
    }

    /// Closes the stream with `reason`. Later writes fail; reads still return anything the server
    /// had already sent.
    pub async fn close(&mut self, reason: CloseReason) -> Result<()> {
        std::future::poll_fn(|cx| self.poll_close_with(cx, reason)).await?;
        Ok(())
    }

    fn write_error(&self) -> io::Error {
        match self.read_state {
            ReadState::Closed(reason) => close_reason_error(reason),
            ReadState::ConnectionLost => io::Error::new(io::ErrorKind::ConnectionAborted, Error::MuxClosed),
            ReadState::Open => io::Error::new(io::ErrorKind::BrokenPipe, "wisp stream is closed"),
        }
    }

    fn poll_send_data(&mut self, cx: &mut Context<'_>, buf: &[u8], max_len: usize) -> Poll<io::Result<usize>> {
        if self.locally_closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "wisp stream is closed")));
        }
        match self.flow.check(cx.waker()) {
            Window::Open => {}
            Window::Exhausted => return Poll::Pending,
            Window::Closed => {
                // pull the close reason off the event queue so the error says why
                self.drain_close_event();
                return Poll::Ready(Err(self.write_error()));
            }
        }
        if ready!(self.sender.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, Error::MuxClosed)));
        }
        let len = buf.len().min(max_len);
        let frame = Frame::new(
            self.stream_id,
            Packet::Data {
                payload: buf[..len].to_vec(),
            },
        );
        if self.sender.send_item(Command::Frame(frame)).is_err() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, Error::MuxClosed)));
        }
        self.flow.consume();
        Poll::Ready(Ok(len))
    }

    /// Looks for a pending close without waiting, buffering any data found on the way.
    fn drain_close_event(&mut self) {
        while self.read_state == ReadState::Open {
            match self.events.try_recv() {
                Ok(StreamEvent::Data(payload)) => {
                    if self.read_pos >= self.read_buf.len() {
                        self.read_buf = payload;
                        self.read_pos = 0;
                    } else {
                        self.read_buf.extend_from_slice(&payload);
                    }
                }
                Ok(StreamEvent::Closed(reason)) => self.read_state = ReadState::Closed(reason),
                Ok(StreamEvent::ConnectionLost) => self.read_state = ReadState::ConnectionLost,
                Err(_) => break,
            }
        }
    }

    fn poll_close_with(&mut self, cx: &mut Context<'_>, reason: CloseReason) -> Poll<io::Result<()>> {
        if self.locally_closed {
            return Poll::Ready(Ok(()));
        }
        // nothing to tell the server if it already closed the stream
        if !self.shared.remove_stream(self.stream_id, self.token) {
            self.locally_closed = true;
            return Poll::Ready(Ok(()));
        }
        if ready!(self.sender.poll_reserve(cx)).is_ok() {
            let close = Frame::new(self.stream_id, Packet::Close { reason });
            let _ = self.sender.send_item(Command::Frame(close));
        }
        self.locally_closed = true;
        self.flow.close();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for WispStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.read_pos < this.read_buf.len() {
                let available = &this.read_buf[this.read_pos..];
                let len = available.len().min(buf.remaining());
                buf.put_slice(&available[..len]);
                this.read_pos += len;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match this.read_state {
                ReadState::Open => {}
                // the upstream socket reached EOF
                ReadState::Closed(CloseReason::Voluntary) => return Poll::Ready(Ok(())),
                ReadState::Closed(reason) => return Poll::Ready(Err(close_reason_error(reason))),
                ReadState::ConnectionLost => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, Error::MuxClosed)))
                }
            }

            match ready!(this.events.poll_recv(cx)) {
                Some(StreamEvent::Data(payload)) => {
                    this.read_buf = payload;
                    this.read_pos = 0;
                }
                Some(StreamEvent::Closed(reason)) => this.read_state = ReadState::Closed(reason),
                Some(StreamEvent::ConnectionLost) | None => this.read_state = ReadState::ConnectionLost,
            }
        }
    }
}

impl AsyncWrite for WispStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.poll_send_data(cx, buf, MAX_DATA_PAYLOAD)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // frames are handed to the connection task as soon as they are written
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_close_with(cx, CloseReason::Voluntary)
    }
}

impl Drop for WispStream {
    fn drop(&mut self) {
        if self.locally_closed {
            return;
        }
        if self.shared.remove_stream(self.stream_id, self.token) {
            let close = Frame::new(
                self.stream_id,
                Packet::Close {
                    reason: CloseReason::Voluntary,
                },
            );
            // the ordered data queue keeps the CLOSE behind anything already written; only fall
            // back to the control queue when that is full, since drop cannot wait
            let queued = self
                .sender
                .get_ref()
                .is_some_and(|sender| sender.try_send(Command::Frame(close.clone())).is_ok());
            if !queued {
                let _ = self.ctrl_tx.send(Command::Frame(close));
            }
        }
    }
}

impl std::fmt::Debug for WispStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WispStream")
            .field("stream_id", &self.stream_id)
            .field("stream_type", &self.stream_type)
            .field("send_window", &self.send_window())
            .field("read_state", &self.read_state)
            .finish()
    }
}
