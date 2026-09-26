//! The client side: run the handshake over a websocket, then open streams that behave like
//! sockets.
//!
//! ```no_run
//! # async fn example() -> wisp_tokio::Result<()> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use wisp_tokio::client::{self, ClientConfig, ClientMux};
//!
//! let (ws, _) = tokio_tungstenite::connect_async(client::request("ws://127.0.0.1:9000/")?).await?;
//! let mux = ClientMux::new(ws, ClientConfig::default()).await?;
//! let mut stream = mux.open_tcp("example.com", 80).await?;
//! stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
//! let mut response = Vec::new();
//! stream.read_to_end(&mut response).await?;
//! # Ok(())
//! # }
//! ```

mod driver;
mod handshake;
mod stream;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::WebSocketStream;

use wisp_core::{CloseReason, Frame, Packet, StreamType, WispVersion};

use crate::error::{Error, Result};

pub use stream::WispStream;

use driver::{Command, FlowState, StreamSlot};

/// Frames queued for the websocket before `open` and stream writes start waiting.
const OUTBOUND_CAPACITY: usize = 256;

/// Username/password credentials for the password auth extension.
#[derive(Debug, Clone)]
pub struct PasswordCredentials {
    pub username: String,
    pub password: String,
}

/// An ed25519 key for the key auth extension.
#[derive(Debug, Clone)]
pub struct KeyCredentials {
    pub username: String,
    pub signing_key: SigningKey,
}

/// What the client advertises and which credentials it may send. Credentials are only sent when
/// the server offers the matching auth method.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub password: Option<PasswordCredentials>,
    pub key: Option<KeyCredentials>,
    /// Advertise UDP support.
    pub udp: bool,
    /// Advertise the stream open confirmation extension. When the server supports it too,
    /// [`ClientMux::open`] waits until the server has actually connected the TCP socket, and fails
    /// with the server's close reason if it could not.
    pub stream_confirmation: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            password: None,
            key: None,
            udp: true,
            stream_confirmation: true,
        }
    }
}

/// What the handshake learned about the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The version from the server's INFO packet.
    pub version: WispVersion,
    /// The per-stream buffer size from the server's CONTINUE on stream 0.
    pub buffer_size: u32,
    pub motd: Option<String>,
    /// Both sides support UDP.
    pub udp: bool,
    /// Both sides support stream open confirmation.
    pub stream_confirmation: bool,
    /// Every extension id the server advertised, including ones this crate does not know.
    pub extensions: Vec<u8>,
}

/// Builds a websocket request for `url` with the `Sec-WebSocket-Protocol` header the spec needs
/// for v2.
#[allow(clippy::result_large_err)]
pub fn request(url: &str) -> Result<Request> {
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(crate::WISP_SUBPROTOCOL),
    );
    Ok(request)
}

pub(crate) struct Shared {
    pub(crate) streams: Mutex<HashMap<u32, StreamSlot>>,
    pub(crate) closed: AtomicBool,
    next_token: AtomicU64,
}

impl Shared {
    /// Removes the stream only if the slot still belongs to the stream holding `token`: after the
    /// server closes a stream its id can be handed out again. Returns whether it was removed.
    pub(crate) fn remove_stream(&self, stream_id: u32, token: u64) -> bool {
        let mut streams = self.streams.lock().unwrap();
        if streams.get(&stream_id).is_some_and(|slot| slot.token == token) {
            streams.remove(&stream_id);
            true
        } else {
            false
        }
    }
}

/// A client wisp connection. Cheap to clone; every clone opens streams on the same websocket.
/// The connection stays up while any clone or stream is alive, and is closed by [`close`].
///
/// [`close`]: ClientMux::close
#[derive(Clone)]
pub struct ClientMux {
    info: Arc<ServerInfo>,
    shared: Arc<Shared>,
    out_tx: mpsc::Sender<Command>,
    ctrl_tx: mpsc::UnboundedSender<Command>,
}

impl ClientMux {
    /// Runs the handshake on `ws` and starts a background task that drives the connection.
    pub async fn new<S>(mut ws: WebSocketStream<S>, config: ClientConfig) -> Result<ClientMux>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let info = handshake::perform(&mut ws, &config).await?;
        let shared = Arc::new(Shared {
            streams: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            next_token: AtomicU64::new(0),
        });
        let (out_tx, out_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        tokio::spawn(driver::run(ws, shared.clone(), out_rx, ctrl_rx));
        Ok(ClientMux {
            info: Arc::new(info),
            shared,
            out_tx,
            ctrl_tx,
        })
    }

    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Whether the underlying websocket has closed.
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Number of streams currently open on this connection.
    pub fn stream_count(&self) -> usize {
        self.shared.streams.lock().unwrap().len()
    }

    pub async fn open_tcp(&self, host: impl Into<String>, port: u16) -> Result<WispStream> {
        self.open(StreamType::Tcp, host, port).await
    }

    pub async fn open_udp(&self, host: impl Into<String>, port: u16) -> Result<WispStream> {
        self.open(StreamType::Udp, host, port).await
    }

    /// Opens a stream to `host:port`. With stream open confirmation negotiated, TCP streams only
    /// return once the server has connected, and a failed connect comes back as
    /// [`Error::StreamClosed`] carrying the server's reason. Otherwise the stream is returned
    /// immediately and a failed connect shows up on the first read or write.
    pub async fn open(&self, stream_type: StreamType, host: impl Into<String>, port: u16) -> Result<WispStream> {
        if self.is_closed() {
            return Err(Error::MuxClosed);
        }
        if stream_type == StreamType::Udp && !self.info.udp {
            return Err(Error::UdpNotSupported);
        }

        let wait_for_confirmation = stream_type == StreamType::Tcp && self.info.stream_confirmation;
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let flow = Arc::new(FlowState::new(match stream_type {
            StreamType::Tcp => Some(self.info.buffer_size),
            // udp streams are not flow controlled
            StreamType::Udp => None,
        }));
        let (confirm_tx, confirm_rx) = if wait_for_confirmation {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let token = self.shared.next_token.fetch_add(1, Ordering::Relaxed);
        let stream_id = {
            let mut streams = self.shared.streams.lock().unwrap();
            let stream_id = loop {
                let candidate: u32 = rand::thread_rng().gen();
                if candidate != 0 && !streams.contains_key(&candidate) {
                    break candidate;
                }
            };
            streams.insert(
                stream_id,
                StreamSlot {
                    token,
                    events: events_tx,
                    flow: flow.clone(),
                    confirm: confirm_tx,
                },
            );
            stream_id
        };

        let connect = Frame::new(
            stream_id,
            Packet::Connect {
                stream_type,
                destination_port: port,
                destination_hostname: host.into(),
            },
        );
        if self.out_tx.send(Command::Frame(connect)).await.is_err() {
            self.shared.remove_stream(stream_id, token);
            return Err(Error::MuxClosed);
        }

        let stream = WispStream::new(
            stream_id,
            token,
            stream_type,
            events_rx,
            flow,
            self.out_tx.clone(),
            self.ctrl_tx.clone(),
            self.shared.clone(),
        );

        if let Some(confirm_rx) = confirm_rx {
            match confirm_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => return Err(Error::StreamClosed(reason)),
                Err(_) => return Err(Error::MuxClosed),
            }
        }

        Ok(stream)
    }

    /// Closes the websocket. Open streams see the connection end on their next read or write.
    pub fn close(&self) {
        let _ = self.ctrl_tx.send(Command::Shutdown);
    }
}

/// How a close reason from the server surfaces through `AsyncRead`/`AsyncWrite`.
pub(crate) fn close_reason_error(reason: CloseReason) -> std::io::Error {
    use std::io::ErrorKind;
    let kind = match reason {
        CloseReason::ConnectionRefused => ErrorKind::ConnectionRefused,
        CloseReason::ConnectionTimedOut | CloseReason::TcpTimedOut => ErrorKind::TimedOut,
        CloseReason::Blocked | CloseReason::AuthRequired => ErrorKind::PermissionDenied,
        CloseReason::InvalidInfo => ErrorKind::InvalidInput,
        CloseReason::HostUnreachable => ErrorKind::NotFound,
        _ => ErrorKind::ConnectionReset,
    };
    std::io::Error::new(kind, Error::StreamClosed(reason))
}

impl std::fmt::Debug for ClientMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientMux")
            .field("info", &self.info)
            .field("closed", &self.is_closed())
            .field("streams", &self.stream_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_carries_the_wisp_subprotocol() {
        let request = request("ws://127.0.0.1:9000/").unwrap();
        assert_eq!(
            request.headers().get("sec-websocket-protocol").unwrap(),
            crate::WISP_SUBPROTOCOL
        );
    }

    #[test]
    fn request_rejects_non_websocket_urls() {
        assert!(request("not a url").is_err());
    }

    #[test]
    fn close_reasons_map_to_io_error_kinds() {
        use std::io::ErrorKind;
        assert_eq!(
            close_reason_error(CloseReason::ConnectionRefused).kind(),
            ErrorKind::ConnectionRefused
        );
        assert_eq!(close_reason_error(CloseReason::ConnectionTimedOut).kind(), ErrorKind::TimedOut);
        assert_eq!(close_reason_error(CloseReason::Blocked).kind(), ErrorKind::PermissionDenied);
        assert_eq!(close_reason_error(CloseReason::NetworkError).kind(), ErrorKind::ConnectionReset);
    }
}
