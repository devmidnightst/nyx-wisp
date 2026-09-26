use wisp_core::CloseReason;

/// Errors from the handshake and from the multiplexer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // boxed because tungstenite's error is large enough to bloat every Result that carries it
    #[error(transparent)]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),
    #[error(transparent)]
    Wisp(#[from] wisp_core::WispError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("connection closed before the handshake completed")]
    ConnectionClosed,
    #[error("unexpected packet received during handshake")]
    UnexpectedHandshakePacket,
    #[error("authentication failed")]
    AuthFailed,
    #[error("peer rejected the connection: {0:?}")]
    Rejected(CloseReason),
    #[error("server requires authentication but no usable credentials were given")]
    MissingCredentials,
    #[error("username must be at most 255 bytes")]
    UsernameTooLong,
    #[error("the server does not support udp streams")]
    UdpNotSupported,
    #[error("stream closed by the server: {0:?}")]
    StreamClosed(CloseReason),
    #[error("the wisp connection has been closed")]
    MuxClosed,
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Error::WebSocket(Box::new(err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
