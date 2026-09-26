//! The server side: websocket upgrade, the v2 (or v1) handshake, and the stream multiplexer that
//! proxies each wisp stream to a real TCP or UDP socket.

mod auth;
mod handshake;
mod mux;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::WebSocketStream;

use wisp_core::{Frame, Packet};

use crate::error::Result;
use crate::ws;

pub use auth::{KeyAuth, PasswordAuth};

/// How a server treats the connections it accepts.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Packets each TCP stream may buffer, sent to clients in CONTINUE. Values below 1 are
    /// treated as 1, since a zero sized buffer would never let a client send anything.
    pub buffer_size: u32,
    pub password_auth: Option<PasswordAuth>,
    pub key_auth: Option<KeyAuth>,
    /// Sent to v2 clients through the MOTD extension (0x04).
    pub motd: Option<String>,
    /// Whether UDP streams are allowed. When false the UDP extension is not advertised and UDP
    /// CONNECTs are closed with 0x41.
    pub udp: bool,
    /// Whether to offer the stream open confirmation extension (0x05). When the client also
    /// supports it, every TCP stream gets a CONTINUE once its upstream socket is connected.
    pub stream_confirmation: bool,
    /// How long to wait for an upstream TCP connect before closing the stream with 0x43.
    pub connect_timeout: Duration,
    /// How long a client may take to send its INFO packet before the connection is dropped.
    pub handshake_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            buffer_size: 128,
            password_auth: None,
            key_auth: None,
            motd: None,
            udp: true,
            stream_confirmation: true,
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl ServerConfig {
    fn effective_buffer_size(&self) -> u32 {
        self.buffer_size.max(1)
    }

    fn auth_required(&self) -> bool {
        self.password_auth.as_ref().is_some_and(|auth| auth.required)
            || self.key_auth.as_ref().is_some_and(|auth| auth.required)
    }
}

/// Settings the multiplexer runs with once a handshake has finished.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MuxOptions {
    pub buffer_size: u32,
    pub udp: bool,
    pub stream_confirmation: bool,
    pub connect_timeout: Duration,
}

/// Upgrades `stream` to a websocket and serves wisp on it until the connection ends.
///
/// Clients that send a `Sec-WebSocket-Protocol` header get Wisp v2 and the first subprotocol they
/// offered is echoed back, as websocket clients require. Clients without the header get Wisp v1,
/// as the spec requires, unless some auth method is required, since v1 cannot authenticate.
#[allow(clippy::result_large_err)]
pub async fn accept<S>(stream: S, config: Arc<ServerConfig>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let has_protocol_header = Arc::new(AtomicBool::new(false));
    let flag = has_protocol_header.clone();
    let ws = tokio_tungstenite::accept_hdr_async(stream, move |req: &Request, mut resp: Response| {
        if let Some(requested) = req.headers().get("sec-websocket-protocol") {
            flag.store(true, Ordering::SeqCst);
            if let Some(first) = first_subprotocol(requested) {
                resp.headers_mut().insert("sec-websocket-protocol", first);
            }
        }
        Ok(resp)
    })
    .await?;

    if has_protocol_header.load(Ordering::SeqCst) {
        serve_v2(ws, &config).await
    } else {
        serve_v1(ws, &config).await
    }
}

fn first_subprotocol(requested: &HeaderValue) -> Option<HeaderValue> {
    requested
        .to_str()
        .ok()
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| HeaderValue::from_str(value).ok())
}

/// Runs the v2 handshake on an already upgraded websocket, then serves streams on it.
pub async fn serve_v2<S>(mut ws: WebSocketStream<S>, config: &ServerConfig) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let negotiated = handshake::perform(&mut ws, config).await?;
    mux::run(
        ws,
        MuxOptions {
            buffer_size: config.effective_buffer_size(),
            udp: config.udp,
            stream_confirmation: negotiated.stream_confirmation,
            connect_timeout: config.connect_timeout,
        },
    )
    .await;
    Ok(())
}

/// Serves a Wisp v1 client: no INFO exchange, just the initial CONTINUE on stream 0. Refused when
/// any auth method is required.
pub async fn serve_v1<S>(mut ws: WebSocketStream<S>, config: &ServerConfig) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if config.auth_required() {
        let _ = ws.close(None).await;
        return Ok(());
    }
    let buffer_size = config.effective_buffer_size();
    ws::send_frame(
        &mut ws,
        &Frame::new(
            0,
            Packet::Continue {
                buffer_remaining: buffer_size,
            },
        ),
    )
    .await?;
    mux::run(
        ws,
        MuxOptions {
            buffer_size,
            udp: config.udp,
            stream_confirmation: false,
            connect_timeout: config.connect_timeout,
        },
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_subprotocol_picks_the_first_offer() {
        let value = HeaderValue::from_static("wisp-v2, something-else");
        assert_eq!(first_subprotocol(&value).unwrap(), "wisp-v2");
        let value = HeaderValue::from_static("  only ");
        assert_eq!(first_subprotocol(&value).unwrap(), "only");
        let value = HeaderValue::from_static("");
        assert!(first_subprotocol(&value).is_none());
    }

    #[test]
    fn buffer_size_is_at_least_one() {
        let config = ServerConfig {
            buffer_size: 0,
            ..ServerConfig::default()
        };
        assert_eq!(config.effective_buffer_size(), 1);
    }

    #[test]
    fn auth_required_looks_at_both_methods() {
        let mut config = ServerConfig::default();
        assert!(!config.auth_required());
        config.password_auth = Some(PasswordAuth {
            username: "u".into(),
            password: "p".into(),
            required: false,
        });
        assert!(!config.auth_required());
        config.key_auth = Some(KeyAuth {
            allowed_keys: vec![],
            required: true,
        });
        assert!(config.auth_required());
    }
}
