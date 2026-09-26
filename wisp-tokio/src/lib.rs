//! Async Wisp v2 on top of tokio and tokio-tungstenite.
//!
//! [`server`] turns an accepted socket (plain TCP, TLS, anything `AsyncRead + AsyncWrite`) into a
//! Wisp server connection that proxies streams to real TCP/UDP sockets. [`client`] runs the client
//! side of the handshake over a websocket and hands out [`client::WispStream`]s that behave like
//! ordinary sockets.

pub mod client;
mod error;
pub mod server;
mod ws;

pub use error::{Error, Result};

/// The value this crate sends in `Sec-WebSocket-Protocol`. The spec only requires the header to
/// be present; its value is unspecified.
pub const WISP_SUBPROTOCOL: &str = "wisp-v2";
