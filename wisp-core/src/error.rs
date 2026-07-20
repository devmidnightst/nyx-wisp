use thiserror::Error;

use crate::close::CloseReason;
use crate::packet::PacketType;

#[derive(Debug, Error)]
pub enum WispError {
    #[error("packet too short: need at least {needed} bytes, got {got}")]
    PacketTooShort { needed: usize, got: usize },

    #[error("unknown packet type: {0:#04x}")]
    UnknownPacketType(u8),

    #[error("unknown stream type: {0:#04x}")]
    UnknownStreamType(u8),

    #[error("invalid utf-8 in packet field")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("extension payload too short: need at least {needed} bytes, got {got}")]
    ExtensionPayloadTooShort { needed: usize, got: usize },

    #[error("extension payload length mismatch: header declared {declared} bytes, buffer has {available}")]
    ExtensionLengthMismatch { declared: u32, available: usize },

    #[error("stream id 0 is reserved for the handshake and cannot be used for a stream")]
    ReservedStreamId,

    #[error("unexpected {0:?} packet during handshake")]
    UnexpectedHandshakePacket(PacketType),

    #[error("send window exhausted, no buffer remaining for stream")]
    SendWindowExhausted,

    #[error("stream is closed")]
    StreamClosed,

    #[error("continue packet is not permitted on a udp stream")]
    ContinueOnUdpStream,

    #[error("handshake rejected by peer: {0:?}")]
    HandshakeRejected(CloseReason),
}

pub type Result<T> = std::result::Result<T, WispError>;
