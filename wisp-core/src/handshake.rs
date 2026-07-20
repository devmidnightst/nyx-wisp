use crate::close::CloseReason;
use crate::error::{Result, WispError};
use crate::frame::Frame;
use crate::packet::Packet;
use crate::version::WispVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHandshakeState {
    AwaitingServerInfo,
    AwaitingServerReply { peer_version: WispVersion },
    Established { peer_version: WispVersion, buffer_remaining: u32 },
    Rejected { reason: CloseReason },
    LegacyV1,
}

impl ClientHandshakeState {
    pub fn new() -> Self {
        ClientHandshakeState::AwaitingServerInfo
    }

    pub fn advance(self, frame: &Frame) -> Result<Self> {
        if frame.stream_id != 0 {
            return Err(WispError::ReservedStreamId);
        }
        match self {
            ClientHandshakeState::AwaitingServerInfo => match &frame.packet {
                Packet::Info { version, .. } => Ok(ClientHandshakeState::AwaitingServerReply {
                    peer_version: *version,
                }),
                Packet::Continue { .. } => Ok(ClientHandshakeState::LegacyV1),
                other => Err(WispError::UnexpectedHandshakePacket(other.packet_type())),
            },
            ClientHandshakeState::AwaitingServerReply { peer_version } => match &frame.packet {
                Packet::Continue { buffer_remaining } => Ok(ClientHandshakeState::Established {
                    peer_version,
                    buffer_remaining: *buffer_remaining,
                }),
                Packet::Close { reason } => Ok(ClientHandshakeState::Rejected { reason: *reason }),
                other => Err(WispError::UnexpectedHandshakePacket(other.packet_type())),
            },
            ClientHandshakeState::Established { .. }
            | ClientHandshakeState::Rejected { .. }
            | ClientHandshakeState::LegacyV1 => {
                Err(WispError::UnexpectedHandshakePacket(frame.packet.packet_type()))
            }
        }
    }
}

impl Default for ClientHandshakeState {
    fn default() -> Self {
        ClientHandshakeState::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHandshakeState {
    AwaitingClientInfo,
    Established { peer_version: WispVersion },
    Rejected { reason: CloseReason },
}

impl ServerHandshakeState {
    pub fn new() -> Self {
        ServerHandshakeState::AwaitingClientInfo
    }

    pub fn advance(self, frame: &Frame) -> Result<Self> {
        if frame.stream_id != 0 {
            return Err(WispError::ReservedStreamId);
        }
        match self {
            ServerHandshakeState::AwaitingClientInfo => match &frame.packet {
                Packet::Info { version, .. } => Ok(ServerHandshakeState::Established {
                    peer_version: *version,
                }),
                other => Err(WispError::UnexpectedHandshakePacket(other.packet_type())),
            },
            ServerHandshakeState::Established { .. } | ServerHandshakeState::Rejected { .. } => {
                Err(WispError::UnexpectedHandshakePacket(frame.packet.packet_type()))
            }
        }
    }

    pub fn reject(reason: CloseReason) -> Self {
        ServerHandshakeState::Rejected { reason }
    }
}

impl Default for ServerHandshakeState {
    fn default() -> Self {
        ServerHandshakeState::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension::ExtensionMeta;

    fn info_frame(version: WispVersion) -> Frame {
        Frame::new(
            0,
            Packet::Info {
                version,
                extensions: vec![ExtensionMeta::new(0x01, vec![])],
            },
        )
    }

    #[test]
    fn client_reaches_established_on_info_then_continue() {
        let state = ClientHandshakeState::new();
        let state = state.advance(&info_frame(WispVersion::V2)).unwrap();
        assert!(matches!(state, ClientHandshakeState::AwaitingServerReply { .. }));
        let state = state
            .advance(&Frame::new(0, Packet::Continue { buffer_remaining: 128 }))
            .unwrap();
        assert_eq!(
            state,
            ClientHandshakeState::Established {
                peer_version: WispVersion::V2,
                buffer_remaining: 128
            }
        );
    }

    #[test]
    fn client_reaches_rejected_on_close() {
        let state = ClientHandshakeState::new();
        let state = state.advance(&info_frame(WispVersion::V2)).unwrap();
        let state = state
            .advance(&Frame::new(
                0,
                Packet::Close {
                    reason: CloseReason::IncompatibleExtensions,
                },
            ))
            .unwrap();
        assert_eq!(
            state,
            ClientHandshakeState::Rejected {
                reason: CloseReason::IncompatibleExtensions
            }
        );
    }

    #[test]
    fn client_falls_back_to_legacy_v1_on_bare_continue() {
        let state = ClientHandshakeState::new();
        let state = state
            .advance(&Frame::new(0, Packet::Continue { buffer_remaining: 1 }))
            .unwrap();
        assert_eq!(state, ClientHandshakeState::LegacyV1);
    }

    #[test]
    fn client_rejects_nonzero_stream_id_during_handshake() {
        let state = ClientHandshakeState::new();
        let frame = Frame::new(3, Packet::Continue { buffer_remaining: 1 });
        assert!(matches!(state.advance(&frame), Err(WispError::ReservedStreamId)));
    }

    #[test]
    fn client_rejects_data_packet_while_awaiting_info() {
        let state = ClientHandshakeState::new();
        let frame = Frame::new(0, Packet::Data { payload: vec![] });
        assert!(state.advance(&frame).is_err());
    }

    #[test]
    fn established_state_rejects_further_handshake_frames() {
        let state = ClientHandshakeState::Established {
            peer_version: WispVersion::V2,
            buffer_remaining: 1,
        };
        let frame = Frame::new(0, Packet::Continue { buffer_remaining: 1 });
        assert!(state.advance(&frame).is_err());
    }

    #[test]
    fn server_reaches_established_on_client_info() {
        let state = ServerHandshakeState::new();
        let state = state.advance(&info_frame(WispVersion::V2)).unwrap();
        assert_eq!(
            state,
            ServerHandshakeState::Established {
                peer_version: WispVersion::V2
            }
        );
    }

    #[test]
    fn server_rejects_non_info_first_packet() {
        let state = ServerHandshakeState::new();
        let frame = Frame::new(0, Packet::Continue { buffer_remaining: 1 });
        assert!(state.advance(&frame).is_err());
    }
}
