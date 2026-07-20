use crate::close::CloseReason;
use crate::error::{Result, WispError};
use crate::packet::Packet;
use crate::stream_type::StreamType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    stream_type: StreamType,
    phase: StreamPhase,
    close_reason: Option<CloseReason>,
}

impl StreamState {
    pub fn new(stream_type: StreamType) -> Self {
        StreamState {
            stream_type,
            phase: StreamPhase::Open,
            close_reason: None,
        }
    }

    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    pub fn phase(&self) -> StreamPhase {
        self.phase
    }

    pub fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }

    pub fn is_open(&self) -> bool {
        self.phase == StreamPhase::Open
    }

    pub fn on_incoming(&mut self, packet: &Packet) -> Result<()> {
        if self.phase == StreamPhase::Closed {
            return Err(WispError::StreamClosed);
        }
        match packet {
            Packet::Data { .. } => Ok(()),
            Packet::Continue { .. } => {
                if self.stream_type == StreamType::Udp {
                    Err(WispError::ContinueOnUdpStream)
                } else {
                    Ok(())
                }
            }
            Packet::Close { reason } => {
                self.phase = StreamPhase::Closed;
                self.close_reason = Some(*reason);
                Ok(())
            }
            Packet::Connect { .. } | Packet::Info { .. } => {
                Err(WispError::UnexpectedHandshakePacket(packet.packet_type()))
            }
        }
    }

    pub fn close_locally(&mut self, reason: CloseReason) {
        self.phase = StreamPhase::Closed;
        self.close_reason = Some(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stream_starts_open() {
        let state = StreamState::new(StreamType::Tcp);
        assert!(state.is_open());
        assert_eq!(state.close_reason(), None);
    }

    #[test]
    fn data_keeps_stream_open() {
        let mut state = StreamState::new(StreamType::Tcp);
        state
            .on_incoming(&Packet::Data { payload: vec![1, 2, 3] })
            .unwrap();
        assert!(state.is_open());
    }

    #[test]
    fn continue_is_rejected_on_udp_stream() {
        let mut state = StreamState::new(StreamType::Udp);
        let result = state.on_incoming(&Packet::Continue { buffer_remaining: 1 });
        assert!(matches!(result, Err(WispError::ContinueOnUdpStream)));
    }

    #[test]
    fn continue_is_accepted_on_tcp_stream() {
        let mut state = StreamState::new(StreamType::Tcp);
        state
            .on_incoming(&Packet::Continue { buffer_remaining: 1 })
            .unwrap();
        assert!(state.is_open());
    }

    #[test]
    fn close_transitions_to_closed_with_reason() {
        let mut state = StreamState::new(StreamType::Tcp);
        state
            .on_incoming(&Packet::Close {
                reason: CloseReason::Voluntary,
            })
            .unwrap();
        assert!(!state.is_open());
        assert_eq!(state.close_reason(), Some(CloseReason::Voluntary));
    }

    #[test]
    fn packets_after_close_are_rejected() {
        let mut state = StreamState::new(StreamType::Tcp);
        state.close_locally(CloseReason::NetworkError);
        let result = state.on_incoming(&Packet::Data { payload: vec![] });
        assert!(matches!(result, Err(WispError::StreamClosed)));
    }

    #[test]
    fn connect_packet_is_never_valid_mid_stream() {
        let mut state = StreamState::new(StreamType::Tcp);
        let result = state.on_incoming(&Packet::Connect {
            stream_type: StreamType::Tcp,
            destination_port: 80,
            destination_hostname: "x".to_string(),
        });
        assert!(result.is_err());
    }
}
