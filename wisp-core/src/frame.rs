use crate::error::{Result, WispError};
use crate::packet::{Packet, PacketType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub stream_id: u32,
    pub packet: Packet,
}

impl Frame {
    pub fn new(stream_id: u32, packet: Packet) -> Self {
        Frame { stream_id, packet }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5);
        out.push(self.packet.packet_type().as_u8());
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        self.packet.encode_payload(&mut out);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Frame> {
        if buf.len() < 5 {
            return Err(WispError::PacketTooShort {
                needed: 5,
                got: buf.len(),
            });
        }
        let packet_type = PacketType::try_from(buf[0])?;
        let stream_id = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let packet = Packet::decode_payload(packet_type, &buf[5..])?;
        Ok(Frame { stream_id, packet })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::close::CloseReason;

    #[test]
    fn header_layout_is_type_then_le_stream_id() {
        let frame = Frame::new(
            0x11223344,
            Packet::Close {
                reason: CloseReason::Unspecified,
            },
        );
        let encoded = frame.encode();
        assert_eq!(encoded[0], 0x04);
        assert_eq!(&encoded[1..5], &0x11223344u32.to_le_bytes());
        assert_eq!(encoded[5], 0x01);
    }

    #[test]
    fn round_trip_every_packet_type() {
        let frames = vec![
            Frame::new(
                7,
                Packet::Connect {
                    stream_type: crate::stream_type::StreamType::Udp,
                    destination_port: 53,
                    destination_hostname: "dns.example".to_string(),
                },
            ),
            Frame::new(
                7,
                Packet::Data {
                    payload: b"payload bytes".to_vec(),
                },
            ),
            Frame::new(7, Packet::Continue { buffer_remaining: 42 }),
            Frame::new(
                7,
                Packet::Close {
                    reason: CloseReason::NetworkError,
                },
            ),
            Frame::new(
                0,
                Packet::Info {
                    version: crate::version::WispVersion::V2,
                    extensions: vec![],
                },
            ),
        ];
        for frame in frames {
            let encoded = frame.encode();
            let decoded = Frame::decode(&encoded).unwrap();
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn decode_rejects_truncated_header() {
        assert!(Frame::decode(&[0x02, 0, 0, 0]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_packet_type() {
        assert!(Frame::decode(&[0xff, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn stream_id_zero_is_representable() {
        let frame = Frame::new(0, Packet::Continue { buffer_remaining: 1 });
        let encoded = frame.encode();
        assert_eq!(&encoded[1..5], &[0, 0, 0, 0]);
    }
}
