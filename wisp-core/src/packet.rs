use crate::close::CloseReason;
use crate::error::{Result, WispError};
use crate::extension::ExtensionMeta;
use crate::stream_type::StreamType;
use crate::version::WispVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect,
    Data,
    Continue,
    Close,
    Info,
}

impl PacketType {
    pub fn as_u8(self) -> u8 {
        match self {
            PacketType::Connect => 0x01,
            PacketType::Data => 0x02,
            PacketType::Continue => 0x03,
            PacketType::Close => 0x04,
            PacketType::Info => 0x05,
        }
    }
}

impl TryFrom<u8> for PacketType {
    type Error = WispError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(PacketType::Connect),
            0x02 => Ok(PacketType::Data),
            0x03 => Ok(PacketType::Continue),
            0x04 => Ok(PacketType::Close),
            0x05 => Ok(PacketType::Info),
            other => Err(WispError::UnknownPacketType(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect {
        stream_type: StreamType,
        destination_port: u16,
        destination_hostname: String,
    },
    Data {
        payload: Vec<u8>,
    },
    Continue {
        buffer_remaining: u32,
    },
    Close {
        reason: CloseReason,
    },
    Info {
        version: WispVersion,
        extensions: Vec<ExtensionMeta>,
    },
}

impl Packet {
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::Connect { .. } => PacketType::Connect,
            Packet::Data { .. } => PacketType::Data,
            Packet::Continue { .. } => PacketType::Continue,
            Packet::Close { .. } => PacketType::Close,
            Packet::Info { .. } => PacketType::Info,
        }
    }

    pub(crate) fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            Packet::Connect {
                stream_type,
                destination_port,
                destination_hostname,
            } => {
                out.push(stream_type.as_u8());
                out.extend_from_slice(&destination_port.to_le_bytes());
                out.extend_from_slice(destination_hostname.as_bytes());
            }
            Packet::Data { payload } => {
                out.extend_from_slice(payload);
            }
            Packet::Continue { buffer_remaining } => {
                out.extend_from_slice(&buffer_remaining.to_le_bytes());
            }
            Packet::Close { reason } => {
                out.push(reason.as_u8());
            }
            Packet::Info { version, extensions } => {
                out.push(version.major);
                out.push(version.minor);
                for extension in extensions {
                    extension.encode(out);
                }
            }
        }
    }

    pub(crate) fn decode_payload(packet_type: PacketType, buf: &[u8]) -> Result<Packet> {
        match packet_type {
            PacketType::Connect => {
                if buf.len() < 3 {
                    return Err(WispError::PacketTooShort {
                        needed: 3,
                        got: buf.len(),
                    });
                }
                let stream_type = StreamType::try_from(buf[0])?;
                let destination_port = u16::from_le_bytes([buf[1], buf[2]]);
                let destination_hostname = std::str::from_utf8(&buf[3..])?.to_string();
                Ok(Packet::Connect {
                    stream_type,
                    destination_port,
                    destination_hostname,
                })
            }
            PacketType::Data => Ok(Packet::Data { payload: buf.to_vec() }),
            PacketType::Continue => {
                if buf.len() < 4 {
                    return Err(WispError::PacketTooShort {
                        needed: 4,
                        got: buf.len(),
                    });
                }
                let buffer_remaining = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                Ok(Packet::Continue { buffer_remaining })
            }
            PacketType::Close => {
                if buf.is_empty() {
                    return Err(WispError::PacketTooShort { needed: 1, got: 0 });
                }
                Ok(Packet::Close {
                    reason: CloseReason::from(buf[0]),
                })
            }
            PacketType::Info => {
                if buf.len() < 2 {
                    return Err(WispError::PacketTooShort {
                        needed: 2,
                        got: buf.len(),
                    });
                }
                let version = WispVersion {
                    major: buf[0],
                    minor: buf[1],
                };
                let extensions = ExtensionMeta::decode_all(&buf[2..])?;
                Ok(Packet::Info { version, extensions })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_type_wire_values() {
        assert_eq!(PacketType::Connect.as_u8(), 0x01);
        assert_eq!(PacketType::Data.as_u8(), 0x02);
        assert_eq!(PacketType::Continue.as_u8(), 0x03);
        assert_eq!(PacketType::Close.as_u8(), 0x04);
        assert_eq!(PacketType::Info.as_u8(), 0x05);
    }

    #[test]
    fn packet_type_round_trip() {
        for value in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            let ty = PacketType::try_from(value).unwrap();
            assert_eq!(ty.as_u8(), value);
        }
        assert!(PacketType::try_from(0x06).is_err());
    }

    #[test]
    fn connect_payload_layout() {
        let packet = Packet::Connect {
            stream_type: StreamType::Tcp,
            destination_port: 443,
            destination_hostname: "example.com".to_string(),
        };
        let mut buf = Vec::new();
        packet.encode_payload(&mut buf);
        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..3], &443u16.to_le_bytes());
        assert_eq!(&buf[3..], b"example.com");
        let decoded = Packet::decode_payload(PacketType::Connect, &buf).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn data_payload_is_passthrough() {
        let packet = Packet::Data {
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buf = Vec::new();
        packet.encode_payload(&mut buf);
        assert_eq!(buf, vec![1, 2, 3, 4, 5]);
        let decoded = Packet::decode_payload(PacketType::Data, &buf).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn continue_payload_layout() {
        let packet = Packet::Continue { buffer_remaining: 128 };
        let mut buf = Vec::new();
        packet.encode_payload(&mut buf);
        assert_eq!(buf, 128u32.to_le_bytes());
        let decoded = Packet::decode_payload(PacketType::Continue, &buf).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn close_payload_layout() {
        let packet = Packet::Close {
            reason: CloseReason::Voluntary,
        };
        let mut buf = Vec::new();
        packet.encode_payload(&mut buf);
        assert_eq!(buf, vec![0x02]);
        let decoded = Packet::decode_payload(PacketType::Close, &buf).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn info_payload_layout() {
        let packet = Packet::Info {
            version: WispVersion { major: 2, minor: 1 },
            extensions: vec![ExtensionMeta::new(0x01, vec![])],
        };
        let mut buf = Vec::new();
        packet.encode_payload(&mut buf);
        assert_eq!(buf[0], 2);
        assert_eq!(buf[1], 1);
        assert_eq!(&buf[2..], &[0x01, 0, 0, 0, 0]);
        let decoded = Packet::decode_payload(PacketType::Info, &buf).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn connect_rejects_short_payload() {
        assert!(Packet::decode_payload(PacketType::Connect, &[0x01, 0x00]).is_err());
    }

    #[test]
    fn continue_rejects_short_payload() {
        assert!(Packet::decode_payload(PacketType::Continue, &[0x00, 0x00]).is_err());
    }

    #[test]
    fn close_rejects_empty_payload() {
        assert!(Packet::decode_payload(PacketType::Close, &[]).is_err());
    }
}
