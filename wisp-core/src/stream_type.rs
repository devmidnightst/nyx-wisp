use crate::error::{Result, WispError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    Tcp,
    Udp,
}

impl StreamType {
    pub fn as_u8(self) -> u8 {
        match self {
            StreamType::Tcp => 0x01,
            StreamType::Udp => 0x02,
        }
    }
}

impl TryFrom<u8> for StreamType {
    type Error = WispError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(StreamType::Tcp),
            0x02 => Ok(StreamType::Udp),
            other => Err(WispError::UnknownStreamType(other)),
        }
    }
}
