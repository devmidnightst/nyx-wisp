use crate::error::{Result, WispError};

pub mod extension_id {
    pub const UDP: u8 = 0x01;
    pub const PASSWORD_AUTH: u8 = 0x02;
    pub const KEY_AUTH: u8 = 0x03;
    pub const MOTD: u8 = 0x04;
    pub const STREAM_OPEN_CONFIRMATION: u8 = 0x05;
}

pub const SIGNATURE_ALGORITHM_ED25519: u8 = 0b0000_0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionMeta {
    pub id: u8,
    pub data: Vec<u8>,
}

impl ExtensionMeta {
    pub fn new(id: u8, data: Vec<u8>) -> Self {
        ExtensionMeta { id, data }
    }

    pub fn encoded_len(&self) -> usize {
        1 + 4 + self.data.len()
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.id);
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
    }

    pub fn decode(buf: &[u8]) -> Result<(ExtensionMeta, &[u8])> {
        if buf.len() < 5 {
            return Err(WispError::ExtensionPayloadTooShort {
                needed: 5,
                got: buf.len(),
            });
        }
        let id = buf[0];
        let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let rest = &buf[5..];
        if rest.len() < len {
            return Err(WispError::ExtensionLengthMismatch {
                declared: len as u32,
                available: rest.len(),
            });
        }
        let data = rest[..len].to_vec();
        Ok((ExtensionMeta { id, data }, &rest[len..]))
    }

    pub fn decode_all(mut buf: &[u8]) -> Result<Vec<ExtensionMeta>> {
        let mut metas = Vec::new();
        while !buf.is_empty() {
            let (meta, rest) = ExtensionMeta::decode(buf)?;
            metas.push(meta);
            buf = rest;
        }
        Ok(metas)
    }

    pub fn encode_all(metas: &[ExtensionMeta]) -> Vec<u8> {
        let mut out = Vec::with_capacity(metas.iter().map(ExtensionMeta::encoded_len).sum());
        for meta in metas {
            meta.encode(&mut out);
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordAuthServer {
    pub required: bool,
}

impl PasswordAuthServer {
    pub fn encode(&self) -> Vec<u8> {
        vec![self.required as u8]
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let byte = *buf.first().ok_or(WispError::ExtensionPayloadTooShort {
            needed: 1,
            got: buf.len(),
        })?;
        Ok(PasswordAuthServer { required: byte != 0 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAuthClient {
    pub username: String,
    pub password: String,
}

impl PasswordAuthClient {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.username.len() + self.password.len());
        out.push(self.username.len() as u8);
        out.extend_from_slice(self.username.as_bytes());
        out.extend_from_slice(self.password.as_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let username_len = *buf.first().ok_or(WispError::ExtensionPayloadTooShort {
            needed: 1,
            got: buf.len(),
        })? as usize;
        if buf.len() < 1 + username_len {
            return Err(WispError::ExtensionPayloadTooShort {
                needed: 1 + username_len,
                got: buf.len(),
            });
        }
        let username = std::str::from_utf8(&buf[1..1 + username_len])?.to_string();
        let password = std::str::from_utf8(&buf[1 + username_len..])?.to_string();
        Ok(PasswordAuthClient { username, password })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthServer {
    pub required: bool,
    pub supported_algorithms: u8,
    pub challenge: Vec<u8>,
}

impl KeyAuthServer {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.challenge.len());
        out.push(self.required as u8);
        out.push(self.supported_algorithms);
        out.extend_from_slice(&self.challenge);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(WispError::ExtensionPayloadTooShort {
                needed: 2,
                got: buf.len(),
            });
        }
        Ok(KeyAuthServer {
            required: buf[0] != 0,
            supported_algorithms: buf[1],
            challenge: buf[2..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthClient {
    pub username: String,
    pub selected_algorithm: u8,
    pub public_key_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl KeyAuthClient {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.username.len() + 1 + 32 + self.signature.len());
        out.push(self.username.len() as u8);
        out.extend_from_slice(self.username.as_bytes());
        out.push(self.selected_algorithm);
        out.extend_from_slice(&self.public_key_hash);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let username_len = *buf.first().ok_or(WispError::ExtensionPayloadTooShort {
            needed: 1,
            got: buf.len(),
        })? as usize;
        let header_len = 1 + username_len + 1 + 32;
        if buf.len() < header_len {
            return Err(WispError::ExtensionPayloadTooShort {
                needed: header_len,
                got: buf.len(),
            });
        }
        let username = std::str::from_utf8(&buf[1..1 + username_len])?.to_string();
        let selected_algorithm = buf[1 + username_len];
        let mut public_key_hash = [0u8; 32];
        public_key_hash.copy_from_slice(&buf[2 + username_len..2 + username_len + 32]);
        let signature = buf[header_len..].to_vec();
        Ok(KeyAuthClient {
            username,
            selected_algorithm,
            public_key_hash,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Motd {
    pub message: String,
}

impl Motd {
    pub fn encode(&self) -> Vec<u8> {
        self.message.as_bytes().to_vec()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        Ok(Motd {
            message: std::str::from_utf8(buf)?.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_meta_round_trip() {
        let metas = vec![
            ExtensionMeta::new(extension_id::UDP, vec![]),
            ExtensionMeta::new(extension_id::MOTD, b"hello".to_vec()),
            ExtensionMeta::new(0xee, vec![1, 2, 3, 4, 5]),
        ];
        let encoded = ExtensionMeta::encode_all(&metas);
        let decoded = ExtensionMeta::decode_all(&encoded).unwrap();
        assert_eq!(metas, decoded);
    }

    #[test]
    fn extension_meta_declared_length_prefix_is_four_bytes_le() {
        let meta = ExtensionMeta::new(0x02, vec![9, 9, 9]);
        let mut out = Vec::new();
        meta.encode(&mut out);
        assert_eq!(out[0], 0x02);
        assert_eq!(&out[1..5], &3u32.to_le_bytes());
        assert_eq!(&out[5..], &[9, 9, 9]);
    }

    #[test]
    fn extension_meta_rejects_truncated_payload() {
        let mut out = Vec::new();
        ExtensionMeta::new(0x02, vec![1, 2, 3]).encode(&mut out);
        out.truncate(out.len() - 1);
        assert!(ExtensionMeta::decode(&out).is_err());
    }

    #[test]
    fn password_auth_server_round_trip() {
        for required in [true, false] {
            let msg = PasswordAuthServer { required };
            assert_eq!(PasswordAuthServer::decode(&msg.encode()).unwrap(), msg);
        }
    }

    #[test]
    fn password_auth_client_round_trip() {
        let msg = PasswordAuthClient {
            username: "steve".to_string(),
            password: "hunter2".to_string(),
        };
        let encoded = msg.encode();
        assert_eq!(encoded[0] as usize, "steve".len());
        assert_eq!(PasswordAuthClient::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn key_auth_server_round_trip() {
        let msg = KeyAuthServer {
            required: true,
            supported_algorithms: SIGNATURE_ALGORITHM_ED25519,
            challenge: vec![0xab; 64],
        };
        assert_eq!(KeyAuthServer::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn key_auth_client_round_trip() {
        let msg = KeyAuthClient {
            username: "steve".to_string(),
            selected_algorithm: SIGNATURE_ALGORITHM_ED25519,
            public_key_hash: [7u8; 32],
            signature: vec![0xcd; 64],
        };
        assert_eq!(KeyAuthClient::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn motd_round_trip() {
        let msg = Motd {
            message: "be nice".to_string(),
        };
        assert_eq!(Motd::decode(&msg.encode()).unwrap(), msg);
    }
}
