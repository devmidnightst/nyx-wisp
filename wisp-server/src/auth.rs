use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wisp_core::extension::{KeyAuthClient, SIGNATURE_ALGORITHM_ED25519};

#[derive(Debug, Clone)]
pub struct PasswordAuthConfig {
    pub username: String,
    pub password: String,
    pub required: bool,
}

#[derive(Clone)]
pub struct KeyAuthConfig {
    pub allowed_keys: Vec<VerifyingKey>,
    pub required: bool,
}

impl KeyAuthConfig {
    pub fn verify(&self, message: &KeyAuthClient, challenge: &[u8]) -> bool {
        if message.selected_algorithm != SIGNATURE_ALGORITHM_ED25519 {
            return false;
        }
        let matching_key = self.allowed_keys.iter().find(|key| {
            let digest = Sha256::digest(key.as_bytes());
            digest.as_slice() == message.public_key_hash
        });
        let Some(key) = matching_key else {
            return false;
        };
        let Ok(signature_bytes) = <[u8; 64]>::try_from(message.signature.as_slice()) else {
            return false;
        };
        let signature = Signature::from_bytes(&signature_bytes);
        key.verify(challenge, &signature).is_ok()
    }
}
