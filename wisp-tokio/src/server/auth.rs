use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wisp_core::extension::{KeyAuthClient, PasswordAuthClient, SIGNATURE_ALGORITHM_ED25519};

/// Username/password auth (extension 0x02).
#[derive(Debug, Clone)]
pub struct PasswordAuth {
    pub username: String,
    pub password: String,
    /// Whether clients must authenticate. When false, clients may skip auth, but credentials they
    /// do send are still checked.
    pub required: bool,
}

impl PasswordAuth {
    pub(crate) fn verify(&self, creds: &PasswordAuthClient) -> bool {
        // evaluate both comparisons so a wrong username and a wrong password take the same time
        let username_ok = constant_time_eq(creds.username.as_bytes(), self.username.as_bytes());
        let password_ok = constant_time_eq(creds.password.as_bytes(), self.password.as_bytes());
        username_ok & password_ok
    }
}

/// Ed25519 public key auth (extension 0x03).
#[derive(Debug, Clone)]
pub struct KeyAuth {
    pub allowed_keys: Vec<VerifyingKey>,
    /// Whether clients must authenticate.
    pub required: bool,
}

impl KeyAuth {
    pub(crate) fn verify(&self, message: &KeyAuthClient, challenge: &[u8]) -> bool {
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

/// Compares two byte strings without an early exit on the first mismatch. The length is not
/// hidden, only the position of the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn password_auth() -> PasswordAuth {
        PasswordAuth {
            username: "user".to_string(),
            password: "hunter2".to_string(),
            required: true,
        }
    }

    fn creds(username: &str, password: &str) -> PasswordAuthClient {
        PasswordAuthClient {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"abc", b"xbc"));
    }

    #[test]
    fn password_auth_checks_both_fields() {
        let auth = password_auth();
        assert!(auth.verify(&creds("user", "hunter2")));
        assert!(!auth.verify(&creds("user", "hunter3")));
        assert!(!auth.verify(&creds("admin", "hunter2")));
        assert!(!auth.verify(&creds("", "")));
    }

    fn key_message(signing_key: &SigningKey, challenge: &[u8]) -> KeyAuthClient {
        let mut public_key_hash = [0u8; 32];
        public_key_hash.copy_from_slice(&Sha256::digest(signing_key.verifying_key().as_bytes()));
        KeyAuthClient {
            username: String::new(),
            selected_algorithm: SIGNATURE_ALGORITHM_ED25519,
            public_key_hash,
            signature: signing_key.sign(challenge).to_bytes().to_vec(),
        }
    }

    #[test]
    fn key_auth_accepts_a_valid_signature_from_an_allowed_key() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let auth = KeyAuth {
            allowed_keys: vec![key.verifying_key()],
            required: true,
        };
        assert!(auth.verify(&key_message(&key, b"challenge"), b"challenge"));
    }

    #[test]
    fn key_auth_rejects_unknown_keys_bad_signatures_and_algorithms() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let other = SigningKey::from_bytes(&[2; 32]);
        let auth = KeyAuth {
            allowed_keys: vec![key.verifying_key()],
            required: true,
        };

        assert!(!auth.verify(&key_message(&other, b"challenge"), b"challenge"));
        assert!(!auth.verify(&key_message(&key, b"other challenge"), b"challenge"));

        let mut wrong_algorithm = key_message(&key, b"challenge");
        wrong_algorithm.selected_algorithm = 0b10;
        assert!(!auth.verify(&wrong_algorithm, b"challenge"));

        let mut short_signature = key_message(&key, b"challenge");
        short_signature.signature.truncate(10);
        assert!(!auth.verify(&short_signature, b"challenge"));
    }
}
