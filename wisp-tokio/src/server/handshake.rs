use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;

use wisp_core::extension::{
    extension_id, KeyAuthClient, KeyAuthServer, Motd, PasswordAuthClient, PasswordAuthServer,
    SIGNATURE_ALGORITHM_ED25519,
};
use wisp_core::{CloseReason, ExtensionMeta, Frame, Packet, WispVersion};

use super::ServerConfig;
use crate::error::{Error, Result};
use crate::ws::{recv_frame, send_frame};

/// Length of the random key auth challenge. The spec suggests around 512 bits.
const CHALLENGE_LEN: usize = 64;

pub(crate) struct Negotiated {
    /// Both sides support the stream open confirmation extension.
    pub stream_confirmation: bool,
}

fn server_extensions(config: &ServerConfig, challenge: Option<&[u8]>) -> Vec<ExtensionMeta> {
    let mut extensions = Vec::new();

    if config.udp {
        extensions.push(ExtensionMeta::new(extension_id::UDP, vec![]));
    }

    if let Some(password_auth) = &config.password_auth {
        extensions.push(ExtensionMeta::new(
            extension_id::PASSWORD_AUTH,
            PasswordAuthServer {
                required: password_auth.required,
            }
            .encode(),
        ));
    }

    if let (Some(key_auth), Some(challenge)) = (&config.key_auth, challenge) {
        extensions.push(ExtensionMeta::new(
            extension_id::KEY_AUTH,
            KeyAuthServer {
                required: key_auth.required,
                supported_algorithms: SIGNATURE_ALGORITHM_ED25519,
                challenge: challenge.to_vec(),
            }
            .encode(),
        ));
    }

    if let Some(motd) = &config.motd {
        extensions.push(ExtensionMeta::new(
            extension_id::MOTD,
            Motd {
                message: motd.clone(),
            }
            .encode(),
        ));
    }

    if config.stream_confirmation {
        extensions.push(ExtensionMeta::new(extension_id::STREAM_OPEN_CONFIRMATION, vec![]));
    }

    extensions
}

pub(crate) async fn perform<S>(ws: &mut WebSocketStream<S>, config: &ServerConfig) -> Result<Negotiated>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let challenge = config.key_auth.as_ref().map(|_| {
        let mut bytes = vec![0u8; CHALLENGE_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    });

    send_frame(
        ws,
        &Frame::new(
            0,
            Packet::Info {
                version: WispVersion::V2,
                extensions: server_extensions(config, challenge.as_deref()),
            },
        ),
    )
    .await?;

    let client_info = tokio::time::timeout(config.handshake_timeout, recv_frame(ws))
        .await
        .map_err(|_| Error::ConnectionClosed)??
        .ok_or(Error::ConnectionClosed)?;
    let client_extensions = match client_info.packet {
        Packet::Info { extensions, .. } if client_info.stream_id == 0 => extensions,
        _ => {
            let _: Result<()> = reject(ws, CloseReason::Unspecified).await;
            return Err(Error::UnexpectedHandshakePacket);
        }
    };

    // a client that sends credentials for a method must pass it. if no credentials were sent
    // at all, the connection is only refused when some method is required, and then with the
    // dedicated "auth required" reason. when both methods are offered, either one is enough.
    let mut any_authenticated = false;

    if let Some(password_auth) = &config.password_auth {
        let provided = client_extensions
            .iter()
            .find(|extension| extension.id == extension_id::PASSWORD_AUTH);
        if let Some(meta) = provided {
            let valid = PasswordAuthClient::decode(&meta.data)
                .map(|creds| password_auth.verify(&creds))
                .unwrap_or(false);
            if !valid {
                return reject(ws, CloseReason::AuthFailedCredentials).await;
            }
            any_authenticated = true;
        }
    }

    if let (Some(key_auth), Some(challenge)) = (&config.key_auth, &challenge) {
        let provided = client_extensions
            .iter()
            .find(|extension| extension.id == extension_id::KEY_AUTH);
        if let Some(meta) = provided {
            let valid = KeyAuthClient::decode(&meta.data)
                .map(|msg| key_auth.verify(&msg, challenge))
                .unwrap_or(false);
            if !valid {
                return reject(ws, CloseReason::AuthFailedSignature).await;
            }
            any_authenticated = true;
        }
    }

    if config.auth_required() && !any_authenticated {
        return reject(ws, CloseReason::AuthRequired).await;
    }

    send_frame(
        ws,
        &Frame::new(
            0,
            Packet::Continue {
                buffer_remaining: config.effective_buffer_size(),
            },
        ),
    )
    .await?;

    let client_confirms = client_extensions
        .iter()
        .any(|extension| extension.id == extension_id::STREAM_OPEN_CONFIRMATION);

    Ok(Negotiated {
        stream_confirmation: config.stream_confirmation && client_confirms,
    })
}

async fn reject<S, T>(ws: &mut WebSocketStream<S>, reason: CloseReason) -> Result<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = send_frame(ws, &Frame::new(0, Packet::Close { reason })).await;
    let _ = ws.close(None).await;
    Err(Error::Rejected(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{KeyAuth, PasswordAuth};

    fn ids(extensions: &[ExtensionMeta]) -> Vec<u8> {
        extensions.iter().map(|extension| extension.id).collect()
    }

    #[test]
    fn default_config_advertises_udp_and_stream_confirmation() {
        let extensions = server_extensions(&ServerConfig::default(), None);
        assert_eq!(
            ids(&extensions),
            vec![extension_id::UDP, extension_id::STREAM_OPEN_CONFIRMATION]
        );
    }

    #[test]
    fn disabled_features_are_not_advertised() {
        let config = ServerConfig {
            udp: false,
            stream_confirmation: false,
            ..ServerConfig::default()
        };
        assert!(server_extensions(&config, None).is_empty());
    }

    #[test]
    fn auth_and_motd_extensions_carry_their_payloads() {
        let config = ServerConfig {
            password_auth: Some(PasswordAuth {
                username: "u".into(),
                password: "p".into(),
                required: false,
            }),
            key_auth: Some(KeyAuth {
                allowed_keys: vec![],
                required: true,
            }),
            motd: Some("hello".into()),
            ..ServerConfig::default()
        };
        let extensions = server_extensions(&config, Some(&[7; CHALLENGE_LEN]));
        let find = |id| extensions.iter().find(|extension| extension.id == id).unwrap();

        let password = PasswordAuthServer::decode(&find(extension_id::PASSWORD_AUTH).data).unwrap();
        assert!(!password.required);

        let key = KeyAuthServer::decode(&find(extension_id::KEY_AUTH).data).unwrap();
        assert!(key.required);
        assert_eq!(key.supported_algorithms, SIGNATURE_ALGORITHM_ED25519);
        assert_eq!(key.challenge, vec![7; CHALLENGE_LEN]);

        assert_eq!(find(extension_id::MOTD).data, b"hello");
    }
}
