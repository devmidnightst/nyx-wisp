use ed25519_dalek::Signer;
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;

use wisp_core::extension::{
    extension_id, KeyAuthClient, KeyAuthServer, Motd, PasswordAuthClient, PasswordAuthServer,
    SIGNATURE_ALGORITHM_ED25519,
};
use wisp_core::{CloseReason, ExtensionMeta, Frame, Packet, WispVersion};

use super::{ClientConfig, ServerInfo};
use crate::error::{Error, Result};
use crate::ws::{recv_frame, send_frame};

/// Runs the client side of the v2 handshake: read the server's INFO, answer with ours (plus
/// credentials when the server asks for them), then wait for CONTINUE or CLOSE on stream 0.
pub(crate) async fn perform<S>(ws: &mut WebSocketStream<S>, config: &ClientConfig) -> Result<ServerInfo>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for username in [
        config.password.as_ref().map(|creds| creds.username.as_str()),
        config.key.as_ref().map(|creds| creds.username.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if username.len() > u8::MAX as usize {
            return Err(Error::UsernameTooLong);
        }
    }

    let server_info = recv_frame(ws).await?.ok_or(Error::ConnectionClosed)?;
    let (server_version, server_extensions) = match server_info.packet {
        Packet::Info { version, extensions } if server_info.stream_id == 0 => (version, extensions),
        // a CONTINUE first means a v1 server, which this client does not speak
        _ => return Err(Error::UnexpectedHandshakePacket),
    };
    let find = |id: u8| server_extensions.iter().find(|extension| extension.id == id);

    let motd = find(extension_id::MOTD)
        .and_then(|extension| Motd::decode(&extension.data).ok())
        .map(|motd| motd.message);

    let mut client_extensions = Vec::new();
    if config.udp {
        client_extensions.push(ExtensionMeta::new(extension_id::UDP, vec![]));
    }
    if config.stream_confirmation {
        client_extensions.push(ExtensionMeta::new(extension_id::STREAM_OPEN_CONFIRMATION, vec![]));
    }

    // if the server marks any auth method as required, sending credentials for any one
    // offered method is enough, the spec lets the client pick
    let mut auth_required = false;
    let mut auth_sent = false;

    if let Some(meta) = find(extension_id::PASSWORD_AUTH) {
        let server_msg = PasswordAuthServer::decode(&meta.data)?;
        auth_required |= server_msg.required;
        if let Some(creds) = &config.password {
            auth_sent = true;
            client_extensions.push(ExtensionMeta::new(
                extension_id::PASSWORD_AUTH,
                PasswordAuthClient {
                    username: creds.username.clone(),
                    password: creds.password.clone(),
                }
                .encode(),
            ));
        }
    }

    if let Some(meta) = find(extension_id::KEY_AUTH) {
        let server_msg = KeyAuthServer::decode(&meta.data)?;
        auth_required |= server_msg.required;
        match &config.key {
            Some(creds) if server_msg.supported_algorithms & SIGNATURE_ALGORITHM_ED25519 != 0 => {
                auth_sent = true;
                let signature = creds.signing_key.sign(&server_msg.challenge);
                let digest = sha2::Sha256::digest(creds.signing_key.verifying_key().as_bytes());
                let mut public_key_hash = [0u8; 32];
                public_key_hash.copy_from_slice(&digest);
                client_extensions.push(ExtensionMeta::new(
                    extension_id::KEY_AUTH,
                    KeyAuthClient {
                        username: creds.username.clone(),
                        selected_algorithm: SIGNATURE_ALGORITHM_ED25519,
                        public_key_hash,
                        signature: signature.to_bytes().to_vec(),
                    }
                    .encode(),
                ));
            }
            _ => {}
        }
    }

    if auth_required && !auth_sent {
        // the spec says a client rejecting the connection must send CLOSE on stream 0 first
        let _ = send_frame(
            ws,
            &Frame::new(
                0,
                Packet::Close {
                    reason: CloseReason::AuthRequired,
                },
            ),
        )
        .await;
        let _ = ws.close(None).await;
        return Err(Error::MissingCredentials);
    }

    send_frame(
        ws,
        &Frame::new(
            0,
            Packet::Info {
                version: WispVersion::V2,
                extensions: client_extensions,
            },
        ),
    )
    .await?;

    let reply = recv_frame(ws).await?.ok_or(Error::ConnectionClosed)?;
    match reply.packet {
        Packet::Continue { buffer_remaining } if reply.stream_id == 0 => Ok(ServerInfo {
            version: server_version,
            buffer_size: buffer_remaining,
            motd,
            udp: config.udp && find(extension_id::UDP).is_some(),
            stream_confirmation: config.stream_confirmation
                && find(extension_id::STREAM_OPEN_CONFIRMATION).is_some(),
            extensions: server_extensions.iter().map(|extension| extension.id).collect(),
        }),
        Packet::Close { reason } if reply.stream_id == 0 => Err(Error::Rejected(reason)),
        _ => Err(Error::UnexpectedHandshakePacket),
    }
}
