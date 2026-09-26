use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use sha2::Digest;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use wisp_core::extension::{
    extension_id, KeyAuthClient, KeyAuthServer, Motd, PasswordAuthClient, PasswordAuthServer,
    SIGNATURE_ALGORITHM_ED25519,
};
use wisp_core::{CloseReason, ExtensionMeta, Frame, Packet, WispVersion};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error(transparent)]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error(transparent)]
    Wisp(#[from] wisp_core::WispError),
    #[error("connection closed before the handshake completed")]
    ConnectionClosed,
    #[error("unexpected packet received during handshake")]
    UnexpectedHandshakePacket,
    #[error("server requires authentication but no usable credentials were given")]
    MissingCredentials,
    #[error("username must be at most 255 bytes")]
    UsernameTooLong,
    #[error("server rejected the connection: {0:?}")]
    Rejected(CloseReason),
}

pub async fn send_frame(ws: &mut WsStream, frame: &Frame) -> Result<(), ProtoError> {
    ws.send(Message::Binary(frame.encode())).await?;
    Ok(())
}

pub async fn recv_frame(ws: &mut WsStream) -> Result<Option<Frame>, ProtoError> {
    loop {
        match ws.next().await {
            None => return Ok(None),
            Some(Err(err)) => return Err(ProtoError::WebSocket(err)),
            Some(Ok(Message::Binary(bytes))) => return Ok(Some(Frame::decode(&bytes)?)),
            Some(Ok(Message::Close(_))) => return Ok(None),
            Some(Ok(_)) => continue,
        }
    }
}

pub struct Credentials<'a> {
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub key_auth_seed: Option<[u8; 32]>,
}

pub struct Negotiated {
    pub buffer_remaining: u32,
    pub motd: Option<String>,
}

pub async fn perform_client_handshake(ws: &mut WsStream, creds: Credentials<'_>) -> Result<Negotiated, ProtoError> {
    let server_info = recv_frame(ws).await?.ok_or(ProtoError::ConnectionClosed)?;
    let server_extensions = match server_info.packet {
        Packet::Info { extensions, .. } if server_info.stream_id == 0 => extensions,
        _ => return Err(ProtoError::UnexpectedHandshakePacket),
    };

    let motd = server_extensions
        .iter()
        .find(|extension| extension.id == extension_id::MOTD)
        .and_then(|extension| Motd::decode(&extension.data).ok())
        .map(|motd| motd.message);

    let mut client_extensions = vec![ExtensionMeta::new(extension_id::UDP, vec![])];

    // if the server marks any auth method as required, sending credentials for any one
    // offered method is enough, the spec lets the client pick
    let mut auth_required = false;
    let mut auth_sent = false;

    if let Some(username) = creds.username {
        if username.len() > u8::MAX as usize {
            return Err(ProtoError::UsernameTooLong);
        }
    }

    if let Some(meta) = server_extensions.iter().find(|extension| extension.id == extension_id::PASSWORD_AUTH) {
        let server_msg = PasswordAuthServer::decode(&meta.data)?;
        auth_required |= server_msg.required;
        if let (Some(username), Some(password)) = (creds.username, creds.password) {
            auth_sent = true;
            client_extensions.push(ExtensionMeta::new(
                extension_id::PASSWORD_AUTH,
                PasswordAuthClient {
                    username: username.to_string(),
                    password: password.to_string(),
                }
                .encode(),
            ));
        }
    }

    if let Some(meta) = server_extensions.iter().find(|extension| extension.id == extension_id::KEY_AUTH) {
        let server_msg = KeyAuthServer::decode(&meta.data)?;
        auth_required |= server_msg.required;
        match creds.key_auth_seed {
            Some(seed) if server_msg.supported_algorithms & SIGNATURE_ALGORITHM_ED25519 != 0 => {
                auth_sent = true;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let verifying_key = signing_key.verifying_key();
                let signature = signing_key.sign(&server_msg.challenge);
                let digest = sha2::Sha256::digest(verifying_key.as_bytes());
                let mut public_key_hash = [0u8; 32];
                public_key_hash.copy_from_slice(&digest);
                client_extensions.push(ExtensionMeta::new(
                    extension_id::KEY_AUTH,
                    KeyAuthClient {
                        username: creds.username.unwrap_or_default().to_string(),
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
        return Err(ProtoError::MissingCredentials);
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

    let reply = recv_frame(ws).await?.ok_or(ProtoError::ConnectionClosed)?;
    match reply.packet {
        Packet::Continue { buffer_remaining } if reply.stream_id == 0 => Ok(Negotiated {
            buffer_remaining,
            motd,
        }),
        Packet::Close { reason } if reply.stream_id == 0 => Err(ProtoError::Rejected(reason)),
        _ => Err(ProtoError::UnexpectedHandshakePacket),
    }
}
