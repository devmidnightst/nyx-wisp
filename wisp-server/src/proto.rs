use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use wisp_core::extension::{
    extension_id, KeyAuthClient, KeyAuthServer, Motd, PasswordAuthClient, PasswordAuthServer,
    SIGNATURE_ALGORITHM_ED25519,
};
use wisp_core::{CloseReason, ExtensionMeta, Frame, Packet, WispVersion};

use crate::auth::{KeyAuthConfig, PasswordAuthConfig};

pub type WsStream = tokio_tungstenite::WebSocketStream<TcpStream>;

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
    #[error("authentication failed")]
    AuthFailed,
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

pub struct HandshakeConfig<'a> {
    pub buffer_size: u32,
    pub password_auth: Option<&'a PasswordAuthConfig>,
    pub key_auth: Option<(&'a KeyAuthConfig, &'a [u8])>,
    pub motd: Option<&'a str>,
}

pub struct Negotiated {
    pub buffer_size: u32,
}

pub async fn perform_server_handshake(
    ws: &mut WsStream,
    config: HandshakeConfig<'_>,
) -> Result<Negotiated, ProtoError> {
    let mut extensions = vec![ExtensionMeta::new(extension_id::UDP, vec![])];

    if let Some(password_auth) = config.password_auth {
        extensions.push(ExtensionMeta::new(
            extension_id::PASSWORD_AUTH,
            PasswordAuthServer {
                required: password_auth.required,
            }
            .encode(),
        ));
    }

    if let Some((key_auth, challenge)) = config.key_auth {
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

    if let Some(motd) = config.motd {
        extensions.push(ExtensionMeta::new(
            extension_id::MOTD,
            Motd {
                message: motd.to_string(),
            }
            .encode(),
        ));
    }

    send_frame(
        ws,
        &Frame::new(
            0,
            Packet::Info {
                version: WispVersion::V2,
                extensions,
            },
        ),
    )
    .await?;

    let client_info = recv_frame(ws).await?.ok_or(ProtoError::ConnectionClosed)?;
    let client_extensions = match client_info.packet {
        Packet::Info { extensions, .. } if client_info.stream_id == 0 => extensions,
        _ => {
            let _ = send_frame(
                ws,
                &Frame::new(
                    0,
                    Packet::Close {
                        reason: CloseReason::Unspecified,
                    },
                ),
            )
            .await;
            return Err(ProtoError::UnexpectedHandshakePacket);
        }
    };

    // a client that sends credentials for a method must pass it. if no credentials were sent
    // at all, the connection is only refused when some method is required, and then with the
    // dedicated "auth required" reason. when both methods are offered, either one is enough.
    let mut any_authenticated = false;
    let mut auth_required = false;

    if let Some(password_auth) = config.password_auth {
        auth_required |= password_auth.required;
        let provided = client_extensions
            .iter()
            .find(|extension| extension.id == extension_id::PASSWORD_AUTH);
        if let Some(meta) = provided {
            let valid = PasswordAuthClient::decode(&meta.data)
                .map(|creds| creds.username == password_auth.username && creds.password == password_auth.password)
                .unwrap_or(false);
            if !valid {
                return reject(ws, CloseReason::AuthFailedCredentials).await;
            }
            any_authenticated = true;
        }
    }

    if let Some((key_auth, challenge)) = config.key_auth {
        auth_required |= key_auth.required;
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

    if auth_required && !any_authenticated {
        return reject(ws, CloseReason::AuthRequired).await;
    }

    send_frame(
        ws,
        &Frame::new(
            0,
            Packet::Continue {
                buffer_remaining: config.buffer_size,
            },
        ),
    )
    .await?;

    Ok(Negotiated {
        buffer_size: config.buffer_size,
    })
}

async fn reject(ws: &mut WsStream, reason: CloseReason) -> Result<Negotiated, ProtoError> {
    let _ = send_frame(ws, &Frame::new(0, Packet::Close { reason })).await;
    let _ = ws.close(None).await;
    Err(ProtoError::AuthFailed)
}
