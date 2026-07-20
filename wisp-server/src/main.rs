mod auth;
mod cli;
mod mux;
mod proto;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use auth::{KeyAuthConfig, PasswordAuthConfig};
use cli::Args;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let password_auth = match (&args.username, &args.password) {
        (Some(username), Some(password)) => Some(Arc::new(PasswordAuthConfig {
            username: username.clone(),
            password: password.clone(),
            required: !args.password_optional,
        })),
        (None, None) => None,
        _ => return Err("--username and --password must be set together".into()),
    };

    let key_auth = if args.key_auth_pubkeys.is_empty() {
        None
    } else {
        let mut allowed_keys = Vec::new();
        for hex_key in &args.key_auth_pubkeys {
            let bytes = hex::decode(hex_key)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "--key-auth-pubkey must be 32 bytes, hex encoded")?;
            allowed_keys.push(VerifyingKey::from_bytes(&bytes)?);
        }
        Some(Arc::new(KeyAuthConfig {
            allowed_keys,
            required: !args.key_auth_optional,
        }))
    };

    let motd: Option<Arc<str>> = args.motd.clone().map(Arc::from);

    let listener = TcpListener::bind(&args.bind).await?;
    println!("nyx-server listening on {}", args.bind);

    loop {
        let (socket, _) = listener.accept().await?;
        let password_auth = password_auth.clone();
        let key_auth = key_auth.clone();
        let motd = motd.clone();
        let buffer_size = args.buffer_size;
        tokio::spawn(async move {
            let _ = handle_connection(socket, buffer_size, password_auth, key_auth, motd).await;
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    buffer_size: u32,
    password_auth: Option<Arc<PasswordAuthConfig>>,
    key_auth: Option<Arc<KeyAuthConfig>>,
    motd: Option<Arc<str>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_ws_protocol_header = Arc::new(AtomicBool::new(false));
    let flag = has_ws_protocol_header.clone();
    let mut ws = tokio_tungstenite::accept_hdr_async(socket, move |req: &Request, resp: Response| {
        flag.store(req.headers().contains_key("sec-websocket-protocol"), Ordering::SeqCst);
        Ok(resp)
    })
    .await?;

    if !has_ws_protocol_header.load(Ordering::SeqCst) {
        return Ok(());
    }

    let challenge = key_auth.as_ref().map(|_| {
        let mut bytes = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    });

    let negotiated = proto::perform_server_handshake(
        &mut ws,
        proto::HandshakeConfig {
            buffer_size,
            password_auth: password_auth.as_deref(),
            key_auth: key_auth.as_deref().zip(challenge.as_deref()),
            motd: motd.as_deref(),
        },
    )
    .await?;

    mux::run(ws, negotiated.buffer_size).await;
    Ok(())
}
