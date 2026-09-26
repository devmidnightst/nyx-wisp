mod cli;
mod tls;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ed25519_dalek::VerifyingKey;
use tokio::net::TcpListener;

use wisp_tokio::server::{self, KeyAuth, PasswordAuth, ServerConfig};

use cli::Args;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = Arc::new(server_config(&args)?);
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(tls::acceptor(cert, key)?),
        _ => None,
    };

    let listener = TcpListener::bind(&args.bind).await?;
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    println!("nyx-server listening on {scheme}://{}/", listener.local_addr()?);

    loop {
        let (socket, _) = listener.accept().await?;
        let config = config.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _ = socket.set_nodelay(true);
            match tls {
                Some(tls) => {
                    if let Ok(socket) = tls.accept(socket).await {
                        let _ = server::accept(socket, config).await;
                    }
                }
                None => {
                    let _ = server::accept(socket, config).await;
                }
            }
        });
    }
}

fn server_config(args: &Args) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let password_auth = match (&args.username, &args.password) {
        (Some(username), Some(password)) => Some(PasswordAuth {
            username: username.clone(),
            password: password.clone(),
            required: !args.password_optional,
        }),
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
        Some(KeyAuth {
            allowed_keys,
            required: !args.key_auth_optional,
        })
    };

    Ok(ServerConfig {
        buffer_size: args.buffer_size,
        password_auth,
        key_auth,
        motd: args.motd.clone(),
        udp: !args.no_udp,
        stream_confirmation: !args.no_stream_confirmation,
        connect_timeout: Duration::from_secs(args.connect_timeout),
        handshake_timeout: Duration::from_secs(args.handshake_timeout),
    })
}
