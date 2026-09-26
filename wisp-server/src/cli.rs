use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "nyx-server", about = "Wisp v2 server that proxies TCP and UDP streams")]
pub struct Args {
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub bind: String,

    /// Packets each TCP stream may buffer, sent to clients in CONTINUE.
    // must be at least 1: a zero sized buffer would never let the client send anything
    #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u32).range(1..))]
    pub buffer_size: u32,

    #[arg(long)]
    pub username: Option<String>,

    #[arg(long)]
    pub password: Option<String>,

    #[arg(long)]
    pub password_optional: bool,

    #[arg(long)]
    pub motd: Option<String>,

    /// Ed25519 public key allowed to authenticate, hex encoded. Repeatable.
    #[arg(long = "key-auth-pubkey")]
    pub key_auth_pubkeys: Vec<String>,

    #[arg(long)]
    pub key_auth_optional: bool,

    /// Refuse UDP streams and stop advertising the UDP extension.
    #[arg(long)]
    pub no_udp: bool,

    /// Stop offering the stream open confirmation extension.
    #[arg(long)]
    pub no_stream_confirmation: bool,

    /// Seconds to wait for an upstream TCP connect.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    pub connect_timeout: u64,

    /// Seconds a client may take to finish the handshake.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    pub handshake_timeout: u64,

    /// PEM certificate chain. Serves wss:// when given together with --tls-key.
    #[arg(long, requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for --tls-cert.
    #[arg(long, requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
}
