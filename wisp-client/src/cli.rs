use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "nyx-client", about = "Opens one wisp stream and connects it to stdin/stdout")]
pub struct Args {
    /// ws:// or wss:// url of the wisp server, ending in a slash.
    pub url: String,

    #[arg(long)]
    pub tcp: Option<String>,

    #[arg(long)]
    pub udp: Option<String>,

    #[arg(long)]
    pub username: Option<String>,

    #[arg(long)]
    pub password: Option<String>,

    /// Ed25519 private key seed, hex encoded.
    #[arg(long)]
    pub key_auth_privkey: Option<String>,

    /// Extra PEM CA certificate to trust for wss://, on top of the built in web roots.
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
}
