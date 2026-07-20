use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "nyx-client")]
pub struct Args {
    pub url: String,

    #[arg(long)]
    pub tcp: Option<String>,

    #[arg(long)]
    pub udp: Option<String>,

    #[arg(long)]
    pub username: Option<String>,

    #[arg(long)]
    pub password: Option<String>,

    #[arg(long)]
    pub key_auth_privkey: Option<String>,
}
