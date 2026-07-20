use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "nyx-server")]
pub struct Args {
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub bind: String,

    #[arg(long, default_value_t = 128)]
    pub buffer_size: u32,

    #[arg(long)]
    pub username: Option<String>,

    #[arg(long)]
    pub password: Option<String>,

    #[arg(long)]
    pub password_optional: bool,

    #[arg(long)]
    pub motd: Option<String>,

    #[arg(long = "key-auth-pubkey")]
    pub key_auth_pubkeys: Vec<String>,

    #[arg(long)]
    pub key_auth_optional: bool,
}
