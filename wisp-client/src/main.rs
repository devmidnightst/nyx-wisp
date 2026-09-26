mod cli;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use ed25519_dalek::SigningKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::{ClientConfig as TlsConfig, RootCertStore};
use tokio_tungstenite::Connector;

use cli::Args;
use wisp_core::StreamType;
use wisp_tokio::client::{self, ClientConfig, ClientMux, KeyCredentials, PasswordCredentials};

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nyx-client: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let (stream_type, host, port) = match (&args.tcp, &args.udp) {
        (Some(target), None) => {
            let (host, port) = parse_target(target)?;
            (StreamType::Tcp, host, port)
        }
        (None, Some(target)) => {
            let (host, port) = parse_target(target)?;
            (StreamType::Udp, host, port)
        }
        _ => return Err("exactly one of --tcp or --udp must be given".into()),
    };

    let config = client_config(&args)?;
    let connector = Connector::Rustls(Arc::new(tls_config(args.ca_cert.as_deref())?));
    let request = client::request(&args.url)?;
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(wisp_tokio::websocket_config()),
        false,
        Some(connector),
    ).await?;

    let mux = ClientMux::new(ws, config).await?;
    if let Some(motd) = &mux.info().motd {
        eprintln!("motd: {motd}");
    }

    let stream = mux.open(stream_type, host, port).await?;

    let (mut from_stream, mut to_stream) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // wisp has no half-close, so stdin reaching EOF closes the whole stream
    tokio::select! {
        _ = tokio::io::copy(&mut stdin, &mut to_stream) => {
            let _ = to_stream.shutdown().await;
        }
        result = tokio::io::copy(&mut from_stream, &mut stdout) => {
            if let Err(err) = result {
                eprintln!("stream closed: {err}");
            }
        }
    }
    stdout.flush().await?;
    mux.close();

    Ok(())
}

fn client_config(args: &Args) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let password = match (&args.username, &args.password) {
        (Some(username), Some(password)) => Some(PasswordCredentials {
            username: username.clone(),
            password: password.clone(),
        }),
        _ => None,
    };

    let key = match &args.key_auth_privkey {
        Some(hex_seed) => {
            let bytes = hex::decode(hex_seed)?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "--key-auth-privkey must be 32 bytes, hex encoded")?;
            Some(KeyCredentials {
                username: args.username.clone().unwrap_or_default(),
                signing_key: SigningKey::from_bytes(&seed),
            })
        }
        None => None,
    };

    Ok(ClientConfig {
        password,
        key,
        ..ClientConfig::default()
    })
}

/// Web PKI roots, plus `ca_cert` when given (for self-signed or private CAs).
fn tls_config(ca_cert: Option<&Path>) -> Result<TlsConfig, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_cert {
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|err| format!("reading {}: {err}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("parsing {}: {err}", path.display()))?;
        if certs.is_empty() {
            return Err(format!("{} contains no certificates", path.display()).into());
        }
        for cert in certs {
            roots.add(cert)?;
        }
    }
    Ok(TlsConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

fn parse_target(target: &str) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let (host, port) = target.rsplit_once(':').ok_or("target must be in host:port form")?;
    let port: u16 = port.parse()?;
    // allow [::1]:80 style ipv6 targets, the brackets are not part of the hostname
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_splits_host_and_port() {
        assert_eq!(parse_target("example.com:80").unwrap(), ("example.com".to_string(), 80));
        assert_eq!(parse_target("[::1]:443").unwrap(), ("::1".to_string(), 443));
        assert_eq!(parse_target("::1:53").unwrap(), ("::1".to_string(), 53));
    }

    #[test]
    fn parse_target_rejects_bad_input() {
        assert!(parse_target("example.com").is_err());
        assert!(parse_target("example.com:http").is_err());
        assert!(parse_target("example.com:70000").is_err());
    }

    #[test]
    fn tls_config_rejects_a_missing_ca_file() {
        assert!(tls_config(Some(Path::new("/definitely/not/here.pem"))).is_err());
    }
}
