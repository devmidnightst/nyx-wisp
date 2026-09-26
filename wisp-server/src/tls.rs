use std::path::Path;
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Builds a TLS acceptor from a PEM certificate chain and a PEM private key (PKCS#8, PKCS#1 or
/// SEC1).
pub fn acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|err| format!("reading {}: {err}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parsing {}: {err}", cert_path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} contains no certificates", cert_path.display()).into());
    }
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|err| format!("reading {}: {err}", key_path.display()))?;

    let mut config = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    // websockets run over HTTP/1.1
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}
