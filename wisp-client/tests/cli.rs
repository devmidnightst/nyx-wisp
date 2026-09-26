//! runs the real nyx-client binary against an in-process wisp server

use std::net::SocketAddr;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;

use wisp_tokio::server::{self, PasswordAuth, ServerConfig};

const WAIT: Duration = Duration::from_secs(10);

async fn start_server(config: ServerConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(config);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                let _ = server::accept(socket, config).await;
            });
        }
    });
    addr
}

async fn start_tls_server(config: ServerConfig, cert: &rcgen::CertifiedKey) -> SocketAddr {
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let tls_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(config);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let config = config.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(socket) = acceptor.accept(socket).await {
                    let _ = server::accept(socket, config).await;
                }
            });
        }
    });
    addr
}

async fn tcp_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

/// runs nyx-client with `args`, feeds it `input`, keeps stdin open for a moment so replies can
/// arrive, then closes stdin and collects the output
async fn run_client(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nyx-client"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    let hold = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(stdin);
    });
    let output = timeout(WAIT, child.wait_with_output())
        .await
        .expect("nyx-client did not exit")
        .unwrap();
    hold.abort();
    output
}

#[tokio::test]
async fn tcp_stream_echoes_stdin_to_stdout() {
    let addr = start_server(ServerConfig::default()).await;
    let echo = tcp_echo_server().await;
    let output = run_client(
        &[&format!("ws://{addr}/"), "--tcp", &format!("127.0.0.1:{echo}")],
        b"hello from stdin\n",
    )
    .await;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"hello from stdin\n");
}

#[tokio::test]
async fn motd_is_printed_to_stderr() {
    let addr = start_server(ServerConfig {
        motd: Some("be nice".into()),
        ..ServerConfig::default()
    })
    .await;
    let echo = tcp_echo_server().await;
    let output = run_client(&[&format!("ws://{addr}/"), "--tcp", &format!("127.0.0.1:{echo}")], b"").await;
    assert!(String::from_utf8_lossy(&output.stderr).contains("motd: be nice"));
}

#[tokio::test]
async fn refused_connect_is_reported() {
    let addr = start_server(ServerConfig::default()).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let output = run_client(&[&format!("ws://{addr}/"), "--tcp", &format!("127.0.0.1:{closed}")], b"").await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ConnectionRefused"), "{stderr}");
}

#[tokio::test]
async fn password_auth_flags() {
    let addr = start_server(ServerConfig {
        password_auth: Some(PasswordAuth {
            username: "user".into(),
            password: "pw".into(),
            required: true,
        }),
        ..ServerConfig::default()
    })
    .await;
    let echo = tcp_echo_server().await;
    let url = format!("ws://{addr}/");
    let target = format!("127.0.0.1:{echo}");

    let output = run_client(&[&url, "--tcp", &target, "--username", "user", "--password", "pw"], b"ok").await;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"ok");

    let output = run_client(&[&url, "--tcp", &target], b"").await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no usable credentials"));

    let output = run_client(&[&url, "--tcp", &target, "--username", "user", "--password", "nope"], b"").await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("AuthFailedCredentials"));
}

#[tokio::test]
async fn wss_works_with_a_custom_ca() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let addr = start_tls_server(ServerConfig::default(), &cert).await;
    let echo = tcp_echo_server().await;

    let dir = std::env::temp_dir().join(format!("nyx-client-ca-{}-{}", std::process::id(), addr.port()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, cert.cert.pem()).unwrap();

    let url = format!("wss://localhost:{}/", addr.port());
    let target = format!("127.0.0.1:{echo}");
    let output = run_client(&[&url, "--tcp", &target, "--ca-cert", ca_path.to_str().unwrap()], b"secure").await;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, b"secure");

    // without the CA the self-signed certificate must be refused
    let output = run_client(&[&url, "--tcp", &target], b"").await;
    assert!(!output.status.success());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn target_must_be_given_exactly_once() {
    let output = run_client(&["ws://127.0.0.1:1/"], b"").await;
    assert!(!output.status.success());
    let output = run_client(&["ws://127.0.0.1:1/", "--tcp", "a:1", "--udp", "b:2"], b"").await;
    assert!(!output.status.success());
}
