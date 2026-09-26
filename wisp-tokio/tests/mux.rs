//! runs the library's server and client against each other over real sockets

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

use wisp_core::{CloseReason, Frame, Packet, WispVersion};
use wisp_tokio::client::{self, ClientConfig, ClientMux, KeyCredentials, PasswordCredentials};
use wisp_tokio::server::{self, KeyAuth, PasswordAuth, ServerConfig};
use wisp_tokio::Error;

const WAIT: Duration = Duration::from_secs(10);

async fn start_server(config: ServerConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(config);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let config = config.clone();
            tokio::spawn(async move {
                let _ = server::accept(socket, config).await;
            });
        }
    });
    addr
}

async fn connect(addr: SocketAddr, config: ClientConfig) -> Result<ClientMux, Error> {
    let request = client::request(&format!("ws://{addr}/")).unwrap();
    let (ws, _) = tokio_tungstenite::connect_async(request).await?;
    ClientMux::new(ws, config).await
}

async fn default_pair() -> ClientMux {
    let addr = start_server(ServerConfig::default()).await;
    connect(addr, ClientConfig::default()).await.unwrap()
}

async fn tcp_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

async fn udp_echo_server() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    port
}

fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// writes `data` and reads the same amount back concurrently, so a full window can't deadlock
async fn echo_through(mux: &ClientMux, port: u16, data: Vec<u8>) -> Vec<u8> {
    let stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let len = data.len();
    let writer = tokio::spawn(async move {
        write.write_all(&data).await.unwrap();
        write
    });
    let mut received = vec![0u8; len];
    timeout(WAIT, read.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    writer.await.unwrap();
    received
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn handshake_reports_server_info() {
    let addr = start_server(ServerConfig {
        buffer_size: 42,
        motd: Some("welcome".into()),
        ..ServerConfig::default()
    })
    .await;
    let mux = connect(addr, ClientConfig::default()).await.unwrap();
    let info = mux.info();
    assert_eq!(info.version, WispVersion::V2);
    assert_eq!(info.buffer_size, 42);
    assert_eq!(info.motd.as_deref(), Some("welcome"));
    assert!(info.udp);
    assert!(info.stream_confirmation);
}

#[tokio::test]
async fn features_are_only_negotiated_when_both_sides_support_them() {
    let addr = start_server(ServerConfig::default()).await;
    let mux = connect(
        addr,
        ClientConfig {
            udp: false,
            stream_confirmation: false,
            ..ClientConfig::default()
        },
    )
    .await
    .unwrap();
    assert!(!mux.info().udp);
    assert!(!mux.info().stream_confirmation);

    let addr = start_server(ServerConfig {
        udp: false,
        stream_confirmation: false,
        ..ServerConfig::default()
    })
    .await;
    let mux = connect(addr, ClientConfig::default()).await.unwrap();
    assert!(!mux.info().udp);
    assert!(!mux.info().stream_confirmation);
}

#[tokio::test]
async fn tcp_stream_round_trip() {
    let mux = default_pair().await;
    let port = tcp_echo_server().await;
    let data = b"hello over wisp".to_vec();
    assert_eq!(echo_through(&mux, port, data.clone()).await, data);
}

#[tokio::test]
async fn large_transfer_respects_a_tiny_window() {
    let addr = start_server(ServerConfig {
        buffer_size: 2,
        ..ServerConfig::default()
    })
    .await;
    let port = tcp_echo_server().await;
    for stream_confirmation in [true, false] {
        let mux = connect(
            addr,
            ClientConfig {
                stream_confirmation,
                ..ClientConfig::default()
            },
        )
        .await
        .unwrap();
        let data = pattern(4 * 1024 * 1024);
        assert_eq!(echo_through(&mux, port, data.clone()).await, data);
    }
}

#[tokio::test]
async fn many_concurrent_streams() {
    let mux = default_pair().await;
    let port = tcp_echo_server().await;
    let mut tasks = Vec::new();
    for i in 0..64u32 {
        let mux = mux.clone();
        tasks.push(tokio::spawn(async move {
            let data = format!("stream number {i}").repeat(100).into_bytes();
            assert_eq!(echo_through(&mux, port, data.clone()).await, data);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn confirmation_surfaces_connect_failures_from_open() {
    let mux = default_pair().await;
    match mux.open_tcp("127.0.0.1", closed_port()).await {
        Err(Error::StreamClosed(CloseReason::ConnectionRefused)) => {}
        other => panic!("expected a refused stream, got {other:?}"),
    }
    match mux.open_tcp("does-not-exist.invalid", 80).await {
        Err(Error::StreamClosed(CloseReason::HostUnreachable)) => {}
        other => panic!("expected an unreachable host, got {other:?}"),
    }
    assert_eq!(mux.stream_count(), 0);
}

#[tokio::test]
async fn without_confirmation_connect_failures_show_up_on_read() {
    let addr = start_server(ServerConfig::default()).await;
    let mux = connect(
        addr,
        ClientConfig {
            stream_confirmation: false,
            ..ClientConfig::default()
        },
    )
    .await
    .unwrap();
    let mut stream = mux.open_tcp("127.0.0.1", closed_port()).await.unwrap();
    let mut buf = [0u8; 8];
    let err = timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(stream.close_reason(), Some(CloseReason::ConnectionRefused));
}

#[tokio::test]
async fn upstream_eof_reads_as_eof() {
    let mux = default_pair().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"bye").await.unwrap();
    });

    let mut stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    let mut received = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut received)).await.unwrap().unwrap();
    assert_eq!(received, b"bye");
    assert_eq!(stream.close_reason(), Some(CloseReason::Voluntary));
    assert!(stream.write_all(b"too late").await.is_err());
}

#[tokio::test]
async fn dropping_a_stream_closes_the_upstream_socket() {
    let mux = default_pair().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    let (mut upstream, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
    assert_eq!(mux.stream_count(), 1);
    drop(stream);
    assert_eq!(mux.stream_count(), 0);

    let mut buf = [0u8; 8];
    let read = timeout(WAIT, upstream.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn shutdown_delivers_pending_data_before_closing() {
    let mux = default_pair().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        received
    });

    let mut stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    let data = pattern(256 * 1024);
    stream.write_all(&data).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(timeout(WAIT, received).await.unwrap().unwrap(), data);
}

#[tokio::test]
async fn udp_packets_keep_their_boundaries() {
    let mux = default_pair().await;
    let port = udp_echo_server().await;
    let mut stream = mux.open_udp("127.0.0.1", port).await.unwrap();
    assert_eq!(stream.send_window(), None);
    for payload in [&b"one"[..], b"two two", b"three three three"] {
        stream.send_packet(payload).await.unwrap();
        let echoed = timeout(WAIT, stream.recv_packet()).await.unwrap().unwrap();
        assert_eq!(echoed.as_deref(), Some(payload));
    }
}

#[tokio::test]
async fn udp_is_refused_when_the_server_disables_it() {
    let addr = start_server(ServerConfig {
        udp: false,
        ..ServerConfig::default()
    })
    .await;
    let mux = connect(addr, ClientConfig::default()).await.unwrap();
    assert!(matches!(mux.open_udp("127.0.0.1", 53).await, Err(Error::UdpNotSupported)));
}

#[tokio::test]
async fn password_auth() {
    let addr = start_server(ServerConfig {
        password_auth: Some(PasswordAuth {
            username: "user".into(),
            password: "hunter2".into(),
            required: true,
        }),
        ..ServerConfig::default()
    })
    .await;
    let creds = |password: &str| ClientConfig {
        password: Some(PasswordCredentials {
            username: "user".into(),
            password: password.into(),
        }),
        ..ClientConfig::default()
    };

    assert!(connect(addr, creds("hunter2")).await.is_ok());
    assert!(matches!(
        connect(addr, creds("wrong")).await,
        Err(Error::Rejected(CloseReason::AuthFailedCredentials))
    ));
    assert!(matches!(
        connect(addr, ClientConfig::default()).await,
        Err(Error::MissingCredentials)
    ));
}

#[tokio::test]
async fn key_auth() {
    let allowed = SigningKey::from_bytes(&[5; 32]);
    let addr = start_server(ServerConfig {
        key_auth: Some(KeyAuth {
            allowed_keys: vec![allowed.verifying_key()],
            required: true,
        }),
        ..ServerConfig::default()
    })
    .await;
    let creds = |signing_key: SigningKey| ClientConfig {
        key: Some(KeyCredentials {
            username: "user".into(),
            signing_key,
        }),
        ..ClientConfig::default()
    };

    assert!(connect(addr, creds(allowed.clone())).await.is_ok());
    assert!(matches!(
        connect(addr, creds(SigningKey::from_bytes(&[6; 32]))).await,
        Err(Error::Rejected(CloseReason::AuthFailedSignature))
    ));
}

#[tokio::test]
async fn username_longer_than_255_bytes_is_rejected_locally() {
    let addr = start_server(ServerConfig::default()).await;
    let config = ClientConfig {
        password: Some(PasswordCredentials {
            username: "x".repeat(256),
            password: "p".into(),
        }),
        ..ClientConfig::default()
    };
    assert!(matches!(connect(addr, config).await, Err(Error::UsernameTooLong)));
}

#[tokio::test]
async fn closing_the_mux_ends_its_streams() {
    let mux = default_pair().await;
    let port = tcp_echo_server().await;
    let mut stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    mux.close();

    let mut buf = [0u8; 8];
    let err = timeout(WAIT, stream.read(&mut buf)).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
    assert!(mux.is_closed());
    assert!(matches!(mux.open_tcp("127.0.0.1", port).await, Err(Error::MuxClosed)));
}

#[tokio::test]
async fn silent_clients_are_dropped_after_the_handshake_timeout() {
    let addr = start_server(ServerConfig {
        handshake_timeout: Duration::from_millis(200),
        ..ServerConfig::default()
    })
    .await;
    let request = client::request(&format!("ws://{addr}/")).unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    // the server's INFO arrives, then nothing we send, then the connection ends
    let first = timeout(WAIT, ws.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(
        Frame::decode(&first.into_data()).unwrap().packet,
        Packet::Info { .. }
    ));
    let ended = timeout(Duration::from_secs(3), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "server kept a silent client around past the handshake timeout");
    let _ = ws.close(None).await;
}

#[tokio::test]
async fn v1_clients_are_served_without_an_info_exchange() {
    let addr = start_server(ServerConfig {
        buffer_size: 3,
        ..ServerConfig::default()
    })
    .await;
    let port = tcp_echo_server().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/")).await.unwrap();

    let first = timeout(WAIT, ws.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(
        Frame::decode(&first.into_data()).unwrap(),
        Frame::new(0, Packet::Continue { buffer_remaining: 3 })
    );

    let connect = Frame::new(
        1,
        Packet::Connect {
            stream_type: wisp_core::StreamType::Tcp,
            destination_port: port,
            destination_hostname: "127.0.0.1".into(),
        },
    );
    ws.send(Message::Binary(connect.encode())).await.unwrap();
    ws.send(Message::Binary(Frame::new(1, Packet::Data { payload: b"v1".to_vec() }).encode()))
        .await
        .unwrap();
    let message = timeout(WAIT, ws.next()).await.unwrap().unwrap().unwrap();
    let frame = Frame::decode(&message.into_data()).unwrap();
    // v1 has no stream open confirmation, so the first thing back is the echo
    assert_eq!(frame, Frame::new(1, Packet::Data { payload: b"v1".to_vec() }));
}
