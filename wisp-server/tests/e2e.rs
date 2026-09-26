//! end to end tests that run the real nyx-server binary and talk wisp to it over a websocket

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use wisp_core::extension::{extension_id, KeyAuthClient, KeyAuthServer, PasswordAuthClient, SIGNATURE_ALGORITHM_ED25519};
use wisp_core::{CloseReason, ExtensionMeta, Frame, Packet, StreamType, WispVersion};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const WAIT: Duration = Duration::from_secs(5);

struct Server {
    child: Child,
    addr: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_server(args: &[&str]) -> Server {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nyx-server"))
        .arg("--bind")
        .arg(addr.to_string())
        .args(args)
        .stdout(Stdio::null())
        .spawn()
        .expect("failed to start nyx-server");
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return Server { child, addr };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("nyx-server never started listening on {addr}");
}

async fn ws_connect(server: &Server, subprotocol: Option<&'static str>) -> Ws {
    let mut request = format!("ws://{}/", server.addr).into_client_request().unwrap();
    if let Some(subprotocol) = subprotocol {
        request
            .headers_mut()
            .insert("sec-websocket-protocol", HeaderValue::from_static(subprotocol));
    }
    let (ws, _) = timeout(WAIT, tokio_tungstenite::connect_async(request))
        .await
        .expect("websocket connect timed out")
        .expect("websocket connect failed");
    ws
}

async fn send(ws: &mut Ws, stream_id: u32, packet: Packet) {
    ws.send(Message::Binary(Frame::new(stream_id, packet).encode()))
        .await
        .unwrap();
}

async fn recv(ws: &mut Ws) -> Option<Frame> {
    loop {
        match timeout(WAIT, ws.next()).await.expect("timed out waiting for a frame") {
            Some(Ok(Message::Binary(bytes))) => return Some(Frame::decode(&bytes).unwrap()),
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return None,
            Some(Ok(_)) => continue,
        }
    }
}

async fn recv_for(ws: &mut Ws, stream_id: u32) -> Packet {
    loop {
        let frame = recv(ws).await.expect("connection closed");
        if frame.stream_id == stream_id {
            return frame.packet;
        }
    }
}

async fn recv_server_info(ws: &mut Ws) -> Vec<ExtensionMeta> {
    let frame = recv(ws).await.expect("no server INFO");
    assert_eq!(frame.stream_id, 0);
    match frame.packet {
        Packet::Info { version, extensions } => {
            assert_eq!(version.major, 2);
            extensions
        }
        other => panic!("expected INFO, got {other:?}"),
    }
}

async fn send_client_info(ws: &mut Ws, extensions: Vec<ExtensionMeta>) {
    send(
        ws,
        0,
        Packet::Info {
            version: WispVersion::V2,
            extensions,
        },
    )
    .await;
}

/// runs the v2 handshake with the given client extensions and returns the server's reply on stream 0
async fn handshake(ws: &mut Ws, extensions: Vec<ExtensionMeta>) -> Packet {
    recv_server_info(ws).await;
    send_client_info(ws, extensions).await;
    let frame = recv(ws).await.expect("no handshake reply");
    assert_eq!(frame.stream_id, 0);
    frame.packet
}

async fn established(server: &Server) -> (Ws, u32) {
    let mut ws = ws_connect(server, Some("wisp-v2")).await;
    match handshake(&mut ws, vec![ExtensionMeta::new(extension_id::UDP, vec![])]).await {
        Packet::Continue { buffer_remaining } => (ws, buffer_remaining),
        other => panic!("handshake failed: {other:?}"),
    }
}

fn connect(stream_type: StreamType, addr: &str, port: u16) -> Packet {
    Packet::Connect {
        stream_type,
        destination_port: port,
        destination_hostname: addr.to_string(),
    }
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
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
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
    // bind then drop so nothing is listening there
    free_port()
}

#[tokio::test]
async fn server_echoes_requested_subprotocol() {
    let server = start_server(&[]).await;
    let mut request = format!("ws://{}/", server.addr).into_client_request().unwrap();
    request
        .headers_mut()
        .insert("sec-websocket-protocol", HeaderValue::from_static("wisp-v2, other"));
    let (_, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        "wisp-v2"
    );
}

#[tokio::test]
async fn v2_handshake_sends_info_then_continue_with_buffer_size() {
    let server = start_server(&["--buffer-size", "7", "--motd", "hi there"]).await;
    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    let extensions = recv_server_info(&mut ws).await;
    assert!(extensions.iter().any(|ext| ext.id == extension_id::UDP));
    let motd = extensions
        .iter()
        .find(|ext| ext.id == extension_id::MOTD)
        .expect("motd extension missing");
    assert_eq!(motd.data, b"hi there");

    send_client_info(&mut ws, vec![]).await;
    let frame = recv(&mut ws).await.unwrap();
    assert_eq!(frame, Frame::new(0, Packet::Continue { buffer_remaining: 7 }));
}

#[tokio::test]
async fn v1_client_without_subprotocol_gets_continue_and_can_proxy() {
    let server = start_server(&["--buffer-size", "9"]).await;
    let echo = tcp_echo_server().await;
    let mut ws = ws_connect(&server, None).await;
    let frame = recv(&mut ws).await.unwrap();
    assert_eq!(frame, Frame::new(0, Packet::Continue { buffer_remaining: 9 }));

    send(&mut ws, 5, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    send(&mut ws, 5, Packet::Data { payload: b"v1".to_vec() }).await;
    assert_eq!(recv_for(&mut ws, 5).await, Packet::Data { payload: b"v1".to_vec() });
}

#[tokio::test]
async fn tcp_stream_echoes_data_sent_before_connect_finishes() {
    let server = start_server(&["--buffer-size", "4"]).await;
    let echo = tcp_echo_server().await;
    let (mut ws, _) = established(&server).await;

    // CONNECT and DATA go out back to back, without waiting for anything from the server
    send(&mut ws, 7, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    let mut sent = Vec::new();
    for i in 0..3u8 {
        let chunk = vec![b'a' + i; 500];
        sent.extend_from_slice(&chunk);
        send(&mut ws, 7, Packet::Data { payload: chunk }).await;
    }

    let mut got = Vec::new();
    while got.len() < sent.len() {
        match recv_for(&mut ws, 7).await {
            Packet::Data { payload } => got.extend_from_slice(&payload),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got, sent);
}

#[tokio::test]
async fn continue_is_sent_after_a_full_window() {
    let server = start_server(&["--buffer-size", "3"]).await;
    let echo = tcp_echo_server().await;
    let (mut ws, window) = established(&server).await;
    assert_eq!(window, 3);

    send(&mut ws, 1, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    for _ in 0..window {
        send(&mut ws, 1, Packet::Data { payload: b"x".to_vec() }).await;
    }

    let mut echoed = 0;
    let mut continues = Vec::new();
    while echoed < window as usize || continues.is_empty() {
        match recv_for(&mut ws, 1).await {
            Packet::Data { payload } => echoed += payload.len(),
            Packet::Continue { buffer_remaining } => continues.push(buffer_remaining),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(continues, vec![3]);
}

#[tokio::test]
async fn slow_connect_does_not_stall_other_streams() {
    let server = start_server(&[]).await;
    let echo = tcp_echo_server().await;
    let (mut ws, _) = established(&server).await;

    // 10.255.255.1 is a non routable address, so this connect hangs until the server times it out
    send(&mut ws, 1, connect(StreamType::Tcp, "10.255.255.1", 80)).await;
    send(&mut ws, 2, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    send(&mut ws, 2, Packet::Data { payload: b"quick".to_vec() }).await;

    let reply = timeout(Duration::from_secs(2), recv_for(&mut ws, 2))
        .await
        .expect("stream 2 was stalled behind stream 1's connect");
    assert_eq!(reply, Packet::Data { payload: b"quick".to_vec() });
}

#[tokio::test]
async fn stream_ids_can_be_reused_after_close() {
    let server = start_server(&[]).await;
    let echo = tcp_echo_server().await;
    let (mut ws, _) = established(&server).await;

    send(&mut ws, 9, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    send(&mut ws, 9, Packet::Data { payload: b"first".to_vec() }).await;
    assert_eq!(recv_for(&mut ws, 9).await, Packet::Data { payload: b"first".to_vec() });

    send(&mut ws, 9, Packet::Close { reason: CloseReason::Voluntary }).await;
    send(&mut ws, 9, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    send(&mut ws, 9, Packet::Data { payload: b"again".to_vec() }).await;

    // the server must not echo a CLOSE for the old stream or tear down the new one
    assert_eq!(recv_for(&mut ws, 9).await, Packet::Data { payload: b"again".to_vec() });
}

#[tokio::test]
async fn refused_connect_reports_connection_refused() {
    let server = start_server(&[]).await;
    let (mut ws, _) = established(&server).await;
    send(&mut ws, 3, connect(StreamType::Tcp, "127.0.0.1", closed_port())).await;
    assert_eq!(
        recv_for(&mut ws, 3).await,
        Packet::Close { reason: CloseReason::ConnectionRefused }
    );
}

#[tokio::test]
async fn invalid_destination_reports_invalid_info() {
    let server = start_server(&[]).await;
    let (mut ws, _) = established(&server).await;

    send(&mut ws, 4, connect(StreamType::Tcp, "", 80)).await;
    assert_eq!(recv_for(&mut ws, 4).await, Packet::Close { reason: CloseReason::InvalidInfo });

    send(&mut ws, 5, connect(StreamType::Tcp, "127.0.0.1", 0)).await;
    assert_eq!(recv_for(&mut ws, 5).await, Packet::Close { reason: CloseReason::InvalidInfo });
}

#[tokio::test]
async fn unresolvable_host_reports_host_unreachable() {
    let server = start_server(&[]).await;
    let (mut ws, _) = established(&server).await;
    send(&mut ws, 6, connect(StreamType::Tcp, "does-not-exist.invalid", 80)).await;
    assert_eq!(
        recv_for(&mut ws, 6).await,
        Packet::Close { reason: CloseReason::HostUnreachable }
    );
}

#[tokio::test]
async fn upstream_eof_reports_voluntary_close() {
    let server = start_server(&[]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket);
    });

    let (mut ws, _) = established(&server).await;
    send(&mut ws, 8, connect(StreamType::Tcp, "127.0.0.1", port)).await;
    assert_eq!(recv_for(&mut ws, 8).await, Packet::Close { reason: CloseReason::Voluntary });
}

#[tokio::test]
async fn overrunning_the_window_gets_throttled() {
    let server = start_server(&["--buffer-size", "1"]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // accept but never read, so writes back up once the kernel buffers fill
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let (mut ws, _) = established(&server).await;
    send(&mut ws, 2, connect(StreamType::Tcp, "127.0.0.1", port)).await;
    let big = vec![0u8; 1024 * 1024];
    let mut throttled = false;
    for _ in 0..64 {
        send(&mut ws, 2, Packet::Data { payload: big.clone() }).await;
    }
    while let Some(frame) = timeout(WAIT, recv(&mut ws)).await.ok().flatten() {
        if frame == Frame::new(2, Packet::Close { reason: CloseReason::Throttled }) {
            throttled = true;
            break;
        }
    }
    assert!(throttled, "a client ignoring CONTINUE should be closed with 0x49");
}

#[tokio::test]
async fn udp_stream_echoes_datagrams() {
    let server = start_server(&[]).await;
    let echo = udp_echo_server().await;
    let (mut ws, _) = established(&server).await;
    send(&mut ws, 11, connect(StreamType::Udp, "127.0.0.1", echo)).await;
    send(&mut ws, 11, Packet::Data { payload: b"dgram".to_vec() }).await;
    assert_eq!(recv_for(&mut ws, 11).await, Packet::Data { payload: b"dgram".to_vec() });
}

#[tokio::test]
async fn frames_on_unknown_streams_are_ignored() {
    let server = start_server(&[]).await;
    let echo = tcp_echo_server().await;
    let (mut ws, _) = established(&server).await;

    send(&mut ws, 40, Packet::Data { payload: b"nobody home".to_vec() }).await;
    send(&mut ws, 41, Packet::Close { reason: CloseReason::Voluntary }).await;
    ws.send(Message::Binary(vec![0xff, 1, 2])).await.unwrap();

    // the connection must still work afterwards
    send(&mut ws, 42, connect(StreamType::Tcp, "127.0.0.1", echo)).await;
    send(&mut ws, 42, Packet::Data { payload: b"alive".to_vec() }).await;
    assert_eq!(recv_for(&mut ws, 42).await, Packet::Data { payload: b"alive".to_vec() });
}

#[tokio::test]
async fn upstream_socket_closes_when_websocket_drops() {
    let server = start_server(&[]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (mut ws, _) = established(&server).await;
    send(&mut ws, 1, connect(StreamType::Tcp, "127.0.0.1", port)).await;
    let (mut upstream, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();

    drop(ws);

    let mut buf = [0u8; 16];
    let read = timeout(WAIT, upstream.read(&mut buf))
        .await
        .expect("upstream socket was left open after the websocket went away");
    assert!(matches!(read, Ok(0) | Err(_)));
}

// auth

fn password_ext(username: &str, password: &str) -> ExtensionMeta {
    ExtensionMeta::new(
        extension_id::PASSWORD_AUTH,
        PasswordAuthClient {
            username: username.to_string(),
            password: password.to_string(),
        }
        .encode(),
    )
}

fn key_ext(signing_key: &SigningKey, challenge: &[u8]) -> ExtensionMeta {
    let mut public_key_hash = [0u8; 32];
    public_key_hash.copy_from_slice(&Sha256::digest(signing_key.verifying_key().as_bytes()));
    ExtensionMeta::new(
        extension_id::KEY_AUTH,
        KeyAuthClient {
            username: String::new(),
            selected_algorithm: SIGNATURE_ALGORITHM_ED25519,
            public_key_hash,
            signature: signing_key.sign(challenge).to_bytes().to_vec(),
        }
        .encode(),
    )
}

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}

async fn key_auth_handshake(ws: &mut Ws, key: &SigningKey, mut extra: Vec<ExtensionMeta>) -> Packet {
    let extensions = recv_server_info(ws).await;
    let meta = extensions
        .iter()
        .find(|ext| ext.id == extension_id::KEY_AUTH)
        .expect("server did not offer key auth");
    let server_msg = KeyAuthServer::decode(&meta.data).unwrap();
    assert_eq!(server_msg.supported_algorithms & SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ED25519);
    extra.push(key_ext(key, &server_msg.challenge));
    send_client_info(ws, extra).await;
    recv(ws).await.expect("no handshake reply").packet
}

#[tokio::test]
async fn password_auth_accepts_and_rejects() {
    let server = start_server(&["--username", "user", "--password", "hunter2"]).await;

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert!(matches!(
        handshake(&mut ws, vec![password_ext("user", "hunter2")]).await,
        Packet::Continue { .. }
    ));

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert_eq!(
        handshake(&mut ws, vec![password_ext("user", "wrong")]).await,
        Packet::Close { reason: CloseReason::AuthFailedCredentials }
    );

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert_eq!(
        handshake(&mut ws, vec![]).await,
        Packet::Close { reason: CloseReason::AuthRequired }
    );
}

#[tokio::test]
async fn optional_password_auth_allows_anonymous_but_not_wrong_creds() {
    let server = start_server(&["--username", "user", "--password", "hunter2", "--password-optional"]).await;

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert!(matches!(handshake(&mut ws, vec![]).await, Packet::Continue { .. }));

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert_eq!(
        handshake(&mut ws, vec![password_ext("user", "nope")]).await,
        Packet::Close { reason: CloseReason::AuthFailedCredentials }
    );
}

#[tokio::test]
async fn key_auth_accepts_allowed_key_and_rejects_others() {
    let allowed = test_key(0x11);
    let server = start_server(&["--key-auth-pubkey", &pubkey_hex(&allowed)]).await;

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert!(matches!(
        key_auth_handshake(&mut ws, &allowed, vec![]).await,
        Packet::Continue { .. }
    ));

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert_eq!(
        key_auth_handshake(&mut ws, &test_key(0x22), vec![]).await,
        Packet::Close { reason: CloseReason::AuthFailedSignature }
    );
}

#[tokio::test]
async fn either_auth_method_is_enough_when_both_are_required() {
    let key = test_key(0x33);
    let pubkey = pubkey_hex(&key);
    let args = ["--username", "user", "--password", "pw", "--key-auth-pubkey", &pubkey];
    let server = start_server(&args).await;

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert!(matches!(
        key_auth_handshake(&mut ws, &key, vec![]).await,
        Packet::Continue { .. }
    ));

    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert!(matches!(
        handshake(&mut ws, vec![password_ext("user", "pw")]).await,
        Packet::Continue { .. }
    ));

    // a wrong password still fails even alongside a valid key
    let mut ws = ws_connect(&server, Some("wisp-v2")).await;
    assert_eq!(
        key_auth_handshake(&mut ws, &key, vec![password_ext("user", "bad")]).await,
        Packet::Close { reason: CloseReason::AuthFailedCredentials }
    );
}

#[tokio::test]
async fn v1_is_refused_when_auth_is_required() {
    let server = start_server(&["--username", "user", "--password", "pw"]).await;
    let mut ws = ws_connect(&server, None).await;
    assert_eq!(recv(&mut ws).await, None);
}

#[tokio::test]
// try_wait returning Some already reaps the child, clippy can't see that
#[allow(clippy::zombie_processes)]
async fn zero_buffer_size_is_rejected_at_startup() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nyx-server"))
        .args(["--bind", &format!("127.0.0.1:{}", free_port()), "--buffer-size", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("nyx-server started with --buffer-size 0 instead of refusing it");
}
