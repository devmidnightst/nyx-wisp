use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

use wisp_core::flow_control::ServerFlowControl;
use wisp_core::{CloseReason, Frame, Packet, StreamType};

use crate::proto::WsStream;

struct StreamHandle {
    to_socket: mpsc::UnboundedSender<Vec<u8>>,
    flow: Option<ServerFlowControl>,
}

type StreamMap = Arc<Mutex<HashMap<u32, StreamHandle>>>;

pub async fn run(mut ws: WsStream, buffer_size: u32) {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel::<u32>();

    loop {
        tokio::select! {
            incoming = ws.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Ok(frame) = Frame::decode(&bytes) {
                            handle_frame(frame, &streams, &out_tx, &closed_tx, buffer_size).await;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            outbound = out_rx.recv() => {
                match outbound {
                    Some(message) => {
                        if ws.send(message).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            Some(stream_id) = closed_rx.recv() => {
                streams.lock().await.remove(&stream_id);
            }
        }
    }
}

async fn handle_frame(
    frame: Frame,
    streams: &StreamMap,
    out_tx: &mpsc::UnboundedSender<Message>,
    closed_tx: &mpsc::UnboundedSender<u32>,
    buffer_size: u32,
) {
    let stream_id = frame.stream_id;
    if stream_id == 0 {
        return;
    }

    match frame.packet {
        Packet::Connect {
            stream_type,
            destination_port,
            destination_hostname,
        } => {
            if streams.lock().await.contains_key(&stream_id) {
                return;
            }
            spawn_stream(
                stream_id,
                stream_type,
                destination_hostname,
                destination_port,
                streams.clone(),
                out_tx.clone(),
                closed_tx.clone(),
                buffer_size,
            )
            .await;
        }
        Packet::Data { payload } => {
            let mut continue_buffer = None;
            {
                let mut guard = streams.lock().await;
                if let Some(handle) = guard.get_mut(&stream_id) {
                    let _ = handle.to_socket.send(payload);
                    if let Some(flow) = handle.flow.as_mut() {
                        if flow.on_data_received() {
                            continue_buffer = Some(flow.buffer_size());
                        }
                    }
                }
            }
            if let Some(buffer_remaining) = continue_buffer {
                let _ = out_tx.send(Message::Binary(
                    Frame::new(stream_id, Packet::Continue { buffer_remaining }).encode(),
                ));
            }
        }
        Packet::Close { .. } => {
            streams.lock().await.remove(&stream_id);
        }
        Packet::Continue { .. } | Packet::Info { .. } => {}
    }
}

async fn spawn_stream(
    stream_id: u32,
    stream_type: StreamType,
    destination_hostname: String,
    destination_port: u16,
    streams: StreamMap,
    out_tx: mpsc::UnboundedSender<Message>,
    closed_tx: mpsc::UnboundedSender<u32>,
    buffer_size: u32,
) {
    if destination_hostname.is_empty() || destination_port == 0 {
        let _ = out_tx.send(Message::Binary(
            Frame::new(
                stream_id,
                Packet::Close {
                    reason: CloseReason::InvalidInfo,
                },
            )
            .encode(),
        ));
        return;
    }

    match stream_type {
        StreamType::Tcp => {
            spawn_tcp_stream(
                stream_id,
                destination_hostname,
                destination_port,
                streams,
                out_tx,
                closed_tx,
                buffer_size,
            )
            .await
        }
        StreamType::Udp => {
            spawn_udp_stream(
                stream_id,
                destination_hostname,
                destination_port,
                streams,
                out_tx,
                closed_tx,
            )
            .await
        }
    }
}

fn close_reason_for_io_error(err: &std::io::Error) -> CloseReason {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => CloseReason::ConnectionRefused,
        std::io::ErrorKind::TimedOut => CloseReason::ConnectionTimedOut,
        _ => CloseReason::HostUnreachable,
    }
}

async fn spawn_tcp_stream(
    stream_id: u32,
    hostname: String,
    port: u16,
    streams: StreamMap,
    out_tx: mpsc::UnboundedSender<Message>,
    closed_tx: mpsc::UnboundedSender<u32>,
    buffer_size: u32,
) {
    let connect_result = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((hostname.as_str(), port))).await;

    let socket = match connect_result {
        Ok(Ok(socket)) => socket,
        Ok(Err(err)) => {
            let reason = close_reason_for_io_error(&err);
            let _ = out_tx.send(Message::Binary(Frame::new(stream_id, Packet::Close { reason }).encode()));
            return;
        }
        Err(_) => {
            let _ = out_tx.send(Message::Binary(
                Frame::new(
                    stream_id,
                    Packet::Close {
                        reason: CloseReason::ConnectionTimedOut,
                    },
                )
                .encode(),
            ));
            return;
        }
    };

    let (to_socket_tx, mut to_socket_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    streams.lock().await.insert(
        stream_id,
        StreamHandle {
            to_socket: to_socket_tx,
            flow: Some(ServerFlowControl::new(buffer_size)),
        },
    );

    tokio::spawn(async move {
        let (mut read_half, mut write_half) = socket.into_split();
        let mut read_buf = vec![0u8; 16 * 1024];

        loop {
            tokio::select! {
                incoming = to_socket_rx.recv() => {
                    match incoming {
                        Some(bytes) => {
                            if write_half.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                read = read_half.read(&mut read_buf) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = out_tx.send(Message::Binary(
                                Frame::new(stream_id, Packet::Data { payload: read_buf[..n].to_vec() }).encode(),
                            ));
                        }
                    }
                }
            }
        }

        let _ = out_tx.send(Message::Binary(
            Frame::new(
                stream_id,
                Packet::Close {
                    reason: CloseReason::Voluntary,
                },
            )
            .encode(),
        ));
        streams.lock().await.remove(&stream_id);
        let _ = closed_tx.send(stream_id);
    });
}

async fn spawn_udp_stream(
    stream_id: u32,
    hostname: String,
    port: u16,
    streams: StreamMap,
    out_tx: mpsc::UnboundedSender<Message>,
    closed_tx: mpsc::UnboundedSender<u32>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(_) => {
            let _ = out_tx.send(Message::Binary(
                Frame::new(
                    stream_id,
                    Packet::Close {
                        reason: CloseReason::HostUnreachable,
                    },
                )
                .encode(),
            ));
            return;
        }
    };

    if socket.connect((hostname.as_str(), port)).await.is_err() {
        let _ = out_tx.send(Message::Binary(
            Frame::new(
                stream_id,
                Packet::Close {
                    reason: CloseReason::HostUnreachable,
                },
            )
            .encode(),
        ));
        return;
    }

    let (to_socket_tx, mut to_socket_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    streams.lock().await.insert(
        stream_id,
        StreamHandle {
            to_socket: to_socket_tx,
            flow: None,
        },
    );

    tokio::spawn(async move {
        let mut read_buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                incoming = to_socket_rx.recv() => {
                    match incoming {
                        Some(bytes) => {
                            let _ = socket.send(&bytes).await;
                        }
                        None => break,
                    }
                }
                read = socket.recv(&mut read_buf) => {
                    match read {
                        Ok(n) => {
                            let _ = out_tx.send(Message::Binary(
                                Frame::new(stream_id, Packet::Data { payload: read_buf[..n].to_vec() }).encode(),
                            ));
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        let _ = out_tx.send(Message::Binary(
            Frame::new(
                stream_id,
                Packet::Close {
                    reason: CloseReason::Voluntary,
                },
            )
            .encode(),
        ));
        streams.lock().await.remove(&stream_id);
        let _ = closed_tx.send(stream_id);
    });
}
