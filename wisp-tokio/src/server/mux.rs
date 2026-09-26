use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use wisp_core::flow_control::ServerFlowControl;
use wisp_core::{CloseReason, Frame, Packet, StreamType};

use super::MuxOptions;
use crate::ws::frame_message;

// frames produced by stream tasks queue here before hitting the websocket. bounded so a slow
// websocket pushes back on the upstream sockets instead of buffering without limit.
const OUTBOUND_CAPACITY: usize = 256;

struct StreamHandle {
    // distinguishes this stream from a later one that reuses the same stream id
    generation: u64,
    stream_type: StreamType,
    to_socket: mpsc::Sender<Vec<u8>>,
}

type StreamMap = Arc<Mutex<HashMap<u32, StreamHandle>>>;

struct StreamContext {
    stream_id: u32,
    generation: u64,
    streams: StreamMap,
    out_tx: mpsc::Sender<Message>,
}

impl StreamContext {
    async fn send(&self, packet: Packet) -> bool {
        self.out_tx
            .send(frame_message(&Frame::new(self.stream_id, packet)))
            .await
            .is_ok()
    }

    // removes the stream if it is still ours and, when the close came from the socket side,
    // tells the client. nothing is sent if the client already closed the stream itself.
    async fn finish(self, reason: Option<CloseReason>) {
        let removed = {
            let mut guard = self.streams.lock().await;
            if guard
                .get(&self.stream_id)
                .is_some_and(|handle| handle.generation == self.generation)
            {
                guard.remove(&self.stream_id);
                true
            } else {
                false
            }
        };
        if let (true, Some(reason)) = (removed, reason) {
            self.send(Packet::Close { reason }).await;
        }
    }
}

pub(crate) async fn run<S>(mut ws: WebSocketStream<S>, options: MuxOptions)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // replies generated directly by the reader loop, which must never block on its own output
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<Message>();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(OUTBOUND_CAPACITY);
    let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));
    let mut next_generation: u64 = 0;

    loop {
        tokio::select! {
            incoming = ws.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Ok(frame) = Frame::decode(&bytes) {
                            handle_frame(
                                frame,
                                &streams,
                                &ctrl_tx,
                                &out_tx,
                                &options,
                                &mut next_generation,
                            )
                            .await;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            Some(message) = ctrl_rx.recv() => {
                if ws.send(message).await.is_err() {
                    break;
                }
            }
            Some(message) = out_rx.recv() => {
                if ws.send(message).await.is_err() {
                    break;
                }
            }
        }
    }

    // dropping every sender makes the stream tasks exit and close their upstream sockets
    streams.lock().await.clear();
}

fn close_message(stream_id: u32, reason: CloseReason) -> Message {
    frame_message(&Frame::new(stream_id, Packet::Close { reason }))
}

/// Capacity of a stream's client-to-socket queue. One CONTINUE window, plus a second one when
/// stream open confirmation is on: the confirmation's CONTINUE can reach the client while packets
/// it sent under the initial window are still in flight, so up to two windows can be outstanding.
fn queue_capacity(options: &MuxOptions) -> usize {
    // tokio's bounded channel panics above usize::MAX >> 3 permits
    const MAX_CAPACITY: usize = usize::MAX >> 4;
    let window = options.buffer_size as usize;
    let capacity = if options.stream_confirmation {
        window.saturating_mul(2)
    } else {
        window
    };
    capacity.clamp(1, MAX_CAPACITY)
}

async fn handle_frame(
    frame: Frame,
    streams: &StreamMap,
    ctrl_tx: &mpsc::UnboundedSender<Message>,
    out_tx: &mpsc::Sender<Message>,
    options: &MuxOptions,
    next_generation: &mut u64,
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
            let mut guard = streams.lock().await;
            if guard.contains_key(&stream_id) {
                return;
            }
            if destination_hostname.is_empty()
                || destination_port == 0
                || (stream_type == StreamType::Udp && !options.udp)
            {
                let _ = ctrl_tx.send(close_message(stream_id, CloseReason::InvalidInfo));
                return;
            }

            // the stream is registered before the upstream connect finishes, so DATA the client
            // sends early (the spec allows this) is queued instead of dropped, and a slow connect
            // no longer stalls every other stream on this websocket
            let (to_socket_tx, to_socket_rx) = mpsc::channel::<Vec<u8>>(queue_capacity(options));
            *next_generation += 1;
            let generation = *next_generation;
            guard.insert(
                stream_id,
                StreamHandle {
                    generation,
                    stream_type,
                    to_socket: to_socket_tx,
                },
            );
            drop(guard);

            let ctx = StreamContext {
                stream_id,
                generation,
                streams: streams.clone(),
                out_tx: out_tx.clone(),
            };
            match stream_type {
                StreamType::Tcp => {
                    tokio::spawn(run_tcp_stream(
                        ctx,
                        destination_hostname,
                        destination_port,
                        to_socket_rx,
                        *options,
                    ));
                }
                StreamType::Udp => {
                    tokio::spawn(run_udp_stream(
                        ctx,
                        destination_hostname,
                        destination_port,
                        to_socket_rx,
                    ));
                }
            }
        }
        Packet::Data { payload } => {
            let mut guard = streams.lock().await;
            let Some(handle) = guard.get(&stream_id) else {
                return;
            };
            match handle.to_socket.try_send(payload) {
                Ok(()) | Err(TrySendError::Closed(_)) => {}
                // udp is lossy anyway, drop the datagram rather than buffer without limit
                Err(TrySendError::Full(_)) if handle.stream_type == StreamType::Udp => {}
                // the queue holds every packet the client may have outstanding, so a full queue
                // means it ignored flow control
                Err(TrySendError::Full(_)) => {
                    guard.remove(&stream_id);
                    let _ = ctrl_tx.send(close_message(stream_id, CloseReason::Throttled));
                }
            }
        }
        Packet::Close { .. } => {
            streams.lock().await.remove(&stream_id);
        }
        Packet::Continue { .. } | Packet::Info { .. } => {}
    }
}

fn close_reason_for_io_error(err: &std::io::Error) -> CloseReason {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => CloseReason::ConnectionRefused,
        std::io::ErrorKind::TimedOut => CloseReason::ConnectionTimedOut,
        _ => CloseReason::HostUnreachable,
    }
}

async fn run_tcp_stream(
    ctx: StreamContext,
    hostname: String,
    port: u16,
    mut to_socket_rx: mpsc::Receiver<Vec<u8>>,
    options: MuxOptions,
) {
    let connect_result =
        tokio::time::timeout(options.connect_timeout, TcpStream::connect((hostname.as_str(), port))).await;

    let socket = match connect_result {
        Ok(Ok(socket)) => socket,
        Ok(Err(err)) => return ctx.finish(Some(close_reason_for_io_error(&err))).await,
        Err(_) => return ctx.finish(Some(CloseReason::ConnectionTimedOut)).await,
    };

    // stream open confirmation: tell the client the socket is up. nothing has been written yet,
    // so whatever the client sent early is still queued and comes off the window it gets back.
    if options.stream_confirmation {
        let queued = u32::try_from(to_socket_rx.len()).unwrap_or(u32::MAX);
        let confirmation = Packet::Continue {
            buffer_remaining: options.buffer_size.saturating_sub(queued),
        };
        if !ctx.send(confirmation).await {
            return ctx.finish(None).await;
        }
    }

    let (mut read_half, mut write_half) = socket.into_split();
    let mut read_buf = vec![0u8; 16 * 1024];
    // counted as packets are written out, not as they arrive, so CONTINUE only goes out once
    // the buffer has actually drained
    let mut flow = ServerFlowControl::new(options.buffer_size);

    let reason = loop {
        tokio::select! {
            incoming = to_socket_rx.recv() => {
                match incoming {
                    Some(bytes) => {
                        if write_half.write_all(&bytes).await.is_err() {
                            break Some(CloseReason::NetworkError);
                        }
                        if flow.on_data_received()
                            && !ctx
                                .send(Packet::Continue {
                                    buffer_remaining: flow.buffer_size(),
                                })
                                .await
                        {
                            break None;
                        }
                    }
                    // the client closed the stream or the websocket went away
                    None => break None,
                }
            }
            read = read_half.read(&mut read_buf) => {
                match read {
                    Ok(0) => break Some(CloseReason::Voluntary),
                    Err(_) => break Some(CloseReason::NetworkError),
                    Ok(n) => {
                        if !ctx.send(Packet::Data { payload: read_buf[..n].to_vec() }).await {
                            break None;
                        }
                    }
                }
            }
        }
    };

    ctx.finish(reason).await;
}

async fn run_udp_stream(
    ctx: StreamContext,
    hostname: String,
    port: u16,
    mut to_socket_rx: mpsc::Receiver<Vec<u8>>,
) {
    let addr = match tokio::net::lookup_host((hostname.as_str(), port)).await {
        Ok(mut addrs) => addrs.next(),
        Err(_) => None,
    };
    let Some(addr) = addr else {
        return ctx.finish(Some(CloseReason::HostUnreachable)).await;
    };

    // bind in the same address family as the destination so ipv6 targets work
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(_) => return ctx.finish(Some(CloseReason::NetworkError)).await,
    };
    if socket.connect(addr).await.is_err() {
        return ctx.finish(Some(CloseReason::HostUnreachable)).await;
    }

    let mut read_buf = vec![0u8; 64 * 1024];
    let reason = loop {
        tokio::select! {
            incoming = to_socket_rx.recv() => {
                match incoming {
                    Some(bytes) => {
                        let _ = socket.send(&bytes).await;
                    }
                    None => break None,
                }
            }
            read = socket.recv(&mut read_buf) => {
                match read {
                    Ok(n) => {
                        if !ctx.send(Packet::Data { payload: read_buf[..n].to_vec() }).await {
                            break None;
                        }
                    }
                    Err(_) => break Some(CloseReason::NetworkError),
                }
            }
        }
    };

    ctx.finish(reason).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn options(buffer_size: u32, stream_confirmation: bool) -> MuxOptions {
        MuxOptions {
            buffer_size,
            udp: true,
            stream_confirmation,
            connect_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn queue_holds_one_window_without_confirmation() {
        assert_eq!(queue_capacity(&options(128, false)), 128);
    }

    #[test]
    fn queue_holds_two_windows_with_confirmation() {
        assert_eq!(queue_capacity(&options(128, true)), 256);
    }

    #[test]
    fn queue_capacity_is_clamped() {
        assert_eq!(queue_capacity(&options(0, false)), 1);
        assert!(queue_capacity(&options(u32::MAX, true)) <= usize::MAX >> 4);
    }

    #[test]
    fn io_errors_map_to_close_reasons() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            close_reason_for_io_error(&Error::from(ErrorKind::ConnectionRefused)),
            CloseReason::ConnectionRefused
        );
        assert_eq!(
            close_reason_for_io_error(&Error::from(ErrorKind::TimedOut)),
            CloseReason::ConnectionTimedOut
        );
        assert_eq!(
            close_reason_for_io_error(&Error::from(ErrorKind::Other)),
            CloseReason::HostUnreachable
        );
    }
}
