mod cli;
mod proto;

use clap::Parser;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use cli::Args;
use wisp_core::flow_control::ClientFlowControl;
use wisp_core::{CloseReason, Frame, Packet, StreamType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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

    let key_auth_seed = match &args.key_auth_privkey {
        Some(hex_seed) => {
            let bytes = hex::decode(hex_seed)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "--key-auth-privkey must be 32 bytes, hex encoded")?;
            Some(bytes)
        }
        None => None,
    };

    // the spec only uses v2 when Sec-WebSocket-Protocol is present, its value is unspecified
    let mut request = args.url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("sec-websocket-protocol", HeaderValue::from_static("wisp-v2"));
    let (mut ws, _) = connect_async(request).await?;

    let negotiated = proto::perform_client_handshake(
        &mut ws,
        proto::Credentials {
            username: args.username.as_deref(),
            password: args.password.as_deref(),
            key_auth_seed,
        },
    )
    .await?;

    if let Some(motd) = &negotiated.motd {
        eprintln!("motd: {motd}");
    }

    let stream_id: u32 = loop {
        let candidate: u32 = rand::thread_rng().gen();
        if candidate != 0 {
            break candidate;
        }
    };

    proto::send_frame(
        &mut ws,
        &Frame::new(
            stream_id,
            Packet::Connect {
                stream_type,
                destination_port: port,
                destination_hostname: host,
            },
        ),
    )
    .await?;

    let mut flow = match stream_type {
        StreamType::Tcp => Some(ClientFlowControl::new(negotiated.buffer_remaining)),
        StreamType::Udp => None,
    };

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut read_buf = vec![0u8; 8192];

    loop {
        let can_send = flow.as_ref().map(ClientFlowControl::can_send).unwrap_or(true);
        tokio::select! {
            read = stdin.read(&mut read_buf), if can_send => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(flow) = flow.as_mut() {
                            let _ = flow.on_send();
                        }
                        proto::send_frame(
                            &mut ws,
                            &Frame::new(stream_id, Packet::Data { payload: read_buf[..n].to_vec() }),
                        )
                        .await?;
                    }
                    Err(_) => break,
                }
            }
            incoming = proto::recv_frame(&mut ws) => {
                match incoming {
                    Ok(Some(frame)) if frame.stream_id == stream_id => match frame.packet {
                        Packet::Data { payload } => {
                            stdout.write_all(&payload).await?;
                            stdout.flush().await?;
                        }
                        Packet::Continue { buffer_remaining } => {
                            if let Some(flow) = flow.as_mut() {
                                flow.on_continue(buffer_remaining);
                            }
                        }
                        Packet::Close { reason } => {
                            eprintln!("stream closed: {reason:?}");
                            break;
                        }
                        _ => {}
                    },
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }

    let _ = proto::send_frame(
        &mut ws,
        &Frame::new(
            stream_id,
            Packet::Close {
                reason: CloseReason::Voluntary,
            },
        ),
    )
    .await;

    Ok(())
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
