use bytes::Bytes;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use wisp_core::Frame;

use crate::error::Result;

pub(crate) fn frame_message(frame: &Frame) -> Message {
    Message::Binary(frame.encode().into())
}

pub(crate) async fn send_frame<S>(ws: &mut WebSocketStream<S>, frame: &Frame) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(frame_message(frame)).await?;
    Ok(())
}

/// Next wisp frame, skipping ping/pong/text. `None` once the websocket is closed.
pub(crate) async fn recv_frame<S>(ws: &mut WebSocketStream<S>) -> Result<Option<Frame>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ws.next().await {
            None => return Ok(None),
            Some(Err(err)) => return Err(err.into()),
            Some(Ok(Message::Binary(bytes))) => return Ok(Some(Frame::decode(&bytes)?)),
            Some(Ok(Message::Close(_))) => return Ok(None),
            Some(Ok(_)) => continue,
        }
    }
}

/// Splits a DATA frame into its stream id and payload. The payload is a view into the message
/// it arrived in, so nothing is copied. Any other frame, or a buffer too short to be a frame, is
/// handed back untouched for [`Frame::decode`].
pub(crate) fn split_data(bytes: Bytes) -> std::result::Result<(u32, Bytes), Bytes> {
    if bytes.len() >= 5 && bytes[0] == wisp_core::PacketType::Data.as_u8() {
        let stream_id = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        Ok((stream_id, bytes.slice(5..)))
    } else {
        Err(bytes)
    }
}

/// Messages queued before a flush. Batching them means one write syscall for many frames
/// instead of one per frame.
const MAX_BATCH: usize = 64;

/// Something for a connection's writer to do.
#[derive(Debug)]
pub(crate) enum Outgoing {
    Message(Message),
    /// Close the websocket and stop writing.
    Shutdown,
}

/// Builds a DATA frame message straight from a payload slice, with a single copy.
pub(crate) fn data_message(stream_id: u32, payload: &[u8]) -> Message {
    let mut bytes = Vec::with_capacity(5 + payload.len());
    bytes.extend_from_slice(&Frame::data_header(stream_id));
    bytes.extend_from_slice(payload);
    Message::Binary(bytes.into())
}

/// Drains both queues into the websocket until the connection ends. Control messages go first.
/// Everything already queued is fed before a single flush.
///
/// Runs next to the reader instead of taking turns with it, so the websocket keeps being read
/// while a write waits on a slow peer. Taking turns deadlocks as soon as both peers wait to write
/// to each other.
pub(crate) async fn write_loop<S>(
    sink: &mut SplitSink<WebSocketStream<S>, Message>,
    ctrl_rx: &mut mpsc::UnboundedReceiver<Outgoing>,
    out_rx: &mut mpsc::Receiver<Outgoing>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let first = tokio::select! {
            biased;
            Some(item) = ctrl_rx.recv() => item,
            item = out_rx.recv() => match item {
                Some(item) => item,
                // every sender is gone, nothing can use this connection any more
                None => {
                    let _ = sink.close().await;
                    return;
                }
            },
        };

        let mut next = Some(first);
        let mut batched = 0;
        while let Some(item) = next.take() {
            match item {
                Outgoing::Message(message) => {
                    if sink.feed(message).await.is_err() {
                        return;
                    }
                }
                Outgoing::Shutdown => {
                    let _ = sink.close().await;
                    return;
                }
            }
            batched += 1;
            if batched < MAX_BATCH {
                next = ctrl_rx.try_recv().ok().or_else(|| out_rx.try_recv().ok());
            }
        }

        if sink.flush().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_core::Packet;

    #[test]
    fn split_data_keeps_the_payload_in_place() {
        let encoded = Bytes::from(Frame::new(77, Packet::Data { payload: b"hello".to_vec() }).encode());
        let (stream_id, payload) = split_data(encoded.clone()).unwrap();
        assert_eq!(stream_id, 77);
        assert_eq!(payload, &b"hello"[..]);
        // same allocation, just offset past the header
        assert_eq!(payload.as_ptr(), encoded[5..].as_ptr());
    }

    #[test]
    fn split_data_hands_back_other_frames() {
        let encoded = Bytes::from(Frame::new(1, Packet::Continue { buffer_remaining: 3 }).encode());
        assert_eq!(split_data(encoded.clone()).unwrap_err(), encoded);
        assert_eq!(split_data(Bytes::from_static(&[2, 0])).unwrap_err(), &[2, 0][..]);
    }

    #[test]
    fn data_message_matches_frame_encoding() {
        let Message::Binary(bytes) = data_message(5, b"abc") else {
            panic!("expected a binary message");
        };
        assert_eq!(bytes, Frame::new(5, Packet::Data { payload: b"abc".to_vec() }).encode());
    }
}
