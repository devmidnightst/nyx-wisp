use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use wisp_core::Frame;

use crate::error::Result;

pub(crate) fn frame_message(frame: &Frame) -> Message {
    Message::Binary(frame.encode())
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
