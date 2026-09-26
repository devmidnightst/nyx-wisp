use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use wisp_core::{CloseReason, Frame, Packet};

use super::Shared;
use crate::ws::frame_message;

/// Something for the driver task to do.
#[derive(Debug)]
pub(crate) enum Command {
    Frame(Frame),
    Shutdown,
}

/// What a stream's reader sees.
#[derive(Debug)]
pub(crate) enum StreamEvent {
    Data(Vec<u8>),
    Closed(CloseReason),
    /// The websocket went away.
    ConnectionLost,
}

/// Per stream send window, shared between the driver (which applies CONTINUE) and the stream's
/// writer. `None` for UDP streams, which have no window.
pub(crate) struct FlowState {
    inner: Mutex<FlowInner>,
}

struct FlowInner {
    remaining: Option<u32>,
    closed: bool,
    waker: Option<Waker>,
}

/// Result of asking for room to send one DATA packet.
pub(crate) enum Window {
    Open,
    Exhausted,
    Closed,
}

impl FlowState {
    pub(crate) fn new(remaining: Option<u32>) -> Self {
        FlowState {
            inner: Mutex::new(FlowInner {
                remaining,
                closed: false,
                waker: None,
            }),
        }
    }

    /// Whether a DATA packet may be sent now. When not, `waker` is woken once that changes.
    pub(crate) fn check(&self, waker: &Waker) -> Window {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return Window::Closed;
        }
        match inner.remaining {
            Some(0) => {
                inner.waker = Some(waker.clone());
                Window::Exhausted
            }
            _ => Window::Open,
        }
    }

    pub(crate) fn consume(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(remaining) = inner.remaining.as_mut() {
            *remaining = remaining.saturating_sub(1);
        }
    }

    pub(crate) fn remaining(&self) -> Option<u32> {
        self.inner.lock().unwrap().remaining
    }

    fn on_continue(&self, buffer_remaining: u32) {
        let mut inner = self.inner.lock().unwrap();
        if inner.remaining.is_some() {
            inner.remaining = Some(buffer_remaining);
        }
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
    }

    pub(crate) fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
    }
}

pub(crate) struct StreamSlot {
    pub(crate) token: u64,
    pub(crate) events: mpsc::UnboundedSender<StreamEvent>,
    pub(crate) flow: Arc<FlowState>,
    /// Set while `open` waits for the stream open confirmation.
    pub(crate) confirm: Option<oneshot::Sender<Result<(), CloseReason>>>,
}

pub(crate) async fn run<S>(
    mut ws: WebSocketStream<S>,
    shared: Arc<Shared>,
    mut out_rx: mpsc::Receiver<Command>,
    mut ctrl_rx: mpsc::UnboundedReceiver<Command>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            incoming = ws.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Ok(frame) = Frame::decode(&bytes) {
                            handle_frame(frame, &shared);
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            // control commands (shutdown, closes from dropped streams when the data queue was
            // full) have their own unbounded queue so they never wait behind data
            Some(command) = ctrl_rx.recv() => {
                if !send_command(&mut ws, command).await {
                    break;
                }
            }
            command = out_rx.recv() => {
                // every sender lives in a ClientMux or a WispStream, so once they are all gone
                // nothing can use this connection any more
                let Some(command) = command else {
                    let _ = ws.close(None).await;
                    break;
                };
                if !send_command(&mut ws, command).await {
                    break;
                }
            }
        }
    }

    shared.closed.store(true, Ordering::SeqCst);
    let slots: Vec<StreamSlot> = shared.streams.lock().unwrap().drain().map(|(_, slot)| slot).collect();
    for mut slot in slots {
        slot.flow.close();
        let _ = slot.events.send(StreamEvent::ConnectionLost);
        if let Some(confirm) = slot.confirm.take() {
            drop(confirm);
        }
    }
}

/// Sends a command's frame; false once the websocket is unusable or a shutdown was requested.
async fn send_command<S>(ws: &mut WebSocketStream<S>, command: Command) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match command {
        Command::Frame(frame) => ws.send(frame_message(&frame)).await.is_ok(),
        Command::Shutdown => {
            let _ = ws.close(None).await;
            false
        }
    }
}

fn handle_frame(frame: Frame, shared: &Shared) {
    if frame.stream_id == 0 {
        return;
    }
    let mut streams = shared.streams.lock().unwrap();
    let Some(slot) = streams.get_mut(&frame.stream_id) else {
        return;
    };

    match frame.packet {
        Packet::Data { payload } => {
            let _ = slot.events.send(StreamEvent::Data(payload));
        }
        Packet::Continue { buffer_remaining } => {
            slot.flow.on_continue(buffer_remaining);
            if let Some(confirm) = slot.confirm.take() {
                let _ = confirm.send(Ok(()));
            }
        }
        Packet::Close { reason } => {
            let mut slot = streams.remove(&frame.stream_id).unwrap();
            slot.flow.close();
            let _ = slot.events.send(StreamEvent::Closed(reason));
            if let Some(confirm) = slot.confirm.take() {
                let _ = confirm.send(Err(reason));
            }
        }
        Packet::Connect { .. } | Packet::Info { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

    struct CountingWaker(std::sync::atomic::AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn waker() -> (Arc<CountingWaker>, Waker) {
        let counter = Arc::new(CountingWaker(Default::default()));
        (counter.clone(), Waker::from(counter))
    }

    #[test]
    fn window_blocks_at_zero_and_reopens_on_continue() {
        let (counter, waker) = waker();
        let flow = FlowState::new(Some(1));
        assert!(matches!(flow.check(&waker), Window::Open));
        flow.consume();
        assert!(matches!(flow.check(&waker), Window::Exhausted));
        flow.on_continue(5);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert!(matches!(flow.check(&waker), Window::Open));
        assert_eq!(flow.remaining(), Some(5));
    }

    #[test]
    fn udp_window_is_unlimited() {
        let (_, waker) = waker();
        let flow = FlowState::new(None);
        for _ in 0..1000 {
            assert!(matches!(flow.check(&waker), Window::Open));
            flow.consume();
        }
        flow.on_continue(3);
        assert_eq!(flow.remaining(), None);
    }

    #[test]
    fn closing_wakes_a_blocked_writer() {
        let (counter, waker) = waker();
        let flow = FlowState::new(Some(0));
        assert!(matches!(flow.check(&waker), Window::Exhausted));
        flow.close();
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert!(matches!(flow.check(&waker), Window::Closed));
    }
}
