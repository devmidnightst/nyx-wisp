use crate::error::{Result, WispError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFlowControl {
    buffer_remaining: u32,
}

impl ClientFlowControl {
    pub fn new(initial_buffer_remaining: u32) -> Self {
        ClientFlowControl {
            buffer_remaining: initial_buffer_remaining,
        }
    }

    pub fn buffer_remaining(&self) -> u32 {
        self.buffer_remaining
    }

    pub fn can_send(&self) -> bool {
        self.buffer_remaining > 0
    }

    pub fn on_send(&mut self) -> Result<()> {
        if self.buffer_remaining == 0 {
            return Err(WispError::SendWindowExhausted);
        }
        self.buffer_remaining -= 1;
        Ok(())
    }

    pub fn on_continue(&mut self, buffer_remaining: u32) {
        self.buffer_remaining = buffer_remaining;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerFlowControl {
    buffer_size: u32,
    received_since_continue: u32,
}

impl ServerFlowControl {
    pub fn new(buffer_size: u32) -> Self {
        ServerFlowControl {
            buffer_size,
            received_since_continue: 0,
        }
    }

    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }

    pub fn on_data_received(&mut self) -> bool {
        self.received_since_continue += 1;
        if self.received_since_continue >= self.buffer_size {
            self.received_since_continue = 0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_decrements_on_send_and_blocks_at_zero() {
        let mut flow = ClientFlowControl::new(2);
        assert!(flow.can_send());
        flow.on_send().unwrap();
        assert_eq!(flow.buffer_remaining(), 1);
        flow.on_send().unwrap();
        assert_eq!(flow.buffer_remaining(), 0);
        assert!(!flow.can_send());
        assert!(flow.on_send().is_err());
    }

    #[test]
    fn client_resets_on_continue() {
        let mut flow = ClientFlowControl::new(1);
        flow.on_send().unwrap();
        assert!(!flow.can_send());
        flow.on_continue(10);
        assert_eq!(flow.buffer_remaining(), 10);
        assert!(flow.can_send());
    }

    #[test]
    fn server_signals_continue_once_buffer_size_packets_received() {
        let mut flow = ServerFlowControl::new(3);
        assert!(!flow.on_data_received());
        assert!(!flow.on_data_received());
        assert!(flow.on_data_received());
        assert!(!flow.on_data_received());
    }

    #[test]
    fn server_counter_resets_after_signalling() {
        let mut flow = ServerFlowControl::new(2);
        assert!(!flow.on_data_received());
        assert!(flow.on_data_received());
        assert!(!flow.on_data_received());
        assert!(flow.on_data_received());
    }
}
