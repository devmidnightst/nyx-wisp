#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Unspecified,
    Voluntary,
    NetworkError,
    IncompatibleExtensions,
    InvalidInfo,
    HostUnreachable,
    ConnectionTimedOut,
    ConnectionRefused,
    TcpTimedOut,
    Blocked,
    Throttled,
    ClientUnexpectedError,
    AuthFailedCredentials,
    AuthFailedSignature,
    AuthRequired,
    Other(u8),
}

impl CloseReason {
    pub fn as_u8(self) -> u8 {
        match self {
            CloseReason::Unspecified => 0x01,
            CloseReason::Voluntary => 0x02,
            CloseReason::NetworkError => 0x03,
            CloseReason::IncompatibleExtensions => 0x04,
            CloseReason::InvalidInfo => 0x41,
            CloseReason::HostUnreachable => 0x42,
            CloseReason::ConnectionTimedOut => 0x43,
            CloseReason::ConnectionRefused => 0x44,
            CloseReason::TcpTimedOut => 0x47,
            CloseReason::Blocked => 0x48,
            CloseReason::Throttled => 0x49,
            CloseReason::ClientUnexpectedError => 0x81,
            CloseReason::AuthFailedCredentials => 0xc0,
            CloseReason::AuthFailedSignature => 0xc1,
            CloseReason::AuthRequired => 0xc2,
            CloseReason::Other(value) => value,
        }
    }

    pub fn is_server_only(self) -> bool {
        matches!(
            self,
            CloseReason::InvalidInfo
                | CloseReason::HostUnreachable
                | CloseReason::ConnectionTimedOut
                | CloseReason::ConnectionRefused
                | CloseReason::TcpTimedOut
                | CloseReason::Blocked
                | CloseReason::Throttled
        )
    }

    pub fn is_client_only(self) -> bool {
        matches!(self, CloseReason::ClientUnexpectedError)
    }
}

impl From<u8> for CloseReason {
    fn from(value: u8) -> Self {
        match value {
            0x01 => CloseReason::Unspecified,
            0x02 => CloseReason::Voluntary,
            0x03 => CloseReason::NetworkError,
            0x04 => CloseReason::IncompatibleExtensions,
            0x41 => CloseReason::InvalidInfo,
            0x42 => CloseReason::HostUnreachable,
            0x43 => CloseReason::ConnectionTimedOut,
            0x44 => CloseReason::ConnectionRefused,
            0x47 => CloseReason::TcpTimedOut,
            0x48 => CloseReason::Blocked,
            0x49 => CloseReason::Throttled,
            0x81 => CloseReason::ClientUnexpectedError,
            0xc0 => CloseReason::AuthFailedCredentials,
            0xc1 => CloseReason::AuthFailedSignature,
            0xc2 => CloseReason::AuthRequired,
            other => CloseReason::Other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_reasons_round_trip() {
        let reasons = [
            CloseReason::Unspecified,
            CloseReason::Voluntary,
            CloseReason::NetworkError,
            CloseReason::IncompatibleExtensions,
            CloseReason::InvalidInfo,
            CloseReason::HostUnreachable,
            CloseReason::ConnectionTimedOut,
            CloseReason::ConnectionRefused,
            CloseReason::TcpTimedOut,
            CloseReason::Blocked,
            CloseReason::Throttled,
            CloseReason::ClientUnexpectedError,
            CloseReason::AuthFailedCredentials,
            CloseReason::AuthFailedSignature,
            CloseReason::AuthRequired,
        ];
        for reason in reasons {
            assert_eq!(CloseReason::from(reason.as_u8()), reason);
        }
    }

    #[test]
    fn wire_values_match_spec_table() {
        assert_eq!(CloseReason::Unspecified.as_u8(), 0x01);
        assert_eq!(CloseReason::Voluntary.as_u8(), 0x02);
        assert_eq!(CloseReason::NetworkError.as_u8(), 0x03);
        assert_eq!(CloseReason::IncompatibleExtensions.as_u8(), 0x04);
        assert_eq!(CloseReason::InvalidInfo.as_u8(), 0x41);
        assert_eq!(CloseReason::HostUnreachable.as_u8(), 0x42);
        assert_eq!(CloseReason::ConnectionTimedOut.as_u8(), 0x43);
        assert_eq!(CloseReason::ConnectionRefused.as_u8(), 0x44);
        assert_eq!(CloseReason::TcpTimedOut.as_u8(), 0x47);
        assert_eq!(CloseReason::Blocked.as_u8(), 0x48);
        assert_eq!(CloseReason::Throttled.as_u8(), 0x49);
        assert_eq!(CloseReason::ClientUnexpectedError.as_u8(), 0x81);
        assert_eq!(CloseReason::AuthFailedCredentials.as_u8(), 0xc0);
        assert_eq!(CloseReason::AuthFailedSignature.as_u8(), 0xc1);
        assert_eq!(CloseReason::AuthRequired.as_u8(), 0xc2);
    }

    #[test]
    fn unknown_reason_preserves_byte() {
        assert_eq!(CloseReason::from(0x99), CloseReason::Other(0x99));
        assert_eq!(CloseReason::Other(0x99).as_u8(), 0x99);
    }
}
