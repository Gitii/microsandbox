//! TCP stream protocol message payloads.

use serde::{Deserialize, Serialize};

/// Maximum unacknowledged TCP bytes in each direction, per connection.
/// Both peers start with this credit after `core.tcp.connected`. Credit is
/// returned only after bytes reach the destination socket or consuming reader.
pub const TCP_WINDOW_BYTES: usize = 64 * 1024;

/// Maximum payload of one TCP data frame. Empty data frames are invalid.
pub const TCP_MAX_DATA_BYTES: usize = 16 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Request to open a TCP connection from inside the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnect {
    /// Destination host name or address as seen by the guest.
    pub host: String,

    /// Destination TCP port.
    pub port: u16,
}

/// Confirmation that a TCP connection was opened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnected {}

/// TCP stream data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpData {
    /// The raw stream bytes.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Return consumed byte credit to the sender, in either direction.
/// Zero credit, overflow, or credit above the initial window is a protocol error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpCredit {
    /// Number of bytes consumed since the previous credit message.
    pub bytes: u32,
}

/// Notification that one side has closed its write half.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpEof {}

/// Request to close the TCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpClose {}

/// Terminal acknowledgment emitted only after all guest socket futures are dropped.
/// Failure to observe this message (including transport loss) means cleanup is
/// unknown to the caller, not that remote teardown has been confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpClosed {}

/// Terminal notification that the TCP session failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFailed {
    /// Human-readable failure description.
    pub error: String,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_payloads_roundtrip() {
        let connect = TcpConnect {
            host: "127.0.0.1".to_string(),
            port: 8080,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&connect, &mut buf).unwrap();
        let decoded: TcpConnect = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.host, connect.host);
        assert_eq!(decoded.port, connect.port);

        let data = TcpData {
            data: b"hello".to_vec(),
        };
        buf.clear();
        ciborium::into_writer(&data, &mut buf).unwrap();
        let decoded: TcpData = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.data, data.data);

        let failed = TcpFailed {
            error: "connection refused".to_string(),
        };
        buf.clear();
        ciborium::into_writer(&failed, &mut buf).unwrap();
        let decoded: TcpFailed = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.error, failed.error);
    }
}
