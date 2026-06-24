//! Shadowgram Network Layer
//!
//! Anonymous network transport providing:
//! - Tor onion routing via Arti (pure Rust)
//! - Optional mixnet routing for traffic analysis resistance
//! - DHT-based peer discovery
//! - Constant-size packet padding
//! - Cover traffic generation

pub mod tor;
pub mod mixnet;
pub mod dht;
pub mod padding;
pub mod cover_traffic;
pub mod relay;
pub mod transports;
pub mod noise;

// Re-exports
pub use tor::{TorTransport, TorError, OnionAddress};
pub use mixnet::{MixnetClient, MixnetConfig};
pub use dht::{DhtNode, DhtConfig, PeerDiscovery};
pub use padding::{PaddedMessage, PaddingConfig};
pub use cover_traffic::{CoverTraffic, TrafficConfig};
pub use relay::{RelayPool, MultiPathRouting};
pub use noise::{NoiseIK, NoiseBuilder, HandshakeMessageA, HandshakeMessageB, NoiseError};

/// Network message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Initial handshake
    Handshake,
    /// Ratchet update
    Ratchet,
    /// Regular message
    Message,
    /// Control/signaling message
    Control,
    /// Cover traffic (dummy)
    Cover,
}

/// Network envelope wrapper
#[derive(Clone)]
pub struct NetworkEnvelope {
    /// Message type
    pub msg_type: MessageType,

    /// Encrypted payload (already encrypted at application layer)
    pub payload: Vec<u8>,

    /// Constant-size padding
    pub padding: Vec<u8>,

    /// Timestamp (obfuscated)
    pub timestamp: u64,
}

impl NetworkEnvelope {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            payload,
            padding: Vec::new(),
            timestamp: 0,
        }
    }

    /// Apply padding to constant size
    pub fn pad_to_constant_size(&mut self, target_size: usize) {
        let current_size = self.payload.len();
        if current_size < target_size {
            self.padding = vec![0u8; target_size - current_size];
        }
    }

    /// Serialize envelope for transport
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Type byte
        let type_byte = match self.msg_type {
            MessageType::Handshake => 1,
            MessageType::Ratchet => 2,
            MessageType::Message => 3,
            MessageType::Control => 4,
            MessageType::Cover => 5,
        };
        data.push(type_byte);

        // Payload length (varint)
        data.extend_from_slice(&self.payload.len().to_le_bytes());

        // Payload
        data.extend_from_slice(&self.payload);

        // Padding
        data.extend_from_slice(&self.padding);

        // Timestamp
        data.extend_from_slice(&self.timestamp.to_le_bytes());

        data
    }

    /// Deserialize envelope from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        if data.is_empty() {
            return Err(NetworkError::InvalidFormat("Empty data".into()));
        }

        let type_byte = data[0];
        let msg_type = match type_byte {
            1 => MessageType::Handshake,
            2 => MessageType::Ratchet,
            3 => MessageType::Message,
            4 => MessageType::Control,
            5 => MessageType::Cover,
            _ => return Err(NetworkError::InvalidFormat("Unknown message type".into())),
        };

        if data.len() < 9 {
            return Err(NetworkError::InvalidFormat("Too short for length header".into()));
        }

        let payload_len = usize::from_le_bytes(data[1..9].try_into().unwrap());

        if data.len() < 9 + payload_len {
            return Err(NetworkError::InvalidFormat("Payload length mismatch".into()));
        }

        let payload = data[9..9 + payload_len].to_vec();

        // Calculate padding
        let total_data_len = 9 + payload_len + 8; // +8 for timestamp at end
        let padding_len = data.len().saturating_sub(total_data_len);
        let padding = if padding_len > 0 {
            data[9 + payload_len..9 + payload_len + padding_len].to_vec()
        } else {
            Vec::new()
        };

        // Parse timestamp from end
        let timestamp = if data.len() >= 8 {
            let ts_start = data.len() - 8;
            u64::from_le_bytes(data[ts_start..].try_into().unwrap_or([0u8; 8]))
        } else {
            0
        };

        Ok(Self {
            msg_type,
            payload,
            padding,
            timestamp,
        })
    }
}

/// Network layer errors
#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout exceeded")]
    Timeout,

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Routing failed: {0}")]
    RoutingFailed(String),
}