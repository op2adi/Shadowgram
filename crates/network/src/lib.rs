//! Shadowgram Network Layer
//!
//! Anonymous network transport providing:
//! - Tor onion routing via Arti (pure Rust)
//! - Optional mixnet routing for traffic analysis resistance
//! - DHT-based peer discovery
//! - Constant-size packet padding
//! - Cover traffic generation

pub mod cover_traffic;
pub mod dht;
pub mod mailbox;
pub mod mixnet;
pub mod noise;
pub mod padding;
pub mod relay;
pub mod tor;
pub mod transports;

// Re-exports
pub use cover_traffic::{CoverTraffic, TrafficConfig};
pub use dht::{DhtConfig, DhtNode, PeerDiscovery};
pub use mailbox::{
    MailboxEnvelope, MailboxError, OutboundQueue, PendingOutbound, RelayMailbox,
    MAILBOX_TTL_SECS, MAX_ENVELOPE_BYTES, MAX_PENDING_PER_RECIPIENT,
};
pub use mixnet::{MixnetClient, MixnetConfig};
pub use noise::{HandshakeMessageA, HandshakeMessageB, NoiseBuilder, NoiseError, NoiseIK};
pub use padding::{PaddedMessage, PaddingConfig};
use rand::{rngs::OsRng, RngCore};
pub use relay::{MultiPathRouting, RelayPool};
pub use tor::{OnionAddress, TorError, TorTransport};
use zeroize::Zeroize;

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
        let timestamp = current_timestamp();
        Self {
            msg_type,
            payload,
            padding: Vec::new(),
            timestamp,
        }
    }

    /// Apply padding to constant size
    pub fn pad_to_constant_size(&mut self, target_size: usize) {
        let current_size = self.payload.len();
        if current_size < target_size {
            self.padding = vec![0u8; target_size - current_size];
            OsRng.fill_bytes(&mut self.padding);
        }
    }

    /// Serialize envelope for transport
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + 8 + 8 + self.payload.len() + self.padding.len());

        // Type byte
        let type_byte = match self.msg_type {
            MessageType::Handshake => 1,
            MessageType::Ratchet => 2,
            MessageType::Message => 3,
            MessageType::Control => 4,
            MessageType::Cover => 5,
        };
        data.push(type_byte);

        let payload_len = self.payload.len() as u32;
        let padding_len = self.padding.len() as u32;
        data.extend_from_slice(&payload_len.to_le_bytes());
        data.extend_from_slice(&padding_len.to_le_bytes());

        data.extend_from_slice(&self.payload);
        data.extend_from_slice(&self.padding);
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

        if data.len() < 17 {
            return Err(NetworkError::InvalidFormat(
                "Too short for length header".into(),
            ));
        }

        let payload_len = u32::from_le_bytes(
            data[1..5]
                .try_into()
                .map_err(|_| NetworkError::InvalidFormat("Invalid payload length header".into()))?,
        ) as usize;
        let padding_len = u32::from_le_bytes(
            data[5..9]
                .try_into()
                .map_err(|_| NetworkError::InvalidFormat("Invalid padding length header".into()))?,
        ) as usize;
        let expected_len = 1 + 4 + 4 + payload_len + padding_len + 8;

        if data.len() != expected_len {
            return Err(NetworkError::InvalidFormat(
                "Envelope length mismatch".into(),
            ));
        }

        let payload_start = 9;
        let payload_end = payload_start + payload_len;
        let padding_end = payload_end + padding_len;
        let payload = data[payload_start..payload_end].to_vec();
        let padding = data[payload_end..padding_end].to_vec();
        let timestamp = u64::from_le_bytes(
            data[padding_end..padding_end + 8]
                .try_into()
                .map_err(|_| NetworkError::InvalidFormat("Invalid timestamp".into()))?,
        );

        Ok(Self {
            msg_type,
            payload,
            padding,
            timestamp,
        })
    }
}

impl Drop for NetworkEnvelope {
    fn drop(&mut self) {
        self.payload.zeroize();
        self.padding.zeroize();
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

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_network_envelope_roundtrip(
            msg_type in 1u8..=5u8,
            payload in proptest::collection::vec(any::<u8>(), 0..256),
            padding_target in 0usize..512,
        ) {
            let mapped = match msg_type {
                1 => MessageType::Handshake,
                2 => MessageType::Ratchet,
                3 => MessageType::Message,
                4 => MessageType::Control,
                _ => MessageType::Cover,
            };
            let mut envelope = NetworkEnvelope::new(mapped, payload.clone());
            envelope.pad_to_constant_size(padding_target);
            let serialized = envelope.serialize();
            let decoded = NetworkEnvelope::deserialize(&serialized).unwrap();

            prop_assert_eq!(decoded.msg_type, envelope.msg_type);
            prop_assert_eq!(&decoded.payload, &payload);
            prop_assert_eq!(decoded.padding.len(), envelope.padding.len());
        }

        #[test]
        fn prop_network_envelope_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = NetworkEnvelope::deserialize(&data);
        }
    }
}
