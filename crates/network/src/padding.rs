//! Constant-Size Packet Padding
//!
//! To defeat traffic analysis based on message sizes, all messages
//! are padded to fixed sizes. This module provides padding utilities.

use rand::{RngCore, Rng, rngs::OsRng};
use thiserror::Error;

/// Padding configuration
#[derive(Clone)]
pub struct PaddingConfig {
    /// Base padding size (all messages padded to at least this)
    pub min_size: usize,

    /// Padding granularity (messages padded to next multiple)
    pub granularity: usize,

    /// Maximum message size (messages larger are fragmented)
    pub max_size: usize,

    /// Enable random padding (add random extra bytes)
    pub random_padding: bool,

    /// Random padding range (0 to this value)
    pub random_range: usize,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            min_size: 256,           // Minimum 256 bytes
            granularity: 64,         // Pad to 64-byte boundary
            max_size: 65536,         // Max 64KB
            random_padding: true,    // Add random padding
            random_range: 1024,      // 0-1KB extra random padding
        }
    }
}

/// Padding errors
#[derive(Error, Debug)]
pub enum PaddingError {
    #[error("Message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Padded message wrapper
#[derive(Clone)]
pub struct PaddedMessage {
    /// Original payload
    pub payload: Vec<u8>,

    /// Padding bytes
    pub padding: Vec<u8>,

    /// Total size after padding
    pub total_size: usize,
}

impl PaddedMessage {
    /// Create new padded message from payload
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            padding: Vec::new(),
            total_size: 0,
        }
    }

    /// Apply padding according to config
    pub fn pad(&mut self, config: &PaddingConfig) -> Result<(), PaddingError> {
        let payload_len = self.payload.len();

        // Check max size
        if payload_len > config.max_size {
            return Err(PaddingError::MessageTooLarge {
                size: payload_len,
                max: config.max_size,
            });
        }

        // Calculate target size
        let mut target_size = config.min_size.max(payload_len);

        // Round up to granularity
        if config.granularity > 0 {
            target_size = ((target_size + config.granularity - 1) / config.granularity) * config.granularity;
        }

        // Add random padding if enabled
        if config.random_padding {
            let extra = OsRng.gen_range(0..=config.random_range);
            target_size += extra;

            // Round to granularity again
            if config.granularity > 0 {
                target_size = ((target_size + config.granularity - 1) / config.granularity) * config.granularity;
            }
        }

        // Ensure we don't exceed max
        target_size = target_size.min(config.max_size);

        // Generate padding
        let padding_len = target_size - payload_len;
        self.padding = vec![0u8; padding_len];

        // Fill padding with random bytes (better than zeros for analysis resistance)
        OsRng.fill_bytes(&mut self.padding);

        self.total_size = target_size;

        Ok(())
    }

    /// Get total message size (payload + padding)
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Serialize for transmission (payload + padding)
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.total_size);
        data.extend_from_slice(&self.payload);
        data.extend_from_slice(&self.padding);
        data
    }

    /// Deserialize from received data
    pub fn deserialize(data: &[u8], payload_len: usize) -> Result<Self, PaddingError> {
        if data.len() < payload_len {
            return Err(PaddingError::InvalidConfig(
                "Data shorter than payload length".into()
            ));
        }

        let payload = data[..payload_len].to_vec();
        let padding = data[payload_len..].to_vec();

        Ok(Self {
            payload,
            padding,
            total_size: data.len(),
        })
    }

    /// Strip padding and return payload
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Padding scheme for constant-bandwidth mode
pub struct ConstantBandwidth {
    /// Fixed packet size
    packet_size: usize,

    /// Bytes sent this interval
    bytes_sent: usize,

    /// Target bytes per interval
    target_per_interval: usize,
}

impl ConstantBandwidth {
    /// Create new constant bandwidth tracker
    pub fn new(packet_size: usize, target_bytes_per_sec: usize) -> Self {
        Self {
            packet_size,
            bytes_sent: 0,
            target_per_interval: target_bytes_per_sec,
        }
    }

    /// Get number of packets to send this interval
    pub fn packets_needed(&self) -> usize {
        let remaining = self.target_per_interval.saturating_sub(self.bytes_sent);
        (remaining + self.packet_size - 1) / self.packet_size
    }

    /// Record bytes sent
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes;
    }

    /// Reset counter for new interval
    pub fn reset_interval(&mut self) {
        self.bytes_sent = 0;
    }

    /// Check if we're under target
    pub fn under_target(&self) -> bool {
        self.bytes_sent < self.target_per_interval
    }
}

/// Fragment large messages into fixed-size packets
pub struct MessageFraggregator {
    fragment_size: usize,
}

impl MessageFraggregator {
    pub fn new(fragment_size: usize) -> Self {
        Self { fragment_size }
    }

    /// Fragment message into fixed-size pieces
    pub fn fragment(&self, message: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();

        for chunk in message.chunks(self.fragment_size) {
            let mut fragment = chunk.to_vec();

            // Pad last fragment if needed
            if fragment.len() < self.fragment_size {
                fragment.resize(self.fragment_size, 0);
                // Fill with random bytes instead
                OsRng.fill_bytes(&mut fragment[chunk.len()..]);
            }

            fragments.push(fragment);
        }

        fragments
    }

    /// Reassemble message from fragments
    pub fn reassemble(&self, fragments: &[Vec<u8>], original_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(original_size);

        for (i, fragment) in fragments.iter().enumerate() {
            let start = i * self.fragment_size;
            let end = (start + fragment.len()).min(original_size);

            if start < original_size {
                let copy_len = (end - start).min(fragment.len());
                result.extend_from_slice(&fragment[..copy_len]);
            }
        }

        result
    }

    /// Get number of fragments for a message
    pub fn fragment_count(&self, message_len: usize) -> usize {
        (message_len + self.fragment_size - 1) / self.fragment_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_granularity() {
        let config = PaddingConfig {
            min_size: 100,
            granularity: 32,
            max_size: 1000,
            random_padding: false,
            random_range: 0,
        };

        let mut msg = PaddedMessage::new(vec![0u8; 50]);
        msg.pad(&config).unwrap();

        assert!(msg.total_size() >= 100);
        assert_eq!(msg.total_size() % 32, 0);
    }

    #[test]
    fn test_padding_too_large() {
        let config = PaddingConfig {
            min_size: 100,
            granularity: 32,
            max_size: 100,
            random_padding: false,
            random_range: 0,
        };

        let mut msg = PaddedMessage::new(vec![0u8; 200]);
        let result = msg.pad(&config);
        assert!(matches!(result, Err(PaddingError::MessageTooLarge { .. })));
    }

    #[test]
    fn test_message_fragmentation() {
        let frag = MessageFraggregator::new(64);
        let message = vec![1u8; 150];

        let fragments = frag.fragment(&message);
        assert_eq!(fragments.len(), 3); // 64 + 64 + 22 -> 3 fragments
        assert_eq!(fragments[0].len(), 64);
        assert_eq!(fragments[1].len(), 64);
        assert_eq!(fragments[2].len(), 64); // Padded
    }

    #[test]
    fn test_fragment_reassembly() {
        let frag = MessageFraggregator::new(64);
        let original = vec![1u8; 150];

        let fragments = frag.fragment(&original);
        let reassembled = frag.reassemble(&fragments, 150);

        assert_eq!(original, reassembled);
    }

    #[test]
    fn test_constant_bandwidth() {
        let mut cb = ConstantBandwidth::new(1000, 5000); // 1KB packets, 5KB/s target

        assert!(cb.under_target());
        assert_eq!(cb.packets_needed(), 5);

        cb.record_sent(3000);
        assert!(cb.under_target());
        assert_eq!(cb.packets_needed(), 2);

        cb.record_sent(2000);
        assert!(!cb.under_target());
        assert_eq!(cb.packets_needed(), 0);
    }

    #[test]
    fn test_padding_randomness() {
        let config = PaddingConfig::default();

        let mut msg1 = PaddedMessage::new(vec![0u8; 100]);
        let mut msg2 = PaddedMessage::new(vec![0u8; 100]);

        msg1.pad(&config).unwrap();
        msg2.pad(&config).unwrap();

        // Padding should be different (random)
        assert_ne!(msg1.padding, msg2.padding);
    }
}