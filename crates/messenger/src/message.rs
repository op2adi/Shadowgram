//! Message Types and Envelopes
//!
//! Message structures for the Shadowgram protocol.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Message status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Composed locally
    Composed,

    /// Sending to network
    Sending,

    /// Sent to network
    Sent,

    /// Delivered to recipient
    Delivered,

    /// Read by recipient (if enabled)
    Read,

    /// Failed to send
    Failed,
}

/// Message direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    /// Outgoing message
    Outgoing,

    /// Incoming message
    Incoming,
}

/// Application-level message content
#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message ID
    pub id: String,

    /// Conversation ID
    pub conversation_id: String,

    /// Message content (plaintext for outgoing, decrypted for incoming)
    pub content: String,

    /// Message type
    pub message_type: MessageType,

    /// Timestamp
    pub timestamp: u64,

    /// Delivery status
    pub status: MessageStatus,

    /// Direction
    pub direction: MessageDirection,
}

/// Message type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Plain text message
    Text,

    /// Image attachment
    Image,

    /// File attachment
    File,

    /// Voice message
    Voice,

    /// System message
    System,

    /// Key exchange message
    KeyExchange,

    /// Ratchet sync message
    RatchetSync,
}

/// Encrypted message envelope for transport
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Protocol version
    pub version: u8,

    /// Sender's identity (pairwise pseudonym)
    pub sender: Vec<u8>,

    /// Conversation identifier
    pub conversation_id: Vec<u8>,

    /// Message sequence number
    pub sequence: u64,

    /// Ratchet level
    pub ratchet_level: u32,

    /// Encrypted payload
    pub ciphertext: Vec<u8>,

    /// Authentication tag
    pub auth_tag: Vec<u8>,

    /// Header (serialized ratchet state)
    pub header: Vec<u8>,

    /// Padding (for traffic analysis resistance)
    pub padding: Vec<u8>,
}

impl Message {
    /// Create new text message
    pub fn text(content: String) -> Self {
        Self {
            id: uuid_v4(),
            conversation_id: String::new(),
            content,
            message_type: MessageType::Text,
            timestamp: current_timestamp(),
            status: MessageStatus::Composed,
            direction: MessageDirection::Outgoing,
        }
    }

    /// Create new system message
    pub fn system(content: String) -> Self {
        Self {
            id: uuid_v4(),
            conversation_id: String::new(),
            content,
            message_type: MessageType::System,
            timestamp: current_timestamp(),
            status: MessageStatus::Delivered,
            direction: MessageDirection::Incoming,
        }
    }

    /// Serialize message to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize message from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

fn uuid_v4() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl MessageEnvelope {
    /// Create new envelope
    pub fn new(sender: Vec<u8>, conversation_id: Vec<u8>, sequence: u64) -> Self {
        Self {
            version: 1,
            sender,
            conversation_id,
            sequence,
            ratchet_level: 0,
            ciphertext: Vec::new(),
            auth_tag: Vec::new(),
            header: Vec::new(),
            padding: Vec::new(),
        }
    }

    /// Set encrypted payload
    pub fn set_payload(&mut self, ciphertext: Vec<u8>, auth_tag: Vec<u8>) {
        self.ciphertext = ciphertext;
        self.auth_tag = auth_tag;
    }

    /// Set ratchet header
    pub fn set_header(&mut self, header: Vec<u8>) {
        self.header = header;
    }

    /// Apply padding
    pub fn pad_to_size(&mut self, target_size: usize) {
        let current_size = self.version as usize
            + self.sender.len()
            + self.conversation_id.len()
            + 8 // sequence
            + 4 // ratchet_level
            + 4 // ciphertext length prefix
            + self.ciphertext.len()
            + 4 // auth_tag length prefix
            + self.auth_tag.len()
            + 4 // header length prefix
            + self.header.len();

        if current_size < target_size {
            self.padding = vec![0u8; target_size - current_size];
            // Fill with random bytes
            use rand::{rngs::OsRng, RngCore};
            OsRng.fill_bytes(&mut self.padding);
        }
    }

    /// Serialize envelope
    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize envelope
    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Get total size of serialized envelope
    pub fn serialized_size(&self) -> usize {
        // Approximate size
        1 + self.sender.len()
            + self.conversation_id.len()
            + 8
            + 4
            + self.ciphertext.len()
            + self.auth_tag.len()
            + self.header.len()
            + self.padding.len()
    }
}

impl Zeroize for MessageEnvelope {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.auth_tag.zeroize();
        self.header.zeroize();
        self.padding.zeroize();
    }
}

impl Drop for MessageEnvelope {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Batch of messages for efficient transmission
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageBatch {
    /// Batch ID
    pub batch_id: u64,

    /// Messages in batch
    pub messages: Vec<MessageEnvelope>,

    /// Whether this batch contains cover traffic
    pub is_cover: bool,
}

impl MessageBatch {
    pub fn new(batch_id: u64) -> Self {
        Self {
            batch_id,
            messages: Vec::new(),
            is_cover: false,
        }
    }

    pub fn add_message(&mut self, envelope: MessageEnvelope) {
        self.messages.push(envelope);
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Message priority for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePriority {
    /// Normal priority
    Normal,

    /// High priority (key exchange, urgent)
    High,

    /// Low priority (can be delayed)
    Low,
}

impl Default for MessagePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Message header for Double Ratchet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's ratchet public key
    pub dh_public: [u8; 32],

    /// Message number in sending chain
    pub message_number: u64,

    /// Previous chain length (for skipped keys)
    pub previous_chain_length: u32,

    /// Ratchet level for layered ratcheting
    pub ratchet_level: u32,

    /// Additional authenticated data
    pub aad: Vec<u8>,
}

impl MessageHeader {
    pub fn new(dh_public: [u8; 32], message_number: u64, previous_chain_length: u32) -> Self {
        Self {
            dh_public,
            message_number,
            previous_chain_length,
            ratchet_level: 0,
            aad: Vec::new(),
        }
    }

    /// Serialize header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(96 + self.aad.len());
        data.extend_from_slice(&self.dh_public);
        data.extend_from_slice(&self.message_number.to_le_bytes());
        data.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        data.extend_from_slice(&self.ratchet_level.to_le_bytes());

        // Length-prefixed AAD
        data.extend_from_slice(&(self.aad.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.aad);

        data
    }

    /// Deserialize header from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 48 {
            return Err(MessageError::InvalidFormat("Header too short".into()));
        }

        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[0..32]);

        let message_number = u64::from_le_bytes(
            data[32..40]
                .try_into()
                .map_err(|_| MessageError::InvalidFormat("Missing message number".into()))?,
        );
        let previous_chain_length =
            u32::from_le_bytes(data[40..44].try_into().map_err(|_| {
                MessageError::InvalidFormat("Missing previous chain length".into())
            })?);
        let ratchet_level = u32::from_le_bytes(
            data[44..48]
                .try_into()
                .map_err(|_| MessageError::InvalidFormat("Missing ratchet level".into()))?,
        );

        let aad = if data.len() > 48 {
            if data.len() < 52 {
                return Err(MessageError::InvalidFormat(
                    "AAD length prefix is truncated".into(),
                ));
            }
            let aad_len = u32::from_le_bytes(
                data[48..52]
                    .try_into()
                    .map_err(|_| MessageError::InvalidFormat("Invalid AAD length".into()))?,
            ) as usize;
            if data.len() < 52 + aad_len {
                return Err(MessageError::InvalidFormat("AAD length mismatch".into()));
            }
            data[52..52 + aad_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            dh_public,
            message_number,
            previous_chain_length,
            ratchet_level,
            aad,
        })
    }

    /// Set additional authenticated data
    pub fn with_aad(mut self, aad: Vec<u8>) -> Self {
        self.aad = aad;
        self
    }
}

/// Message header errors
#[derive(Error, Debug)]
pub enum MessageError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Serialization failed: {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_message_creation() {
        let msg = Message {
            id: "msg123".to_string(),
            conversation_id: "conv456".to_string(),
            content: "Hello!".to_string(),
            message_type: MessageType::Text,
            timestamp: 1234567890,
            status: MessageStatus::Composed,
            direction: MessageDirection::Outgoing,
        };

        assert_eq!(msg.status, MessageStatus::Composed);
        assert_eq!(msg.direction, MessageDirection::Outgoing);
    }

    #[test]
    fn test_envelope_serialization() {
        let mut env = MessageEnvelope::new(vec![1, 2, 3], vec![4, 5, 6], 1);
        env.set_payload(vec![7, 8, 9], vec![10, 11, 12]);

        let serialized = env.serialize().unwrap();
        let deserialized = MessageEnvelope::deserialize(&serialized).unwrap();

        assert_eq!(env.sender, deserialized.sender);
        assert_eq!(env.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_message_batch() {
        let mut batch = MessageBatch::new(1);
        batch.add_message(MessageEnvelope::new(vec![], vec![], 1));
        batch.add_message(MessageEnvelope::new(vec![], vec![], 2));

        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }

    proptest! {
        #[test]
        fn prop_message_roundtrip(
            content in ".*",
            conversation in ".*",
            timestamp in any::<u64>(),
        ) {
            let message = Message {
                id: "msg".to_string(),
                conversation_id: conversation,
                content,
                message_type: MessageType::Text,
                timestamp,
                status: MessageStatus::Composed,
                direction: MessageDirection::Outgoing,
            };

            let bytes = message.serialize().unwrap();
            let decoded = Message::deserialize(&bytes).unwrap();
            prop_assert_eq!(decoded.content, message.content);
            prop_assert_eq!(decoded.conversation_id, message.conversation_id);
            prop_assert_eq!(decoded.timestamp, message.timestamp);
        }

        #[test]
        fn prop_message_header_roundtrip(
            dh_public in prop::array::uniform32(any::<u8>()),
            message_number in any::<u64>(),
            previous_chain_length in any::<u32>(),
            ratchet_level in any::<u32>(),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let mut header = MessageHeader::new(dh_public, message_number, previous_chain_length);
            header.ratchet_level = ratchet_level;
            header.aad = aad.clone();

            let bytes = header.serialize();
            let decoded = MessageHeader::deserialize(&bytes).unwrap();

            prop_assert_eq!(decoded.dh_public, header.dh_public);
            prop_assert_eq!(decoded.message_number, header.message_number);
            prop_assert_eq!(decoded.previous_chain_length, header.previous_chain_length);
            prop_assert_eq!(decoded.ratchet_level, header.ratchet_level);
            prop_assert_eq!(decoded.aad, aad);
        }

        #[test]
        fn prop_message_header_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = MessageHeader::deserialize(&data);
        }

        #[test]
        fn prop_message_envelope_roundtrip(
            sender in proptest::collection::vec(any::<u8>(), 0..64),
            conversation_id in proptest::collection::vec(any::<u8>(), 0..64),
            sequence in any::<u64>(),
            ciphertext in proptest::collection::vec(any::<u8>(), 0..256),
            auth_tag in proptest::collection::vec(any::<u8>(), 0..32),
            header in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let mut envelope = MessageEnvelope::new(sender.clone(), conversation_id.clone(), sequence);
            envelope.set_payload(ciphertext.clone(), auth_tag.clone());
            envelope.set_header(header.clone());
            envelope.pad_to_size(512);

            let encoded = envelope.serialize().unwrap();
            let decoded = MessageEnvelope::deserialize(&encoded).unwrap();

            prop_assert_eq!(&decoded.sender, &sender);
            prop_assert_eq!(&decoded.conversation_id, &conversation_id);
            prop_assert_eq!(decoded.sequence, sequence);
            prop_assert_eq!(&decoded.ciphertext, &ciphertext);
            prop_assert_eq!(&decoded.auth_tag, &auth_tag);
            prop_assert_eq!(&decoded.header, &header);
        }
    }
}
