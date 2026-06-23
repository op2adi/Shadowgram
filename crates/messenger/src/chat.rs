//! Chat Session Management
//!
//! 1-on-1 chat sessions with Double Ratchet encryption.
//!
//! Each chat session maintains:
//! - Double Ratchet state for forward secrecy
//! - Message history (encrypted at rest)
//! - Session metadata (created, last activity)

use thiserror::Error;
use shadowgram_crypto::double_ratchet::DoubleRatchet;

/// Chat errors
#[derive(Error, Debug)]
pub enum ChatError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Contact not found: {0}")]
    ContactNotFound(String),
}

/// Chat session state
#[derive(Clone, Debug)]
pub enum ChatState {
    /// New chat, no session established
    New,

    /// Key exchange in progress
    KeyExchange,

    /// Session established, can send/receive
    Established,

    /// Session expired/invalid
    Expired,
}

/// 1-on-1 chat session
pub struct ChatSession {
    /// Contact's identity fingerprint
    contact_fingerprint: String,

    /// Our identity fingerprint
    our_fingerprint: String,

    /// Session state
    state: ChatState,

    /// Double Ratchet for encryption/decryption
    ratchet: Option<DoubleRatchet>,

    /// Message counter
    message_count: u64,

    /// Last activity timestamp
    last_activity: u64,
}

impl ChatSession {
    /// Create new chat session
    pub fn new(our_fingerprint: String, contact_fingerprint: String) -> Self {
        Self {
            contact_fingerprint,
            our_fingerprint,
            state: ChatState::New,
            ratchet: None,
            message_count: 0,
            last_activity: current_timestamp(),
        }
    }

    /// Create session with established ratchet
    pub fn with_ratchet(
        our_fingerprint: String,
        contact_fingerprint: String,
        ratchet: DoubleRatchet,
    ) -> Self {
        Self {
            contact_fingerprint,
            our_fingerprint,
            state: ChatState::Established,
            ratchet: Some(ratchet),
            message_count: 0,
            last_activity: current_timestamp(),
        }
    }

    /// Get contact fingerprint
    pub fn contact_fingerprint(&self) -> &str {
        &self.contact_fingerprint
    }

    /// Get our fingerprint
    pub fn our_fingerprint(&self) -> &str {
        &self.our_fingerprint
    }

    /// Get session state
    pub fn state(&self) -> &ChatState {
        &self.state
    }

    /// Get ratchet reference
    pub fn ratchet(&self) -> Option<&DoubleRatchet> {
        self.ratchet.as_ref()
    }

    /// Get mutable ratchet
    pub fn ratchet_mut(&mut self) -> Option<&mut DoubleRatchet> {
        self.ratchet.as_mut()
    }

    /// Set the ratchet (completes key exchange)
    pub fn set_ratchet(&mut self, ratchet: DoubleRatchet) {
        self.ratchet = Some(ratchet);
        self.state = ChatState::Established;
    }

    /// Check if session is established
    pub fn is_established(&self) -> bool {
        matches!(self.state, ChatState::Established)
    }

    /// Update session state
    pub fn set_state(&mut self, state: ChatState) {
        self.state = state;
    }

    /// Record message sent/received
    pub fn record_activity(&mut self) {
        self.message_count += 1;
        self.last_activity = current_timestamp();
    }

    /// Get message count
    pub fn message_count(&self) -> u64 {
        self.message_count
    }

    /// Get last activity timestamp
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Check if session is stale (no activity for N days)
    pub fn is_stale(&self, max_days: u64) -> bool {
        let now = current_timestamp();
        let secs_per_day = 86400;
        (now - self.last_activity) > (max_days * secs_per_day)
    }

    /// Encrypt message with Double Ratchet
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ChatError> {
        let ratchet = self.ratchet.as_mut()
            .ok_or(ChatError::SessionNotFound)?;

        let (ciphertext, header) = ratchet.encrypt(plaintext)
            .map_err(|e| ChatError::EncryptionError(e.to_string()))?;

        // Serialize header + ciphertext
        let mut output = header.serialize();
        output.extend(ciphertext);
        Ok(output)
    }

    /// Decrypt message with Double Ratchet
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ChatError> {
        let ratchet = self.ratchet.as_mut()
            .ok_or(ChatError::SessionNotFound)?;

        // Parse header (first 96 bytes for X25519 public key + counters)
        if ciphertext.len() < 96 {
            return Err(ChatError::InvalidMessage("Message too short".into()));
        }

        let header = crate::message::MessageHeader::deserialize(&ciphertext[..96])
            .map_err(|e| ChatError::DecryptionError(e.to_string()))?;

        let plaintext = ratchet.decrypt(&header, &ciphertext[96..])
            .map_err(|e| ChatError::DecryptionError(e.to_string()))?;

        self.record_activity();
        Ok(plaintext)
    }
}

/// Chat conversation manager
pub struct Chat {
    /// Session
    session: ChatSession,

    /// Pending outbound messages
    pending_outbound: Vec<crate::message::Message>,

    /// Pending inbound messages (awaiting decryption)
    pending_inbound: Vec<crate::message::MessageEnvelope>,
}

impl Chat {
    /// Create new chat
    pub fn new(our_fingerprint: String, contact_fingerprint: String) -> Self {
        Self {
            session: ChatSession::new(our_fingerprint, contact_fingerprint),
            pending_outbound: Vec::new(),
            pending_inbound: Vec::new(),
        }
    }

    /// Get session reference
    pub fn session(&self) -> &ChatSession {
        &self.session
    }

    /// Get session mutable reference
    pub fn session_mut(&mut self) -> &mut ChatSession {
        &mut self.session
    }

    /// Queue message for sending
    pub fn queue_message(&mut self, message: crate::message::Message) {
        self.pending_outbound.push(message);
    }

    /// Get pending outbound messages
    pub fn take_pending_outbound(&mut self) -> Vec<crate::message::Message> {
        std::mem::take(&mut self.pending_outbound)
    }

    /// Queue encrypted message for processing
    pub fn queue_inbound(&mut self, envelope: crate::message::MessageEnvelope) {
        self.pending_inbound.push(envelope);
    }

    /// Get pending inbound messages
    pub fn take_pending_inbound(&mut self) -> Vec<crate::message::MessageEnvelope> {
        std::mem::take(&mut self.pending_inbound)
    }

    /// Get chat statistics
    pub fn stats(&self) -> ChatStats {
        ChatStats {
            contact_fingerprint: self.session.contact_fingerprint().to_string(),
            state: format!("{:?}", self.session.state()),
            message_count: self.session.message_count(),
            pending_outbound: self.pending_outbound.len(),
            pending_inbound: self.pending_inbound.len(),
        }
    }
}

/// Chat statistics
pub struct ChatStats {
    pub contact_fingerprint: String,
    pub state: String,
    pub message_count: u64,
    pub pending_outbound: usize,
    pub pending_inbound: usize,
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_session_creation() {
        let session = ChatSession::new(
            "our_fp".to_string(),
            "their_fp".to_string(),
        );

        assert_eq!(session.state(), &ChatState::New);
        assert_eq!(session.message_count(), 0);
    }

    #[test]
    fn test_chat_session_activity() {
        let mut session = ChatSession::new(
            "our_fp".to_string(),
            "their_fp".to_string(),
        );

        session.record_activity();
        assert_eq!(session.message_count(), 1);
        assert!(session.last_activity() > 0);
    }

    #[test]
    fn test_chat_stale_detection() {
        let mut session = ChatSession::new(
            "our_fp".to_string(),
            "their_fp".to_string(),
        );

        // Not stale immediately
        assert!(!session.is_stale(7)); // 7 days threshold

        // Simulate stale by setting old timestamp
        session.last_activity = 0;
        assert!(session.is_stale(7));
    }
}