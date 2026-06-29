//! Offline relay mailbox for ciphertext-only store-and-forward delivery.
//!
//! Design invariants:
//! - Relay nodes NEVER see plaintext, sender identity, or message semantics.
//! - Relay nodes store only: recipient_hash (BLAKE3 of fingerprint), ciphertext,
//!   message_id (random), and TTL timestamp.
//! - Delivery is sender→relay (push) and recipient→relay (pull).
//! - Recipient ACKs each message_id after successful decryption; relay then
//!   deletes it.
//! - All relay communication happens over Tor; fail closed if Tor is unavailable.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Default TTL: 7 days.
pub const MAILBOX_TTL_SECS: u64 = 7 * 24 * 3600;

/// Maximum size of a single encrypted envelope payload (256 KiB).
/// Larger application-layer messages must be fragmented before submission.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// Maximum number of envelopes queued per recipient on a single relay.
/// Prevents one recipient from starving others.
pub const MAX_PENDING_PER_RECIPIENT: usize = 100;

/// Mailbox errors.
#[derive(Error, Debug)]
pub enum MailboxError {
    #[error("Message too large: {0} bytes (max {MAX_ENVELOPE_BYTES})")]
    MessageTooLarge(usize),

    #[error("Mailbox full for recipient")]
    MailboxFull,

    #[error("Message not found")]
    NotFound,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// A mailbox envelope stored on a relay node.
///
/// Relays hold **only** this struct — they see no plaintext, no sender identity,
/// no message semantics.  `recipient_hash` is BLAKE3(fingerprint) so the relay
/// cannot correlate the hash back to an identity without the original string.
#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxEnvelope {
    /// Random 32-byte message identifier for dedup and recipient ACK.
    pub message_id: [u8; 32],

    /// BLAKE3 hash of the recipient's identity fingerprint — routing only.
    pub recipient_hash: [u8; 32],

    /// Fully-encrypted application payload. Opaque to the relay.
    pub ciphertext: Vec<u8>,

    /// Unix timestamp after which the relay may discard this envelope.
    pub expires_at: u64,

    /// Unix timestamp of envelope creation.
    pub created_at: u64,
}

impl MailboxEnvelope {
    /// Create a new envelope for offline delivery.
    ///
    /// `ciphertext` must already be AEAD-encrypted by the application layer.
    /// The relay will not inspect it.
    pub fn new(
        recipient_fingerprint: &str,
        ciphertext: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<Self, MailboxError> {
        if ciphertext.len() > MAX_ENVELOPE_BYTES {
            return Err(MailboxError::MessageTooLarge(ciphertext.len()));
        }
        let mut message_id = [0u8; 32];
        OsRng.fill_bytes(&mut message_id);
        let recipient_hash = *blake3::hash(recipient_fingerprint.as_bytes()).as_bytes();
        let now = current_timestamp();
        Ok(Self {
            message_id,
            recipient_hash,
            ciphertext,
            expires_at: now + ttl_secs,
            created_at: now,
        })
    }

    /// True if this envelope has exceeded its TTL.
    pub fn is_expired(&self) -> bool {
        self.expires_at < current_timestamp()
    }

    /// Serialize for wire transport or local DB storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MailboxError> {
        bincode::serialize(self).map_err(|e| MailboxError::SerializationError(e.to_string()))
    }

    /// Deserialize from wire transport or local DB storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MailboxError> {
        bincode::deserialize(bytes).map_err(|e| MailboxError::SerializationError(e.to_string()))
    }
}

/// Server-side mailbox store (runs on relay nodes).
///
/// Keyed by BLAKE3(recipient_fingerprint).  Each slot holds up to
/// `MAX_PENDING_PER_RECIPIENT` non-expired ciphertext envelopes.
/// The relay never inspects the ciphertext.
pub struct RelayMailbox {
    /// recipient_hash → queued envelopes (ciphertext-only, no plaintext)
    store: HashMap<[u8; 32], Vec<MailboxEnvelope>>,
}

impl RelayMailbox {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    /// Accept an inbound envelope for store-and-forward.
    ///
    /// Returns `MailboxFull` if the recipient's slot is at capacity so
    /// callers can try a different relay rather than losing the message.
    pub fn store(&mut self, env: MailboxEnvelope) -> Result<(), MailboxError> {
        if env.ciphertext.len() > MAX_ENVELOPE_BYTES {
            return Err(MailboxError::MessageTooLarge(env.ciphertext.len()));
        }
        let slot = self.store.entry(env.recipient_hash).or_default();
        if slot.len() >= MAX_PENDING_PER_RECIPIENT {
            return Err(MailboxError::MailboxFull);
        }
        // Idempotent re-submit: ignore duplicate message_ids.
        if slot.iter().any(|e| e.message_id == env.message_id) {
            return Ok(());
        }
        slot.push(env);
        Ok(())
    }

    /// Return all non-expired envelopes for `recipient_fingerprint`.
    ///
    /// Expired envelopes are swept lazily before transfer.
    /// This call transfers ownership of the envelopes — the slot is emptied.
    /// The caller is responsible for acknowledging successful decryption
    /// (or re-fetching from another relay on failure).
    pub fn retrieve(&mut self, recipient_fingerprint: &str) -> Vec<MailboxEnvelope> {
        let hash = *blake3::hash(recipient_fingerprint.as_bytes()).as_bytes();
        let slot = self.store.entry(hash).or_default();
        slot.retain(|e| !e.is_expired());
        let envelopes = slot.split_off(0); // move without cloning
        if slot.is_empty() {
            self.store.remove(&hash);
        }
        envelopes
    }

    /// Delete a specific envelope after the recipient confirms decryption.
    ///
    /// Returns `NotFound` if `message_id` is not in this recipient's slot
    /// (already ACKed, expired, or wrong recipient).
    pub fn acknowledge(
        &mut self,
        recipient_fingerprint: &str,
        message_id: &[u8; 32],
    ) -> Result<(), MailboxError> {
        let hash = *blake3::hash(recipient_fingerprint.as_bytes()).as_bytes();
        if let Some(slot) = self.store.get_mut(&hash) {
            let before = slot.len();
            slot.retain(|e| &e.message_id != message_id);
            if slot.len() == before {
                return Err(MailboxError::NotFound);
            }
            if slot.is_empty() {
                self.store.remove(&hash);
            }
            Ok(())
        } else {
            Err(MailboxError::NotFound)
        }
    }

    /// Sweep all slots and remove expired envelopes. Call periodically
    /// (e.g. every hour on a relay node) to reclaim memory.
    pub fn sweep_expired(&mut self) {
        self.store.retain(|_, slot| {
            slot.retain(|e| !e.is_expired());
            !slot.is_empty()
        });
    }

    /// Number of pending envelopes for a recipient.
    pub fn pending_count(&self, recipient_fingerprint: &str) -> usize {
        let hash = *blake3::hash(recipient_fingerprint.as_bytes()).as_bytes();
        self.store.get(&hash).map(|s| s.len()).unwrap_or(0)
    }

    /// Total number of envelopes stored across all recipients.
    pub fn total_count(&self) -> usize {
        self.store.values().map(|s| s.len()).sum()
    }
}

impl Default for RelayMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-side pending outbound queue.
///
/// When direct delivery to a recipient fails (recipient offline), the sender
/// wraps the already-encrypted ciphertext in a `MailboxEnvelope` and enqueues
/// it here.  On reconnect, the client calls `due()` to get items ready for
/// retry and submits them to the relay over Tor.
///
/// Persistence is the caller's responsibility: serialise with
/// `pending()`/`load_from()` and write to the encrypted local DB.
pub struct OutboundQueue {
    pending: Vec<PendingOutbound>,
}

/// A single queued outbound envelope with retry state.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingOutbound {
    /// The envelope to deliver to the relay.
    pub envelope: MailboxEnvelope,

    /// Onion address of the relay to submit to (e.g. `"abc.onion:8080"`).
    pub relay_address: String,

    /// Number of failed delivery attempts so far.
    pub attempts: u32,

    /// Unix timestamp before which this entry should NOT be retried.
    pub retry_after: u64,
}

impl OutboundQueue {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Enqueue a ciphertext for offline delivery via `relay_address`.
    pub fn enqueue(&mut self, envelope: MailboxEnvelope, relay_address: String) {
        self.pending.push(PendingOutbound {
            envelope,
            relay_address,
            attempts: 0,
            retry_after: 0,
        });
    }

    /// Return references to all entries that are due for a delivery attempt
    /// (retry_after ≤ now, and envelope not yet expired).
    pub fn due(&self) -> Vec<&PendingOutbound> {
        let now = current_timestamp();
        self.pending
            .iter()
            .filter(|p| p.retry_after <= now && !p.envelope.is_expired())
            .collect()
    }

    /// Record a delivery attempt result.
    ///
    /// On success the entry is removed.  On failure the entry's
    /// `retry_after` is set with exponential back-off (30s × 2^n, capped at
    /// 1 hour) so the client does not hammer the relay.
    pub fn record_attempt(&mut self, message_id: &[u8; 32], success: bool) {
        let now = current_timestamp();
        if success {
            self.pending
                .retain(|p| &p.envelope.message_id != message_id);
        } else if let Some(p) = self
            .pending
            .iter_mut()
            .find(|p| &p.envelope.message_id == message_id)
        {
            p.attempts += 1;
            // Exponential backoff: 30 * 2^(attempts-1), max 3600s (1 hour)
            let backoff = 30u64.saturating_mul(1u64 << p.attempts.saturating_sub(1).min(11));
            p.retry_after = now + backoff.min(3600);
        }
    }

    /// Remove all envelopes that have exceeded their TTL.
    pub fn sweep_expired(&mut self) {
        self.pending.retain(|p| !p.envelope.is_expired());
    }

    /// Snapshot of all pending entries (for DB persistence).
    pub fn pending(&self) -> &[PendingOutbound] {
        &self.pending
    }

    /// Load from a previously serialised snapshot.
    pub fn load_from(items: Vec<PendingOutbound>) -> Self {
        Self { pending: items }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Default for OutboundQueue {
    fn default() -> Self {
        Self::new()
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_envelope(recipient: &str, payload: Vec<u8>) -> MailboxEnvelope {
        MailboxEnvelope::new(recipient, payload, MAILBOX_TTL_SECS).unwrap()
    }

    #[test]
    fn test_store_and_retrieve() {
        let mut mailbox = RelayMailbox::new();
        let env = make_envelope("alice_fp", vec![1, 2, 3]);
        let id = env.message_id;

        mailbox.store(env).unwrap();
        let retrieved = mailbox.retrieve("alice_fp");

        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].message_id, id);
        assert_eq!(retrieved[0].ciphertext, vec![1, 2, 3]);
        // retrieve is destructive — slot must be empty afterwards
        assert_eq!(mailbox.pending_count("alice_fp"), 0);
    }

    #[test]
    fn test_retrieve_is_destructive() {
        let mut mailbox = RelayMailbox::new();
        mailbox.store(make_envelope("bob_fp", vec![42])).unwrap();
        assert_eq!(mailbox.pending_count("bob_fp"), 1);

        let retrieved = mailbox.retrieve("bob_fp");
        assert_eq!(retrieved.len(), 1);
        // Slot emptied — no separate ACK required
        assert_eq!(mailbox.pending_count("bob_fp"), 0);
    }

    #[test]
    fn test_acknowledge_nonexistent_returns_error() {
        let mut mailbox = RelayMailbox::new();
        let id = [0u8; 32];
        assert!(matches!(
            mailbox.acknowledge("nobody", &id),
            Err(MailboxError::NotFound)
        ));
    }

    #[test]
    fn test_max_envelope_size_rejected() {
        let huge = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        let result = MailboxEnvelope::new("fp", huge, MAILBOX_TTL_SECS);
        assert!(matches!(result, Err(MailboxError::MessageTooLarge(_))));
    }

    #[test]
    fn test_mailbox_full_rejected() {
        let mut mailbox = RelayMailbox::new();
        for _ in 0..MAX_PENDING_PER_RECIPIENT {
            mailbox.store(make_envelope("charlie_fp", vec![0])).unwrap();
        }
        let result = mailbox.store(make_envelope("charlie_fp", vec![1]));
        assert!(matches!(result, Err(MailboxError::MailboxFull)));
    }

    #[test]
    fn test_dedup_idempotent() {
        let mut mailbox = RelayMailbox::new();
        let env = make_envelope("dave_fp", vec![99]);
        mailbox.store(env.clone()).unwrap();
        mailbox.store(env).unwrap(); // second submit must not grow the slot
        assert_eq!(mailbox.pending_count("dave_fp"), 1);
    }

    #[test]
    fn test_outbound_queue_success_removes_entry() {
        let mut queue = OutboundQueue::new();
        let env = make_envelope("eve_fp", vec![1, 2, 3]);
        let id = env.message_id;

        queue.enqueue(env, "relay.onion:8080".into());
        assert_eq!(queue.len(), 1);
        assert!(!queue.due().is_empty());

        queue.record_attempt(&id, true);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_outbound_queue_backoff_on_failure() {
        let mut queue = OutboundQueue::new();
        let env = make_envelope("frank_fp", vec![7]);
        let id = env.message_id;

        queue.enqueue(env, "relay.onion:8080".into());
        queue.record_attempt(&id, false);

        let now = current_timestamp();
        let p = queue
            .pending
            .iter()
            .find(|p| p.envelope.message_id == id)
            .unwrap();
        assert!(p.retry_after > now);
        assert_eq!(p.attempts, 1);
        // After first failure: backoff = 30 * 2^0 = 30s
        assert_eq!(p.retry_after, now + 30);
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let env = make_envelope("grace_fp", vec![10, 20, 30]);
        let bytes = env.to_bytes().unwrap();
        let decoded = MailboxEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.message_id, env.message_id);
        assert_eq!(decoded.ciphertext, env.ciphertext);
        assert_eq!(decoded.expires_at, env.expires_at);
    }

    #[test]
    fn test_sweep_expired_removes_old_messages() {
        let mut mailbox = RelayMailbox::new();
        let mut env = make_envelope("henry_fp", vec![1]);
        env.expires_at = 1; // epoch 1 → always expired
        mailbox.store(env).unwrap();

        assert_eq!(mailbox.pending_count("henry_fp"), 1);
        mailbox.sweep_expired();
        assert_eq!(mailbox.pending_count("henry_fp"), 0);
        assert_eq!(mailbox.total_count(), 0);
    }

    #[test]
    fn test_different_recipients_are_isolated() {
        let mut mailbox = RelayMailbox::new();
        mailbox
            .store(make_envelope("alice", vec![1]))
            .unwrap();
        mailbox.store(make_envelope("bob", vec![2])).unwrap();

        let alice_msgs = mailbox.retrieve("alice");
        let bob_msgs = mailbox.retrieve("bob");

        assert_eq!(alice_msgs.len(), 1);
        assert_eq!(alice_msgs[0].ciphertext, vec![1]);
        assert_eq!(bob_msgs.len(), 1);
        assert_eq!(bob_msgs[0].ciphertext, vec![2]);
    }

    #[test]
    fn test_retrieve_filters_expired() {
        let mut mailbox = RelayMailbox::new();
        let mut env = make_envelope("iris_fp", vec![5]);
        env.expires_at = 1; // force expired
        mailbox.store(env).unwrap();

        let retrieved = mailbox.retrieve("iris_fp");
        assert!(retrieved.is_empty());
    }

    #[test]
    fn test_outbound_queue_load_from_roundtrip() {
        let mut queue = OutboundQueue::new();
        queue.enqueue(make_envelope("jack_fp", vec![3]), "r.onion:1".into());
        queue.enqueue(make_envelope("kate_fp", vec![4]), "r.onion:2".into());

        let snapshot = queue.pending().to_vec();
        let restored = OutboundQueue::load_from(snapshot);
        assert_eq!(restored.len(), 2);
    }
}
