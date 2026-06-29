-- Shadowgram Database Schema
-- Migration: 002_relay_mailbox.sql
-- Description: Persistent outbound queue for offline relay delivery

-- ============================================================================
-- Pending outbox: ciphertext envelopes waiting for relay delivery.
--
-- Only the encrypted payload (envelope_bytes) is stored here.
-- The local DB row contains no plaintext and no sender/recipient PII beyond
-- the relay_address used for routing.  The envelope_bytes field is the
-- bincode-serialized MailboxEnvelope (recipient_hash + ciphertext + TTL).
-- ============================================================================
CREATE TABLE IF NOT EXISTS pending_outbox (
    message_id   BLOB PRIMARY KEY,   -- 32-byte random ID (from MailboxEnvelope)
    relay_address TEXT NOT NULL,      -- onion address of the target relay
    envelope_bytes BLOB NOT NULL,     -- bincode(MailboxEnvelope) — ciphertext only
    attempts     INTEGER DEFAULT 0,
    retry_after  INTEGER DEFAULT 0,   -- unix timestamp; 0 = retry immediately
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL     -- unix timestamp; drop row after this
);

CREATE INDEX IF NOT EXISTS idx_pending_outbox_retry  ON pending_outbox(retry_after);
CREATE INDEX IF NOT EXISTS idx_pending_outbox_expiry ON pending_outbox(expires_at);

-- Update schema version
INSERT OR REPLACE INTO schema_versions (version, applied_at, description)
VALUES (2, strftime('%s', 'now'), 'Add pending_outbox for offline relay delivery');
