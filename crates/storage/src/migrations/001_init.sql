-- Shadowgram Database Schema
-- Migration: 001_init.sql
-- Description: Initial schema for identities, contacts, conversations, and messages

-- ============================================================================
-- Identities: Store user identities (encrypted private keys)
-- ============================================================================
CREATE TABLE IF NOT EXISTS identities (
    fingerprint TEXT PRIMARY KEY,
    public_identity BLOB NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_identities_active ON identities(is_active);

-- ============================================================================
-- Contacts: Known contacts with their public identities
-- ============================================================================
CREATE TABLE IF NOT EXISTS contacts (
    fingerprint TEXT PRIMARY KEY,
    alias TEXT NOT NULL,
    public_identity BLOB NOT NULL,
    pairwise_id BLOB,
    trust_level INTEGER DEFAULT 0,
    added_at INTEGER NOT NULL,
    last_seen INTEGER,
    notes BLOB,
    is_blocked INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_contacts_alias ON contacts(alias);
CREATE INDEX IF NOT EXISTS idx_contacts_trust ON contacts(trust_level);

-- ============================================================================
-- Conversations: 1-on-1 and group chat metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    type INTEGER NOT NULL,  -- 1=direct, 2=group
    peer_fingerprint TEXT REFERENCES contacts(fingerprint),
    our_identity TEXT REFERENCES identities(fingerprint),
    ratchet_state BLOB,
    last_message_at INTEGER,
    unread_count INTEGER DEFAULT 0,
    is_archived INTEGER DEFAULT 0,
    is_muted INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_conversations_type ON conversations(type);
CREATE INDEX IF NOT EXISTS idx_conversations_peer ON conversations(peer_fingerprint);
CREATE INDEX IF NOT EXISTS idx_conversations_last ON conversations(last_message_at DESC);

-- ============================================================================
-- Messages: Encrypted message storage
-- ============================================================================
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL REFERENCES conversations(id),
    sequence INTEGER NOT NULL,
    direction INTEGER NOT NULL,  -- 1=incoming, 2=outgoing
    envelope BLOB NOT NULL,
    status INTEGER DEFAULT 0,  -- 0=composed, 1=sending, 2=sent, 3=delivered, 4=read, 5=failed
    received_at INTEGER NOT NULL,
    UNIQUE(conversation_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_sequence ON messages(conversation_id, sequence);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at DESC);

-- ============================================================================
-- Group Members: Membership in group conversations
-- ============================================================================
CREATE TABLE IF NOT EXISTS group_members (
    conversation_id TEXT NOT NULL REFERENCES conversations(id),
    member_fingerprint TEXT NOT NULL,
    role INTEGER DEFAULT 0,  -- 0=member, 1=admin, 2=creator
    joined_at INTEGER NOT NULL,
    left_at INTEGER,
    PRIMARY KEY (conversation_id, member_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_group_members_conversation ON group_members(conversation_id);

-- ============================================================================
-- Devices: Known devices for multi-device sync
-- ============================================================================
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    public_key BLOB NOT NULL,
    key_share BLOB,
    registered_at INTEGER NOT NULL,
    last_sync INTEGER,
    is_current INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_devices_current ON devices(is_current);

-- ============================================================================
-- Pending Sync: Operations waiting to be synced
-- ============================================================================
CREATE TABLE IF NOT EXISTS pending_sync (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_type TEXT NOT NULL,
    operation_data BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    retry_count INTEGER DEFAULT 0,
    last_attempt INTEGER
);

CREATE INDEX IF NOT EXISTS idx_pending_sync_type ON pending_sync(operation_type);
CREATE INDEX IF NOT EXISTS idx_pending_sync_created ON pending_sync(created_at);

-- ============================================================================
-- Settings: User preferences (encrypted)
-- ============================================================================
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    encrypted_value BLOB,
    updated_at INTEGER NOT NULL
);

-- ============================================================================
-- Metadata: Database metadata and versioning
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_versions (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    description TEXT
);

-- Insert current version
INSERT OR REPLACE INTO schema_versions (version, applied_at, description)
VALUES (1, strftime('%s', 'now'), 'Initial schema');

-- ============================================================================
-- Views for common queries
-- ============================================================================

-- Active conversations with last message preview
CREATE VIEW IF NOT EXISTS v_conversations_preview AS
SELECT
    c.id,
    c.type,
    c.peer_fingerprint,
    ct.alias as peer_alias,
    c.last_message_at,
    c.unread_count,
    (SELECT m.envelope FROM messages m
     WHERE m.conversation_id = c.id
     ORDER BY m.sequence DESC LIMIT 1) as last_message_envelope
FROM conversations c
LEFT JOIN contacts ct ON c.peer_fingerprint = ct.fingerprint
WHERE c.is_archived = 0
ORDER BY c.last_message_at DESC;

-- ============================================================================
-- Triggers for maintaining consistency
-- ============================================================================

-- Update conversation last_message_at when new message arrives
CREATE TRIGGER IF NOT EXISTS trg_update_conversation_on_message
AFTER INSERT ON messages
BEGIN
    UPDATE conversations
    SET last_message_at = NEW.received_at
    WHERE id = NEW.conversation_id;
END;

-- Increment unread count on incoming messages
CREATE TRIGGER IF NOT EXISTS trg_increment_unread
AFTER INSERT ON messages
WHEN NEW.direction = 1
BEGIN
    UPDATE conversations
    SET unread_count = unread_count + 1
    WHERE id = NEW.conversation_id;
END;