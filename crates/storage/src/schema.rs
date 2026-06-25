//! Schema Definitions
//!
//! Database schema constants and helpers.

/// Current schema version
pub const SCHEMA_VERSION: u32 = 1;

/// Table names
pub mod tables {
    pub const IDENTITIES: &str = "identities";
    pub const CONTACTS: &str = "contacts";
    pub const CONVERSATIONS: &str = "conversations";
    pub const MESSAGES: &str = "messages";
    pub const GROUP_MEMBERS: &str = "group_members";
    pub const DEVICES: &str = "devices";
    pub const PENDING_SYNC: &str = "pending_sync";
    pub const SETTINGS: &str = "settings";
    pub const SCHEMA_VERSIONS: &str = "schema_versions";
}

/// Column names for common tables
pub mod columns {
    pub mod identities {
        pub const FINGERPRINT: &str = "fingerprint";
        pub const PUBLIC_IDENTITY: &str = "public_identity";
        pub const ENCRYPTED_PRIVATE_KEY: &str = "encrypted_private_key";
        pub const CREATED_AT: &str = "created_at";
        pub const ROTATED_AT: &str = "rotated_at";
        pub const IS_ACTIVE: &str = "is_active";
    }

    pub mod contacts {
        pub const FINGERPRINT: &str = "fingerprint";
        pub const ALIAS: &str = "alias";
        pub const PUBLIC_IDENTITY: &str = "public_identity";
        pub const PAIRWISE_ID: &str = "pairwise_id";
        pub const TRUST_LEVEL: &str = "trust_level";
        pub const ADDED_AT: &str = "added_at";
        pub const LAST_SEEN: &str = "last_seen";
        pub const IS_BLOCKED: &str = "is_blocked";
    }

    pub mod messages {
        pub const ID: &str = "id";
        pub const CONVERSATION_ID: &str = "conversation_id";
        pub const SEQUENCE: &str = "sequence";
        pub const DIRECTION: &str = "direction";
        pub const ENVELOPE: &str = "envelope";
        pub const STATUS: &str = "status";
        pub const RECEIVED_AT: &str = "received_at";
    }

    pub mod conversations {
        pub const ID: &str = "id";
        pub const TYPE: &str = "type";
        pub const PEER_FINGERPRINT: &str = "peer_fingerprint";
        pub const OUR_IDENTITY: &str = "our_identity";
        pub const RATCHET_STATE: &str = "ratchet_state";
        pub const LAST_MESSAGE_AT: &str = "last_message_at";
        pub const UNREAD_COUNT: &str = "unread_count";
        pub const IS_ARCHIVED: &str = "is_archived";
        pub const IS_MUTED: &str = "is_muted";
    }
}

/// Migration definitions
pub struct Migration {
    pub version: u32,
    pub description: &'static str,
    pub sql: &'static str,
}

/// All migrations in order
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "Initial schema",
    sql: include_str!("migrations/001_init.sql"),
}];

/// Get applied migrations from database
pub fn get_applied_migrations(conn: &rusqlite::Connection) -> Result<Vec<u32>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT version FROM schema_versions ORDER BY version")?;
    let versions = stmt.query_map([], |r| r.get(0))?;

    let mut result = Vec::new();
    for v in versions {
        result.push(v?);
    }
    Ok(result)
}

/// Check if migration is needed
pub fn needs_migration(conn: &rusqlite::Connection) -> Result<Option<u32>, rusqlite::Error> {
    let applied = get_applied_migrations(conn)?;

    for migration in MIGRATIONS {
        if !applied.contains(&migration.version) {
            return Ok(Some(migration.version));
        }
    }

    Ok(None)
}

/// Run all pending migrations
pub fn run_migrations(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let mut applied = get_applied_migrations(conn)?;

    for migration in MIGRATIONS {
        if !applied.contains(&migration.version) {
            // Run migration
            conn.execute_batch(migration.sql)?;

            // Record as applied
            conn.execute(
                "INSERT INTO schema_versions (version, applied_at, description)
                 VALUES (?1, strftime('%s', 'now'), ?2)",
                rusqlite::params![migration.version, migration.description],
            )?;

            applied.push(migration.version);
        }
    }

    Ok(())
}
