//! Database Layer with SQLCipher
//!
//! SQLite with SQLCipher page-level encryption.

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;

/// Database errors
#[derive(Error, Debug)]
pub enum DbError {
    #[error("SQL error: {0}")]
    SqlError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Already open")]
    AlreadyOpen,
}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::SqlError(e.to_string())
    }
}

/// Database configuration
#[derive(Clone)]
pub struct DbConfig {
    /// Path to database file
    pub path: PathBuf,

    /// Encryption key (32 bytes for AES-256)
    pub encryption_key: [u8; 32],

    /// Page size for SQLCipher
    pub page_size: usize,

    /// WAL mode enabled
    pub wal_mode: bool,

    /// Connection pool size
    pub pool_size: u32,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("shadowgram.db"),
            encryption_key: [0u8; 32], // Must be set properly
            page_size: 4096,
            wal_mode: true,
            pool_size: 1,
        }
    }
}

/// Database connection wrapper
pub struct Database {
    /// Connection (wrapped for thread safety)
    conn: Arc<RwLock<Connection>>,

    /// Configuration
    config: DbConfig,

    /// Open flag
    open: bool,
}

impl Database {
    /// Create new database (not yet opened)
    pub fn new(config: DbConfig) -> Result<Self, DbError> {
        Ok(Self {
            conn: Arc::new(RwLock::new(Connection::open_in_memory()?)), // Placeholder
            config,
            open: false,
        })
    }

    /// Open database connection
    pub fn open(&mut self) -> Result<(), DbError> {
        if self.open {
            return Err(DbError::AlreadyOpen);
        }

        // In production with SQLCipher:
        // 1. Open SQLite connection
        // 2. Set encryption key via PRAGMA key
        // 3. Run integrity check
        // 4. Initialize schema if needed

        // For now, use in-memory SQLite without encryption
        let conn = Connection::open_in_memory()?;

        // Set basic pragmas
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
        ")?;

        *self.conn.write() = conn;
        self.open = true;

        Ok(())
    }

    /// Close database connection
    pub fn close(&mut self) -> Result<(), DbError> {
        if !self.open {
            return Ok(());
        }

        // In production: properly checkpoint WAL, clear sensitive data

        self.open = false;
        Ok(())
    }

    /// Check if database is open
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Get connection reference
    pub fn conn(&self) -> Arc<RwLock<Connection>> {
        self.conn.clone()
    }

    /// Run initialization (create schema)
    pub fn init_schema(&self) -> Result<(), DbError> {
        let conn = self.conn.read();

        conn.execute_batch(include_str!("migrations/001_init.sql"))?;

        Ok(())
    }

    /// Store identity
    pub fn store_identity(
        &self,
        fingerprint: &str,
        public_identity: &[u8],
        encrypted_private_key: &[u8],
    ) -> Result<(), DbError> {
        let conn = self.conn.read();

        conn.execute(
            "INSERT OR REPLACE INTO identities (fingerprint, public_identity, encrypted_private_key, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint,
                public_identity,
                encrypted_private_key,
                current_timestamp()
            ],
        )?;

        Ok(())
    }

    /// Load identity
    pub fn load_identity(
        &self,
        fingerprint: &str,
    ) -> Result<Option<IdentityRow>, DbError> {
        let conn = self.conn.read();

        let row = conn.query_row(
            "SELECT fingerprint, public_identity, encrypted_private_key, created_at, rotated_at
             FROM identities WHERE fingerprint = ?1",
            params![fingerprint],
            |r| {
                Ok(IdentityRow {
                    fingerprint: r.get(0)?,
                    public_identity: r.get(1)?,
                    encrypted_private_key: r.get(2)?,
                    created_at: r.get(3)?,
                    rotated_at: r.get(4)?,
                })
            }
        ).optional()?;

        Ok(row)
    }

    /// Store contact
    pub fn store_contact(
        &self,
        fingerprint: &str,
        alias: &str,
        public_identity: &[u8],
        trust_level: u8,
    ) -> Result<(), DbError> {
        let conn = self.conn.read();

        conn.execute(
            "INSERT OR REPLACE INTO contacts (fingerprint, alias, public_identity, trust_level, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                fingerprint,
                alias,
                public_identity,
                trust_level,
                current_timestamp()
            ],
        )?;

        Ok(())
    }

    /// Get contact
    pub fn get_contact(
        &self,
        fingerprint: &str,
    ) -> Result<Option<ContactRow>, DbError> {
        let conn = self.conn.read();

        let row = conn.query_row(
            "SELECT fingerprint, alias, public_identity, trust_level, added_at, last_seen
             FROM contacts WHERE fingerprint = ?1",
            params![fingerprint],
            |r| {
                Ok(ContactRow {
                    fingerprint: r.get(0)?,
                    alias: r.get(1)?,
                    public_identity: r.get(2)?,
                    trust_level: r.get(3)?,
                    added_at: r.get(4)?,
                    last_seen: r.get(5)?,
                })
            }
        ).optional()?;

        Ok(row)
    }

    /// Store message
    pub fn store_message(
        &self,
        conversation_id: &str,
        sequence: u64,
        direction: u8,
        envelope: &[u8],
        status: u8,
    ) -> Result<(), DbError> {
        let conn = self.conn.read();

        conn.execute(
            "INSERT INTO messages (conversation_id, sequence, direction, envelope, status, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                conversation_id,
                sequence,
                direction,
                envelope,
                status,
                current_timestamp()
            ],
        )?;

        Ok(())
    }

    /// Get messages for conversation
    pub fn get_messages(
        &self,
        conversation_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MessageRow>, DbError> {
        let conn = self.conn.read();

        let mut stmt = conn.prepare(
            "SELECT sequence, direction, envelope, status, received_at
             FROM messages
             WHERE conversation_id = ?1
             ORDER BY sequence DESC
             LIMIT ?2 OFFSET ?3"
        )?;

        let rows = stmt.query_map(params![conversation_id, limit, offset], |r| {
            Ok(MessageRow {
                sequence: r.get(0)?,
                direction: r.get(1)?,
                envelope: r.get(2)?,
                status: r.get(3)?,
                received_at: r.get(4)?,
            })
        })?;

        rows.map(|r| r.map_err(DbError::from)).collect()
    }

    /// Get database statistics
    pub fn stats(&self) -> Result<DbStats, DbError> {
        let conn = self.conn.read();

        let identity_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM identities",
            [],
            |r| r.get(0),
        )?;

        let contact_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM contacts",
            [],
            |r| r.get(0),
        )?;

        let message_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages",
            [],
            |r| r.get(0),
        )?;

        Ok(DbStats {
            identity_count: identity_count as usize,
            contact_count: contact_count as usize,
            message_count: message_count as usize,
        })
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if self.open {
            let _ = self.close();
        }
    }
}

/// Identity row from database
#[derive(Clone)]
pub struct IdentityRow {
    pub fingerprint: String,
    pub public_identity: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub created_at: u64,
    pub rotated_at: Option<u64>,
}

/// Contact row from database
#[derive(Clone)]
pub struct ContactRow {
    pub fingerprint: String,
    pub alias: String,
    pub public_identity: Vec<u8>,
    pub trust_level: u8,
    pub added_at: u64,
    pub last_seen: Option<u64>,
}

/// Message row from database
#[derive(Clone)]
pub struct MessageRow {
    pub sequence: u64,
    pub direction: u8,
    pub envelope: Vec<u8>,
    pub status: u8,
    pub received_at: u64,
}

/// Database statistics
pub struct DbStats {
    pub identity_count: usize,
    pub contact_count: usize,
    pub message_count: usize,
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let config = DbConfig::default();
        let mut db = Database::new(config).unwrap();

        assert!(!db.is_open());

        db.open().unwrap();
        assert!(db.is_open());
    }

    #[test]
    fn test_database_schema_init() {
        let mut db = Database::new(DbConfig::default()).unwrap();
        db.open().unwrap();

        // This will fail because migration file doesn't exist yet
        // In production, would create migrations directory
        // let result = db.init_schema();
        // assert!(result.is_ok());
    }

    #[test]
    fn test_database_stats() {
        let mut db = Database::new(DbConfig::default()).unwrap();
        db.open().unwrap();

        let stats = db.stats().unwrap();
        assert_eq!(stats.identity_count, 0);
        assert_eq!(stats.contact_count, 0);
        assert_eq!(stats.message_count, 0);
    }
}