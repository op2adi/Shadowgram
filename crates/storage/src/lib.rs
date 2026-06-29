//! Shadowgram Secure Storage
//!
//! Encrypted local storage using SQLCipher for:
//! - Identity keys (encrypted at rest)
//! - Contact list
//! - Message history
//! - Chat sessions
//!
//! All data is encrypted with per-user keys derived from
//! a master key that can be backed up separately.

pub mod database;
pub mod encrypted_cache;
pub mod schema;

// Re-exports
pub use database::{
    ContactRow, Database, DbConfig, DbError, DbStats, IdentityRow, MessageRow, PendingOutboxRow,
};
pub use encrypted_cache::{CacheEntry, EncryptedCache};
pub use schema::{columns, tables, SCHEMA_VERSION};

/// Storage library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
