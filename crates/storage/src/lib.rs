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
pub mod schema;
pub mod encrypted_cache;

// Re-exports
pub use database::{
    Database, DbConfig, DbError,
    IdentityRow, ContactRow, MessageRow, DbStats,
};
pub use schema::{Schema, Tables};
pub use encrypted_cache::{EncryptedCache, CacheEntry};

/// Storage library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");