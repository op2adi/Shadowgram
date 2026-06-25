//! Shadowgram Messenger Protocol
//!
//! High-level messaging API providing:
//! - 1-on-1 encrypted chats (Double Ratchet)
//! - Group chats (MLS TreeKEM)
//! - Contact discovery
//! - Multi-device synchronization

pub mod chat;
pub mod client;
pub mod contacts;
pub mod group;
pub mod message;
pub mod psi;
pub mod sync;

// Re-exports
pub use chat::{Chat, ChatError, ChatSession, ChatState, ChatStats};
pub use client::{Client, ClientConfig, ClientError};
pub use contacts::{Contact, ContactDiscovery, ContactStore, MemoryContactStore, TrustLevel};
pub use group::{Commit, GroupError, GroupInfo, GroupMember, GroupState, MemberRole};
pub use message::{
    Message, MessageBatch, MessageDirection, MessageEnvelope, MessageError, MessageHeader,
    MessagePriority, MessageStatus, MessageType,
};
pub use psi::{ContactDiscoveryPSI, ContactFingerprint, PsiProtocol, PsiResult};
pub use sync::{DeviceInfo, DeviceSync, SyncError, SyncOperation, SyncStatus};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
