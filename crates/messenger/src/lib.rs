//! Shadowgram Messenger Protocol
//!
//! High-level messaging API providing:
//! - 1-on-1 encrypted chats (Double Ratchet)
//! - Group chats (MLS TreeKEM)
//! - Contact discovery
//! - Multi-device synchronization

pub mod client;
pub mod chat;
pub mod group;
pub mod message;
pub mod contacts;
pub mod sync;
pub mod psi;

// Re-exports
pub use client::{Client, ClientConfig, ClientError};
pub use chat::{Chat, ChatSession, ChatError, ChatState, ChatStats};
pub use message::{
    Message, MessageEnvelope, MessageStatus, MessageType as MsgType,
    MessageDirection, MessageBatch, MessagePriority, MessageHeader, MessageError,
};
pub use contacts::{Contact, ContactStore, ContactDiscovery, TrustLevel};
pub use group::{GroupState, GroupInfo, GroupMember, MemberRole, Commit, GroupError};
pub use sync::{DeviceSync, SyncError, DeviceInfo, SyncOperation};
pub use psi::{PsiProtocol, ContactDiscoveryPSI, PsiResult, ContactFingerprint};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");