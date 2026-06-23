//! Shadowgram Identity Management
//!
//! This crate provides identity generation and management:
//! - Long-term identity keypairs (X25519 + Ed25519 + ML-KEM)
//! - Pairwise pseudonyms per contact
//! - QR code generation for identity exchange
//! - Threshold secret sharing for multi-device sync
//!
//! # Privacy Properties
//! - No phone numbers, emails, or usernames required
//! - Identities are cryptographic keypairs only
//! - Pairwise pseudonyms prevent correlation across contacts
//! - Automatic identity rotation limits exposure

pub mod identity;
pub mod pairwise;
pub mod qr;
pub mod threshold;
pub mod rotation;

// Re-export main types
pub use identity::{Identity, IdentityKeys, PublicIdentity, IdentityError};
pub use pairwise::PairwiseIdentity;
pub use qr::{QrCode, QrError};
pub use threshold::{SecretShare, ThresholdConfig, ShareError};
pub use identity::RotationPolicy;
pub use rotation::RotationScheduler;