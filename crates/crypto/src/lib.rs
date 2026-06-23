//! Shadowgram Cryptographic Core
//!
//! This crate provides the cryptographic primitives for Shadowgram:
//! - X25519 + ML-KEM-768 hybrid key exchange
//! - Double Ratchet protocol (Signal-style)
//! - AEAD encryption (ChaCha20-Poly1305 / AES-GCM)
//! - Key derivation and management
//!
//! # Security Properties
//! - Forward secrecy: Past messages cannot be decrypted with compromised long-term keys
//! - Post-compromise security: Future messages protected after ratchet healing
//! - Deniable authentication: No cryptographic proof of sender identity to third parties
//!
//! # No Backdoors
//! All cryptographic operations use standard, audited implementations.
//! No hidden randomness, no engineered weaknesses.

pub mod key_exchange;
pub mod double_ratchet;
pub mod aead;
pub mod kdf;
pub mod keys;

// Re-export main types
pub use key_exchange::{HybridKeypair, SharedSecret, KeyExchangeError};
pub use double_ratchet::{DoubleRatchet, RatchetError, MessageKey};
pub use aead::{AeadKey, AeadCipher, CipherError};
pub use kdf::KeyDerivation;
pub use keys::{KeyStore, KeyMaterial, ZeroizeOnDrop};

// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");