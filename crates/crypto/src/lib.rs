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

pub mod aead;
pub mod double_ratchet;
pub mod kdf;
pub mod key_exchange;
pub mod keys;

// Re-export main types
pub use aead::{AeadCipher, AeadKey, CipherError};
pub use double_ratchet::{DoubleRatchet, MessageKey, RatchetError};
pub use kdf::KeyDerivation;
pub use key_exchange::{HybridKeypair, KeyExchangeError, SharedSecret};
pub use keys::{KeyMaterial, KeyStore, ZeroizeOnDrop};

// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
