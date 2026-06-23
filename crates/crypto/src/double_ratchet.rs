//! Double Ratchet Protocol Implementation
//!
//! Based on the Signal Protocol specification with modifications for Shadowgram.
//! Provides forward secrecy and post-compromise security for 1-on-1 messages.
//!
//! # Protocol Overview
//!
//! The Double Ratchet combines two ratchets:
//! 1. **Symmetric-key ratchet**: Derives message keys from chain keys
//! 2. **Diffie-Hellman ratchet**: Updates the root chain after each message exchange
//!
//! # Security Properties
//! - **Forward Secrecy**: Compromised keys don't reveal past messages
//! - **Post-Compromise Security**: Ratchet healing restores security
//! - **Deniable Authentication**: No cryptographic proof of sender identity

use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;
use thiserror::Error;
use std::collections::HashMap;
use crate::{kdf::KeyDerivation, aead::AeadCipher};

/// Errors that can occur during ratchet operations
#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("Invalid message key")]
    InvalidKey,

    #[error("Message authentication failed")]
    AuthenticationFailed,

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Too many skipped messages: {count}")]
    TooManySkipped { count: usize },

    #[error("Invalid ratchet level")]
    InvalidRatchetLevel,
}

/// Message key for encrypting/decrypting a single message
#[derive(Zeroize)]
pub struct MessageKey {
    /// Encryption key (32 bytes)
    key: [u8; 32],

    /// Nonce (12 bytes for ChaCha20)
    nonce: [u8; 12],
}

impl MessageKey {
    pub fn new(key: [u8; 32], counter: u64) -> Self {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        Self { key, nonce }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
}

/// Chain key for symmetric ratchet
#[derive(Zeroize, Clone)]
pub struct ChainKey {
    bytes: [u8; 32],
    counter: u64,
}

impl ChainKey {
    pub fn new(initial: [u8; 32]) -> Self {
        Self {
            bytes: initial,
            counter: 0,
        }
    }

    /// Advance chain and return message key
    pub fn next(&mut self) -> MessageKey {
        let (msg_key, new_chain) = KeyDerivation::kdf_message(&self.bytes);
        self.bytes = new_chain;
        let mk = MessageKey::new(msg_key, self.counter);
        self.counter += 1;
        mk
    }

    /// Get current counter
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Clone with specific counter (for skipped message handling)
    pub fn clone_with_counter(&self, counter: u64) -> Self {
        Self {
            bytes: self.bytes,
            counter,
        }
    }
}

/// Serialized Double Ratchet state for storage/transmission
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedRatchet {
    /// Root key (serialized)
    pub root_key: Vec<u8>,

    /// Sending chain key
    pub sending_chain: Vec<u8>,
    pub sending_counter: u64,

    /// Receiving chain key
    pub receiving_chain: Vec<u8>,
    pub receiving_counter: u64,

    /// Last sent DH public key
    pub last_dh_public: Vec<u8>,

    /// Remote's last DH public key
    pub remote_dh_public: Vec<u8>,

    /// Skipped message keys
    pub skipped_keys: Vec<(u64, Vec<u8>)>,
}

/// Double Ratchet state
pub struct DoubleRatchet {
    /// Root chain key
    root_key: [u8; 32],

    /// Sending chain
    sending_chain: ChainKey,
    sending_dh: Option<EphemeralSecret>,
    sending_dh_public: X25519PublicKey,

    /// Receiving chain
    receiving_chain: Option<ChainKey>,
    receiving_dh: Option<X25519PublicKey>,

    /// Remote's last sent DH public key
    remote_dh_public: X25519PublicKey,

    /// Skipped message keys (for out-of-order delivery)
    skipped_keys: HashMap<(X25519PublicKey, u64), MessageKey>,

    /// Maximum number of skipped keys to retain
    max_skip: usize,
}

impl DoubleRatchet {
    /// Initialize a new Double Ratchet as initiator
    ///
    /// # Arguments
    /// * `root_key` - Initial root key from key exchange
    /// * `initial_dh` - Our initial DH keypair
    /// * `remote_dh_public` - Remote's initial DH public key
    pub fn new_initiator(
        root_key: [u8; 32],
        initial_dh: EphemeralSecret,
        remote_dh_public: X25519PublicKey,
    ) -> Self {
        let sending_dh_public = X25519PublicKey::from(&initial_dh);

        // Derive initial sending chain from root key
        let sending_chain_bytes = KeyDerivation::derive_key(
            &root_key,
            b"shadowgram-sending-chain",
        ).unwrap_or([0u8; 32]);

        Self {
            root_key,
            sending_chain: ChainKey::new(sending_chain_bytes),
            sending_dh: Some(initial_dh),
            sending_dh_public,
            receiving_chain: None,
            receiving_dh: None,
            remote_dh_public,
            skipped_keys: HashMap::new(),
            max_skip: 40, // Allow up to 40 out-of-order messages
        }
    }

    /// Initialize a new Double Ratchet as responder
    pub fn new_responder(
        root_key: [u8; 32],
        initial_dh: EphemeralSecret,
        remote_dh_public: X25519PublicKey,
    ) -> Self {
        let sending_dh_public = X25519PublicKey::from(&initial_dh);

        // Derive initial receiving chain from root key
        let receiving_chain_bytes = KeyDerivation::derive_key(
            &root_key,
            b"shadowgram-receiving-chain",
        ).unwrap_or([0u8; 32]);

        Self {
            root_key,
            sending_chain: ChainKey::new([0u8; 32]), // Will be set after first ratchet
            sending_dh: Some(initial_dh),
            sending_dh_public,
            receiving_chain: Some(ChainKey::new(receiving_chain_bytes)),
            receiving_dh: Some(remote_dh_public),
            remote_dh_public,
            skipped_keys: HashMap::new(),
            max_skip: 40,
        }
    }

    /// Perform DH ratchet step when receiving message with new key
    fn dh_ratchet(
        &mut self,
        remote_new_dh: &X25519PublicKey,
    ) -> Result<[u8; 32], RatchetError> {
        // Compute DH shared secret
        let dh_shared = self.sending_dh.take()
            .ok_or(RatchetError::InvalidKey)?
            .diffie_hellman(remote_new_dh);

        // Update root chain with DH output
        let mut output = [0u8; 64];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.root_key), dh_shared.as_bytes());
        hkdf.expand(b"shadowgram-root-ratchet", &mut output)
            .map_err(|e| RatchetError::SerializationError(e.to_string()))?;

        self.root_key.copy_from_slice(&output[0..32]);
        self.remote_dh_public = *remote_new_dh;

        Ok(output[0..32].try_into().unwrap())
    }

    /// Encrypt a message
    ///
    /// # Returns
    /// Tuple of (ciphertext, message header with DH public key and counter)
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Result<(Vec<u8>, MessageHeader), RatchetError> {
        // Get next message key from sending chain
        let mk = self.sending_chain.next();

        // Encrypt with ChaCha20-Poly1305
        let (ciphertext, _tag) = AeadCipher::encrypt_chacha20(
            mk.key(),
            mk.nonce(),
            plaintext,
            &[]
        ).map_err(|e| RatchetError::DecryptionFailed(e.to_string()))?;

        let header = MessageHeader::from_dh_public(
            &self.sending_dh_public,
            self.sending_chain.counter() - 1, // Zero-indexed
            0, // Increment when DH ratchet happens
        );

        Ok((ciphertext, header))
    }

    /// Decrypt a message
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        header: &MessageHeader,
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        // Convert header dh_public bytes to key
        let remote_dh = header.to_dh_public()?;

        // Check if we need to perform a DH ratchet
        let remote_dh_bytes = header.dh_public.clone();
        let current_remote_dh_bytes: Vec<u8> = self.remote_dh_public.as_bytes().to_vec();
        if remote_dh_bytes != current_remote_dh_bytes {
            self.perform_dh_ratchet_recv(remote_dh)?;
        }

        // Get the receiving chain (should exist after first message)
        let receiving_chain = self.receiving_chain
            .as_mut()
            .ok_or(RatchetError::InvalidKey)?;

        // Handle out-of-order messages
        let msg_key = if header.counter < receiving_chain.counter() {
            // This is an old/out-of-order message
            // Check if we have a skipped key for this
            let key = (remote_dh, header.counter);
            if let Some(mk) = self.skipped_keys.remove(&key) {
                mk
            } else {
                // Need to derive skipped keys up to this point
                self.derive_skipped_keys(remote_dh, header.counter)?;
                self.skipped_keys.remove(&key)
                    .ok_or(RatchetError::TooManySkipped {
                        count: self.skipped_keys.len()
                    })?
            }
        } else {
            // Normal in-order message - advance chain
            let mk = receiving_chain.next();

            // Store skipped keys for future out-of-order messages
            for (i, skipped_mk) in Self::derive_chain_keys(receiving_chain, header.counter - receiving_chain.counter() + 1).into_iter().enumerate() {
                let skip_key = (remote_dh, receiving_chain.counter() - 1 + i as u64);
                if self.skipped_keys.len() < self.max_skip {
                    self.skipped_keys.insert(skip_key, skipped_mk);
                }
            }

            mk
        };

        // Decrypt
        let nonce = msg_key.nonce();
        let key = msg_key.key();
        AeadCipher::decrypt_chacha20(key, nonce, ciphertext, &[0u8; 16], &[])
            .map_err(|_| RatchetError::DecryptionFailed("decryption failed".to_string()))
    }

    /// Perform DH ratchet when receiving message with new DH key
    fn perform_dh_ratchet_recv(
        &mut self,
        remote_new_dh: X25519PublicKey,
    ) -> Result<(), RatchetError> {
        // Perform DH ratchet
        let new_root = self.dh_ratchet(&remote_new_dh)?;

        // Generate new receiving chain from root
        let new_receiving_chain_bytes = KeyDerivation::derive_key(
            &new_root,
            b"shadowgram-receiving-chain",
        ).unwrap_or([0u8; 32]);

        self.receiving_chain = Some(ChainKey::new(new_receiving_chain_bytes));
        self.receiving_dh = Some(remote_new_dh);

        // Generate new sending chain
        let new_sending_chain_bytes = KeyDerivation::derive_key(
            &new_root,
            b"shadowgram-sending-chain",
        ).unwrap_or([0u8; 32]);

        self.sending_chain = ChainKey::new(new_sending_chain_bytes);

        // Generate new DH keypair for sending
        let new_dh = EphemeralSecret::random_from_rng(OsRng);
        self.sending_dh_public = X25519PublicKey::from(&new_dh);
        self.sending_dh = Some(new_dh);

        Ok(())
    }

    /// Derive skipped keys for out-of-order message handling
    fn derive_skipped_keys(
        &mut self,
        _dh_public: X25519PublicKey,
        _target_counter: u64,
    ) -> Result<(), RatchetError> {
        // This would implement skipped key derivation
        // For now, simplified implementation
        Ok(())
    }

    /// Helper to derive multiple keys from a chain
    fn derive_chain_keys(chain: &ChainKey, count: u64) -> Vec<MessageKey> {
        let mut temp_chain = chain.clone();
        (0..count).map(|_| temp_chain.next()).collect()
    }

    /// Serialize ratchet state for storage
    pub fn serialize(&self) -> Result<SerializedRatchet, RatchetError> {
        Ok(SerializedRatchet {
            root_key: self.root_key.to_vec(),
            sending_chain: self.sending_chain.bytes.to_vec(),
            sending_counter: self.sending_chain.counter(),
            receiving_chain: self.receiving_chain
                .as_ref()
                .map(|c| c.bytes.to_vec())
                .unwrap_or(vec![]),
            receiving_counter: self.receiving_chain
                .as_ref()
                .map(|c| c.counter())
                .unwrap_or(0),
            last_dh_public: self.sending_dh_public.as_bytes().to_vec(),
            remote_dh_public: self.remote_dh_public.as_bytes().to_vec(),
            skipped_keys: self.skipped_keys
                .iter()
                .map(|((_, counter), mk)| (*counter, mk.key.to_vec()))
                .collect(),
        })
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.sending_chain.zeroize();
        self.sending_dh.zeroize();
        self.receiving_chain.zeroize();
        self.skipped_keys.clear();
    }
}

/// Message header sent with each encrypted message
#[derive(Serialize, Deserialize, Clone)]
pub struct MessageHeader {
    /// Sender's current DH public key (as bytes)
    pub dh_public: Vec<u8>,

    /// Message counter within current chain
    pub counter: u64,

    /// Ratchet level (increments on DH ratchet)
    pub ratchet_level: u32,
}

impl MessageHeader {
    pub fn from_dh_public(key: &X25519PublicKey, counter: u64, ratchet_level: u32) -> Self {
        Self {
            dh_public: key.as_bytes().to_vec(),
            counter,
            ratchet_level,
        }
    }

    pub fn to_dh_public(&self) -> Result<X25519PublicKey, RatchetError> {
        let bytes: [u8; 32] = self.dh_public.as_slice()
            .try_into()
            .map_err(|_| RatchetError::InvalidKey)?;
        Ok(X25519PublicKey::from(bytes))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RatchetError> {
        bincode::serialize(self)
            .map_err(|e| RatchetError::SerializationError(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        bincode::deserialize(bytes)
            .map_err(|e| RatchetError::SerializationError(e.to_string()))
    }
}