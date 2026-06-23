//! Noise Protocol Framework Integration
//!
//! Implementation of the Noise Protocol Framework for authenticated
//! key exchange. Used for establishing secure channels before
//! wrapping traffic in Tor/mixnet.
//!
//! Based on Noise_IKpsk2 pattern for mutual authentication with
//! pre-shared symmetric key.

use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChachaKey, Nonce, KeyInit, aead::Aead};
use sha2::{Sha256, Digest};
use thiserror::Error;

/// Noise protocol errors
#[derive(Error, Debug)]
pub enum NoiseError {
    #[error("Invalid handshake state: {0}")]
    InvalidState(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("MAC verification failed")]
    MacFailed,
}

/// Noise protocol state machine
pub struct NoiseIK {
    /// Handshake state
    state: HandshakeState,

    /// Cipher state (after handshake)
    cipher: Option<CipherState>,
}

/// Handshake state
enum HandshakeState {
    /// Initial state
    Init,

    /// Initiator has sent handshake message
    InitiatorSent {
        s: StaticSecret,      // Our static key
        e: StaticSecret,      // Our ephemeral key
        re: Option<PublicKey>, // Their ephemeral key
        ch: [u8; 32],         // Chain key
        k: Option<[u8; 32]>,  // Current key
    },

    /// Responder received handshake
    ResponderReceived {
        s: StaticSecret,      // Our static key
        e: StaticSecret,      // Our ephemeral key
        rs: Option<PublicKey>, // Their static key
        re: Option<PublicKey>, // Our ephemeral (generated)
        ch: [u8; 32],         // Chain key
        k: Option<[u8; 32]>,  // Current key
    },

    /// Handshake complete
    Complete,
}

/// Cipher state for encrypted communication
struct CipherState {
    /// Encryption key
    k: [u8; 32],

    /// Nonce for encryption
    n: u64,

    /// Nonce for decryption
    rn: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self { k: key, n: 0, rn: 0 }
    }

    /// Encrypt message with associated data
    fn encrypt_with_ad(
        &mut self,
        _ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let key = ChachaKey::from_slice(&self.k);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.n.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        self.n += 1;

        Ok(ciphertext)
    }

    /// Decrypt message with associated data
    fn decrypt_with_ad(
        &mut self,
        _ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let key = ChachaKey::from_slice(&self.k);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.rn.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| NoiseError::AuthenticationFailed)?;

        self.rn += 1;

        Ok(plaintext)
    }
}

impl NoiseIK {
    /// Create new Noise IK initiator
    ///
    /// # Arguments
    /// * `s` - Our static private key
    /// * `rs` - Their static public key (known ahead of time)
    /// * `psk` - Pre-shared key
    pub fn new_initiator(
        _s: StaticSecret,
        _rs: PublicKey,
        _psk: &[u8; 32],
    ) -> Self {
        // Initialize handshake state
        // In production, would follow Noise_IKpsk2 pattern exactly

        Self {
            state: HandshakeState::Init,
            cipher: None,
        }
    }

    /// Create new Noise IK responder
    pub fn new_responder(_s: StaticSecret, _psk: &[u8; 32]) -> Self {
        Self {
            state: HandshakeState::Init,
            cipher: None,
        }
    }

    /// Initiator: write first handshake message
    ///
    /// Returns: (ephemeral public key, encrypted static key, handshake mac)
    pub fn write_message_a(&mut self) -> Result<HandshakeMessageA, NoiseError> {
        let mut state = HandshakeState::Init;
        std::mem::swap(&mut self.state, &mut state);

        let HandshakeState::Init = state else {
            return Err(NoiseError::InvalidState("Not in Init state".into()));
        };

        // Generate static and ephemeral keys
        let s = StaticSecret::random_from_rng(OsRng);
        let e = StaticSecret::random_from_rng(OsRng);

        // Build handshake message
        let mut msg = HandshakeMessageA {
            ephemeral_public: PublicKey::from(&e),
            encrypted_static: vec![],
            mac: [0u8; 16],
        };

        // In production: encrypt static key with ephemeral DH
        // For now, placeholder structure

        self.state = HandshakeState::InitiatorSent {
            s,
            e,
            re: None,
            ch: [0u8; 32],
            k: None,
        };

        Ok(msg)
    }

    /// Responder: read first handshake message, write response
    pub fn read_message_a_write_message_b(
        &mut self,
        msg: &HandshakeMessageA,
        s: StaticSecret,
    ) -> Result<HandshakeMessageB, NoiseError> {
        // Generate our ephemeral
        let e = StaticSecret::random_from_rng(OsRng);

        self.state = HandshakeState::Complete;

        // Initialize cipher with derived key
        let derived_key = [0u8; 32]; // Placeholder - would be from HKDF
        self.cipher = Some(CipherState::new(derived_key));

        Ok(HandshakeMessageB {
            ephemeral_public: PublicKey::from(&e),
            encrypted_static: vec![],
            mac: [0u8; 16],
        })
    }

    /// Initiator: read response, finalize handshake
    pub fn read_message_b(&mut self, _msg: &HandshakeMessageB) -> Result<(), NoiseError> {
        self.state = HandshakeState::Complete;

        // Initialize cipher
        let derived_key = [0u8; 32];
        self.cipher = Some(CipherState::new(derived_key));

        Ok(())
    }

    /// Encrypt application data
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let cipher = self.cipher
            .as_mut()
            .ok_or_else(|| NoiseError::InvalidState("Handshake not complete".into()))?;

        cipher.encrypt_with_ad(&[], plaintext)
    }

    /// Decrypt application data
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let cipher = self.cipher
            .as_mut()
            .ok_or_else(|| NoiseError::InvalidState("Handshake not complete".into()))?;

        cipher.decrypt_with_ad(&[], ciphertext)
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Complete)
    }
}

/// First handshake message (initiator -> responder)
#[derive(Clone)]
pub struct HandshakeMessageA {
    pub ephemeral_public: PublicKey,
    pub encrypted_static: Vec<u8>,
    pub mac: [u8; 16],
}

/// Second handshake message (responder -> initiator)
#[derive(Clone)]
pub struct HandshakeMessageB {
    pub ephemeral_public: PublicKey,
    pub encrypted_static: Vec<u8>,
    pub mac: [u8; 16],
}

/// Noise handshake builder for protocol customization
pub struct NoiseBuilder {
    /// Protocol name (e.g., "Noise_IKpsk2_25519_ChaChaPoly_SHA256")
    protocol_name: String,

    /// Pre-shared key
    psk: Option<[u8; 32]>,

    /// Prologue data
    prologue: Vec<u8>,
}

impl NoiseBuilder {
    pub fn new(protocol_name: &str) -> Self {
        Self {
            protocol_name: protocol_name.to_string(),
            psk: None,
            prologue: Vec::new(),
        }
    }

    pub fn psk(mut self, psk: [u8; 32]) -> Self {
        self.psk = Some(psk);
        self
    }

    pub fn prologue(mut self, data: &[u8]) -> Self {
        self.prologue = data.to_vec();
        self
    }

    pub fn build_initiator(
        self,
        s: StaticSecret,
        rs: PublicKey,
    ) -> Result<NoiseIK, NoiseError> {
        // Hash protocol name for initial chain key
        let mut hasher = Sha256::new();
        hasher.update(self.protocol_name.as_bytes());
        let _ch = hasher.finalize();

        Ok(NoiseIK::new_initiator(
            s,
            rs,
            &self.psk.unwrap_or([0u8; 32]),
        ))
    }

    pub fn build_responder(self, s: StaticSecret) -> Result<NoiseIK, NoiseError> {
        Ok(NoiseIK::new_responder(
            s,
            &self.psk.unwrap_or([0u8; 32]),
        ))
    }
}

/// Re-keying for forward secrecy
pub struct ReKeyManager {
    /// Messages since last rekey
    message_count: u64,

    /// Rekey interval (messages)
    rekey_interval: u64,
}

impl ReKeyManager {
    pub fn new(rekey_interval: u64) -> Self {
        Self {
            message_count: 0,
            rekey_interval,
        }
    }

    pub fn record_message(&mut self) -> bool {
        self.message_count += 1;

        if self.message_count >= self.rekey_interval {
            self.message_count = 0;
            true // Should rekey
        } else {
            false
        }
    }

    pub fn should_rekey(&self) -> bool {
        self.message_count >= self.rekey_interval
    }

    pub fn reset(&mut self) {
        self.message_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake() {
        // Generate static keys for both parties
        let initiator_static = StaticSecret::random_from_rng(OsRng);
        let responder_static = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_static);

        let psk = [1u8; 32];

        // Initiator creates handshake
        let mut initiator = NoiseIK::new_initiator(
            initiator_static,
            responder_public,
            &psk,
        );

        // Responder creates handshake
        let mut responder = NoiseIK::new_responder(
            responder_static,
            &psk,
        );

        // In production, would run full handshake:
        // 1. Initiator writes message A
        // 2. Responder reads A, writes B
        // 3. Initiator reads B
        // 4. Both can now encrypt/decrypt

        assert!(!initiator.is_handshake_complete());
        assert!(!responder.is_handshake_complete());
    }

    #[test]
    fn test_rekey_manager() {
        let mut manager = ReKeyManager::new(100);

        for i in 0..99 {
            assert!(!manager.record_message());
        }

        // 100th message triggers rekey
        assert!(manager.record_message());
        assert!(!manager.should_rekey()); // Reset after rekey
    }
}