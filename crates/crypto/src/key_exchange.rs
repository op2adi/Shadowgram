//! Hybrid Key Exchange: X25519 + ML-KEM-768
//!
//! This module implements a hybrid key exchange combining:
//! - X25519 (elliptic curve Diffie-Hellman) for classical security
//! - ML-KEM-768 for post-quantum security
//!
//! The hybrid approach ensures security even if one algorithm is broken.

use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ml_kem::{MlKem768, EncapsulationKey, DecapsulationKey, Ciphertext, SharedKey};
use ml_kem::kem::{Encapsulate, Decapsulate, Kem, KeyExport};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;
use thiserror::Error;

use crate::kdf::KeyDerivation;

/// Errors that can occur during key exchange
#[derive(Error, Debug)]
pub enum KeyExchangeError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Decapsulation failed")]
    DecapsulationFailed,

    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Ephemeral keypair for X25519
pub struct EphemeralX25519 {
    secret: Option<EphemeralSecret>,
    public: X25519PublicKey,
}

impl EphemeralX25519 {
    /// Generate a new ephemeral keypair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret: Some(secret), public }
    }

    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Consume the secret for DH (single use)
    pub fn ecdh_consume(mut self, remote_public: &X25519PublicKey) -> [u8; 32] {
        self.secret.take().unwrap().diffie_hellman(remote_public).to_bytes()
    }
}

impl Drop for EphemeralX25519 {
    fn drop(&mut self) {
        if let Some(ref mut secret) = self.secret {
            secret.zeroize();
        }
    }
}

/// ML-KEM-768 keypair for hybrid exchange
pub struct MlKemKeypair {
    encapsulation_key: EncapsulationKey<MlKem768>,
    decapsulation_key: DecapsulationKey<MlKem768>,
}

impl MlKemKeypair {
    /// Generate a new ML-KEM-768 keypair
    pub fn generate() -> Self {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate();
        Self {
            encapsulation_key,
            decapsulation_key,
        }
    }

    /// Get the encapsulation (public) key
    pub fn encapsulation_key(&self) -> &EncapsulationKey<MlKem768> {
        &self.encapsulation_key
    }

    /// Get the decapsulation (secret) key
    pub fn decapsulation_key(&self) -> &DecapsulationKey<MlKem768> {
        &self.decapsulation_key
    }

    /// Encapsulate a shared key to this keypair
    pub fn encapsulate(&self) -> Result<(Ciphertext<MlKem768>, [u8; 32]), KeyExchangeError> {
        let (ct, shared) = self.encapsulation_key.encapsulate();
        Ok((ct, shared.into()))
    }

    /// Decapsulate a ciphertext to recover the shared key
    pub fn decapsulate(&self, ciphertext: &Ciphertext<MlKem768>) -> Result<[u8; 32], KeyExchangeError> {
        let shared: SharedKey = self.decapsulation_key.decapsulate(ciphertext);
        Ok(shared.into())
    }
}

/// Hybrid keypair: X25519 + ML-KEM-768
pub struct HybridKeypair {
    /// Our ephemeral X25519 secret
    x25519_secret: Option<EphemeralSecret>,

    /// Our ephemeral X25519 public key
    x25519_public: X25519PublicKey,

    /// Our ML-KEM decapsulation (secret) key
    mlkem_decapsulation_key: Option<DecapsulationKey<MlKem768>>,

    /// Our ML-KEM encapsulation (public) key
    mlkem_encapsulation_key: EncapsulationKey<MlKem768>,
}

impl HybridKeypair {
    /// Generate initiator's hybrid keypair (no ML-KEM secret yet)
    pub fn generate_initiator() -> Self {
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM keypair for decapsulation
        let (mlkem_decapsulation_key, mlkem_encapsulation_key) = MlKem768::generate();

        Self {
            x25519_secret: Some(x25519_secret),
            x25519_public,
            mlkem_decapsulation_key: Some(mlkem_decapsulation_key),
            mlkem_encapsulation_key,
        }
    }

    /// Get X25519 public key to send
    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    /// Get ML-KEM encapsulation (public) key
    pub fn mlkem_encapsulation_key(&self) -> &EncapsulationKey<MlKem768> {
        &self.mlkem_encapsulation_key
    }

    /// Process responder's message as initiator
    pub fn initiator_finish(
        &mut self,
        responder_x25519_public: &X25519PublicKey,
        responder_mlkem_ciphertext: &Ciphertext<MlKem768>,
    ) -> Result<SharedSecret, KeyExchangeError> {
        // X25519 shared secret - take ownership to perform DH
        let x25519_secret = self.x25519_secret.take()
            .ok_or(KeyExchangeError::DecapsulationFailed)?;
        let x25519_shared = x25519_secret.diffie_hellman(responder_x25519_public);

        // ML-KEM decapsulation
        let mlkem_decapsulation_key = self.mlkem_decapsulation_key.take()
            .ok_or(KeyExchangeError::DecapsulationFailed)?;

        let mlkem_shared: [u8; 32] = mlkem_decapsulation_key
            .decapsulate(responder_mlkem_ciphertext)
            .into();

        // Combine X25519 and ML-KEM shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&x25519_shared.to_bytes());
        combined[32..].copy_from_slice(&mlkem_shared);

        Ok(SharedSecret::new(combined))
    }
}

impl Drop for HybridKeypair {
    fn drop(&mut self) {
        // Zeroize secret key material
        if let Some(ref mut secret) = self.x25519_secret {
            secret.zeroize();
        }
    }
}

/// Responder's hybrid key exchange state
pub struct HybridResponder {
    x25519_secret: Option<EphemeralSecret>,
    mlkem_decapsulation_key: Option<DecapsulationKey<MlKem768>>,
    mlkem_encapsulation_key: EncapsulationKey<MlKem768>,
    mlkem_ciphertext: Ciphertext<MlKem768>,
}

impl HybridResponder {
    /// Create responder state from initiator's message
    pub fn new(
        initiator_x25519_public: &X25519PublicKey,
        initiator_mlkem_encapsulation_key: &EncapsulationKey<MlKem768>,
    ) -> Result<(Self, Ciphertext<MlKem768>, X25519PublicKey), KeyExchangeError> {
        // Generate X25519 ephemeral keypair
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Compute X25519 shared secret
        let x25519_shared = x25519_secret.diffie_hellman(initiator_x25519_public);

        // Generate ML-KEM keypair
        let (mlkem_decapsulation_key, mlkem_encapsulation_key) = MlKem768::generate();

        // Encapsulate to initiator's ML-KEM public key
        let (mlkem_ciphertext, mlkem_shared) = initiator_mlkem_encapsulation_key
            .encapsulate();

        // Combine shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&x25519_shared.to_bytes());
        combined[32..].copy_from_slice(mlkem_shared.as_ref());

        let responder = Self {
            x25519_secret: Some(x25519_secret),
            mlkem_decapsulation_key: Some(mlkem_decapsulation_key),
            mlkem_encapsulation_key,
            mlkem_ciphertext: mlkem_ciphertext.clone(),
        };

        Ok((responder, mlkem_ciphertext, x25519_public))
    }

    /// Get the ciphertext to send back to initiator
    pub fn ciphertext(&self) -> &Ciphertext<MlKem768> {
        &self.mlkem_ciphertext
    }

    /// Get X25519 public key to send
    pub fn x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.x25519_secret.as_ref().unwrap())
    }

    /// Get ML-KEM encapsulation (public) key
    pub fn mlkem_encapsulation_key(&self) -> &EncapsulationKey<MlKem768> {
        &self.mlkem_encapsulation_key
    }
}

impl Drop for HybridResponder {
    fn drop(&mut self) {
        if let Some(ref mut secret) = self.x25519_secret {
            secret.zeroize();
        }
    }
}

/// Shared secret from hybrid key exchange
#[derive(Zeroize)]
pub struct SharedSecret {
    bytes: [u8; 64],
}

impl SharedSecret {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }

    /// Derive keys from the shared secret using HKDF
    pub fn derive_keys(&self, context: &[u8]) -> Result<[u8; 32], KeyExchangeError> {
        KeyDerivation::hkdf_sha256(&self.bytes, b"shadowgram-handshake", context)
            .ok_or(KeyExchangeError::KeyDerivationFailed)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

/// Serialized message for key exchange
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyExchangeMessage {
    /// X25519 public key (32 bytes, base64)
    pub x25519_public: String,

    /// ML-KEM encapsulation (public) key (serialized, base64)
    pub mlkem_encapsulation_key: String,

    /// ML-KEM ciphertext (if responder, base64)
    pub mlkem_ciphertext: Option<String>,
}

impl KeyExchangeMessage {
    pub fn from_initiator(
        x25519_public: &X25519PublicKey,
        mlkem_encapsulation_key: &EncapsulationKey<MlKem768>,
    ) -> Self {
        Self {
            x25519_public: base64::encode(x25519_public.as_bytes()),
            mlkem_encapsulation_key: base64::encode(mlkem_encapsulation_key.to_bytes()),
            mlkem_ciphertext: None,
        }
    }

    pub fn from_responder(
        x25519_public: &X25519PublicKey,
        mlkem_encapsulation_key: &EncapsulationKey<MlKem768>,
        ciphertext: &Ciphertext<MlKem768>,
    ) -> Self {
        Self {
            x25519_public: base64::encode(x25519_public.as_bytes()),
            mlkem_encapsulation_key: base64::encode(mlkem_encapsulation_key.to_bytes()),
            mlkem_ciphertext: Some(base64::encode(ciphertext.as_bytes())),
        }
    }

    /// Parse initiator's X25519 public key
    pub fn parse_initiator_x25519(&self) -> Result<X25519PublicKey, KeyExchangeError> {
        let bytes: [u8; 32] = base64::decode(&self.x25519_public)
            .map_err(|e| KeyExchangeError::InvalidPublicKey(e.to_string()))?
            .try_into()
            .map_err(|_| KeyExchangeError::InvalidPublicKey("Wrong length".into()))?;
        Ok(X25519PublicKey::from(bytes))
    }

    /// Parse initiator's ML-KEM encapsulation key
    pub fn parse_initiator_mlkem_key(&self) -> Result<EncapsulationKey<MlKem768>, KeyExchangeError> {
        let bytes = base64::decode(&self.mlkem_encapsulation_key)
            .map_err(|e| KeyExchangeError::InvalidPublicKey(e.to_string()))?;
        let bytes_array: [u8; 1568] = bytes
            .try_into()
            .map_err(|_| KeyExchangeError::InvalidPublicKey("Wrong ML-KEM key length".into()))?;
        // Convert raw bytes to Key type using From trait
        let key: ml_kem::Key<MlKem768> = bytes_array.into();
        EncapsulationKey::new(&key)
            .map_err(|e| KeyExchangeError::InvalidPublicKey(e.to_string()))
    }

    /// Parse responder's ML-KEM ciphertext
    pub fn parse_responder_ciphertext(&self) -> Result<Ciphertext<MlKem768>, KeyExchangeError> {
        let bytes = base64::decode(self.mlkem_ciphertext.as_ref()
            .ok_or_else(|| KeyExchangeError::InvalidPublicKey("No ciphertext".into()))?)
            .map_err(|e| KeyExchangeError::InvalidPublicKey(e.to_string()))?;
        let bytes_array: [u8; 1088] = bytes
            .try_into()
            .map_err(|_| KeyExchangeError::InvalidPublicKey("Wrong ML-KEM ciphertext length".into()))?;
        // Convert raw bytes to Ciphertext using From trait
        let ct: ml_kem::Ciphertext<MlKem768> = bytes_array.into();
        Ok(ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        // Initiator starts
        let mut initiator = HybridKeypair::generate_initiator();
        let init_msg = KeyExchangeMessage::from_initiator(
            initiator.x25519_public(),
            initiator.mlkem_encapsulation_key(),
        );

        // Responder processes and creates response
        let their_x25519_public = init_msg.parse_initiator_x25519().unwrap();
        let their_mlkem_key = init_msg.parse_initiator_mlkem_key().unwrap();

        let (responder, ciphertext, responder_x25519_public) =
            HybridResponder::new(&their_x25519_public, &their_mlkem_key).unwrap();

        // Initiator finishes
        let shared_secret = initiator.initiator_finish(&responder_x25519_public, &ciphertext).unwrap();
        assert_eq!(shared_secret.as_bytes().len(), 64);
    }
}