//! Identity Generation and Management
//!
//! Each Shadowgram user has an identity consisting of:
//! - X25519 keypair for key exchange
//! - Ed25519 keypair for signing
//! - ML-KEM keypair for post-quantum security
//!
//! Identities are generated locally and never tied to real-world identifiers.

use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519PublicKey};
use ed25519_dalek::{SigningKey as Ed25519Secret, VerifyingKey as Ed25519PublicKey, Signature};
use ml_kem::{MlKem768, DecapsulationKey, EncapsulationKey, KeyExport};
use ed25519_dalek::Verifier;
use serde::{Serialize, Deserialize};
use base64::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;
use blake3::Hasher as Blake3Hasher;

/// Identity generation errors
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid identity format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

/// Complete identity keypair (private - must be protected)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeys {
    /// X25519 secret key for key exchange
    x25519_secret: X25519Secret,

    /// Ed25519 secret key for signing
    #[zeroize(skip)]
    ed25519_secret: Ed25519Secret,

    /// ML-KEM secret key for PQ security
    #[zeroize(skip)]
    mlkem_decapsulation_key: DecapsulationKey<MlKem768>,
}

impl IdentityKeys {
    /// Generate a new identity keypair
    pub fn generate() -> Result<Self, IdentityError> {
        let mut rng = rand::rngs::OsRng;

        // X25519 keypair
        let x25519_secret = X25519Secret::random_from_rng(&mut rng);

        // Ed25519 keypair
        let ed25519_secret = Ed25519Secret::generate(&mut rng);

        // ML-KEM keypair
        let mut seed = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rng, &mut seed);
        let mlkem_decapsulation_key = DecapsulationKey::<MlKem768>::from_seed(seed.into());

        Ok(Self {
            x25519_secret,
            ed25519_secret,
            mlkem_decapsulation_key,
        })
    }

    /// Get X25519 public key
    pub fn x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.x25519_secret)
    }

    /// Get Ed25519 public key
    pub fn ed25519_public(&self) -> Ed25519PublicKey {
        self.ed25519_secret.verifying_key()
    }

    /// Get ML-KEM public key
    pub fn mlkem_encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        self.mlkem_decapsulation_key.encapsulation_key().clone()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.ed25519_secret.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool, IdentityError> {
        use ed25519_dalek::Verifier;
        self.ed25519_secret
            .verifying_key()
            .verify(message, signature)
            .map_err(|_| IdentityError::SignatureVerificationFailed)?;
        Ok(true)
    }
}

/// Public identity (safe to share)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    /// X25519 public key (base64)
    pub x25519_public: String,

    /// Ed25519 public key (base64)
    pub ed25519_public: String,

    /// ML-KEM public key (base64)
    pub mlkem_public: String,

    /// Identity fingerprint (BLAKE3 hash, 8 chars for display)
    pub fingerprint_short: String,

    /// Full fingerprint (hex, 64 chars)
    pub fingerprint_full: String,

    /// Identity signature over the public keys (proves ownership)
    pub self_signature: String,
}

impl PublicIdentity {
    /// Create public identity from keypair
    pub fn from_keys(keys: &IdentityKeys) -> Result<Self, IdentityError> {
        let x25519_public = keys.x25519_public();
        let ed25519_public = keys.ed25519_public();
        let mlkem_public = keys.mlkem_encapsulation_key();

        // Create fingerprint from all public keys
        let mut hasher = Blake3Hasher::new();
        hasher.update(x25519_public.as_bytes());
        hasher.update(ed25519_public.as_bytes());
        hasher.update(&mlkem_public.to_bytes());
        let fingerprint = hasher.finalize();

        let fingerprint_full = hex::encode(fingerprint.as_bytes());
        let fingerprint_short = BASE64_STANDARD.encode(&fingerprint.as_bytes()[..6])
            .chars()
            .take(8)
            .collect();

        // Sign the public identity to prove ownership
        let mut signable = Vec::new();
        signable.extend_from_slice(x25519_public.as_bytes());
        signable.extend_from_slice(ed25519_public.as_bytes());
        signable.extend_from_slice(&mlkem_public.to_bytes());

        let signature = keys.sign(&signable);
        let self_signature = BASE64_STANDARD.encode(signature.to_bytes());

        Ok(Self {
            x25519_public: BASE64_STANDARD.encode(x25519_public.as_bytes()),
            ed25519_public: BASE64_STANDARD.encode(ed25519_public.as_bytes()),
            mlkem_public: BASE64_STANDARD.encode(mlkem_public.to_bytes()),
            fingerprint_short,
            fingerprint_full,
            self_signature,
        })
    }

    /// Verify the self-signature
    pub fn verify_self_signature(&self) -> Result<bool, IdentityError> {
        let x25519_bytes = BASE64_STANDARD.decode(&self.x25519_public)
            .map_err(|e| IdentityError::InvalidFormat(e.to_string()))?;
        let ed25519_bytes = BASE64_STANDARD.decode(&self.ed25519_public)
            .map_err(|e| IdentityError::InvalidFormat(e.to_string()))?;
        let mlkem_bytes = BASE64_STANDARD.decode(&self.mlkem_public)
            .map_err(|e| IdentityError::InvalidFormat(e.to_string()))?;

        let signature_bytes = BASE64_STANDARD.decode(&self.self_signature)
            .map_err(|e| IdentityError::InvalidFormat(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| IdentityError::InvalidFormat("Invalid signature length".into()))?;

        let ed25519_public = Ed25519PublicKey::from_bytes(
            &ed25519_bytes.try_into()
                .map_err(|_| IdentityError::InvalidFormat("Wrong Ed25519 key length".into()))?
        ).map_err(|_| IdentityError::InvalidFormat("Invalid Ed25519 public key".into()))?;

        let mut signable = Vec::new();
        signable.extend_from_slice(&x25519_bytes);
        signable.extend_from_slice(&ed25519_bytes);
        signable.extend_from_slice(&mlkem_bytes);

        ed25519_public
            .verify(&signable, &signature)
            .map_err(|_| IdentityError::SignatureVerificationFailed)?;

        Ok(true)
    }

    /// Get human-readable fingerprint
    pub fn display_fingerprint(&self) -> &str {
        &self.fingerprint_short
    }

    /// Parse public identity from serialized form
    pub fn from_serialized(data: &[u8]) -> Result<Self, IdentityError> {
        bincode::deserialize(data)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        bincode::serialize(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))
    }
}

/// Complete identity (keys + public info)
pub struct Identity {
    /// Private keys (protected)
    keys: IdentityKeys,

    /// Public identity (shareable)
    public: PublicIdentity,

    /// Creation timestamp
    created_at: u64,

    /// Last rotation timestamp
    rotated_at: Option<u64>,
}

impl Identity {
    /// Generate a new identity
    pub fn generate() -> Result<Self, IdentityError> {
        let keys = IdentityKeys::generate()?;
        let public = PublicIdentity::from_keys(&keys)?;

        Ok(Self {
            keys,
            public,
            created_at: current_timestamp(),
            rotated_at: None,
        })
    }

    /// Get public identity
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// Get X25519 public key
    pub fn x25519_public(&self) -> X25519PublicKey {
        self.keys.x25519_public()
    }

    /// Get X25519 secret key reference
    pub fn x25519_secret(&self) -> &X25519Secret {
        &self.keys.x25519_secret
    }

    /// Get Ed25519 public key
    pub fn ed25519_public(&self) -> Ed25519PublicKey {
        self.keys.ed25519_public()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keys.sign(message)
    }

    /// Get rotation timestamp
    pub fn rotated_at(&self) -> Option<u64> {
        self.rotated_at
    }

    /// Get creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Check if identity should be rotated
    pub fn should_rotate(&self, policy: &RotationPolicy) -> bool {
        policy.should_rotate(self.created_at, self.rotated_at)
    }

    /// Serialize identity for secure storage
    pub fn serialize_encrypted(&self, _encryption_key: &[u8; 32]) -> Result<Vec<u8>, IdentityError> {
        // Serialize keys (would be encrypted in production)
        let mut data = Vec::new();
        data.extend(bincode::serialize(&self.public)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?);
        // In production: encrypt private keys before storage
        Ok(data)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

/// Rotation policy for identity keys
pub struct RotationPolicy {
    /// Rotate after this many seconds
    pub rotation_interval: u64,

    /// Warn before rotation (seconds)
    pub warning_threshold: u64,
}

impl RotationPolicy {
    pub fn new(rotation_interval: u64, warning_threshold: u64) -> Self {
        Self {
            rotation_interval,
            warning_threshold,
        }
    }

    /// Default policy: rotate every 30 days
    pub fn default() -> Self {
        Self {
            rotation_interval: 30 * 24 * 60 * 60, // 30 days
            warning_threshold: 7 * 24 * 60 * 60,  // 7 days warning
        }
    }

    fn should_rotate(&self, created_at: u64, rotated_at: Option<u64>) -> bool {
        let now = current_timestamp();
        let base_time = rotated_at.unwrap_or(created_at);
        now - base_time > self.rotation_interval
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate().unwrap();
        assert!(!identity.public().fingerprint_full.is_empty());
    }

    #[test]
    fn test_self_signature_verification() {
        let identity = Identity::generate().unwrap();
        assert!(identity.public().verify_self_signature().is_ok());
    }

    #[test]
    fn test_fingerprint_uniqueness() {
        let id1 = Identity::generate().unwrap();
        let id2 = Identity::generate().unwrap();
        assert_ne!(id1.public().fingerprint_full, id2.public().fingerprint_full);
    }

    #[test]
    fn test_signing() {
        let identity = Identity::generate().unwrap();
        let message = b"Test message";
        let signature = identity.sign(message);
        assert!(identity.keys.verify(message, &signature).unwrap());
    }
}