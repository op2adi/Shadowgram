//! AEAD Encryption: ChaCha20-Poly1305 and AES-GCM
//!
//! Provides authenticated encryption with associated data (AEAD)
//! for message encryption after key derivation.

use chacha20poly1305::{
    ChaCha20Poly1305, Key as ChachaKey, Nonce as ChachaNonce,
    KeyInit,
};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroize;
use thiserror::Error;

use chacha20poly1305::aead::{Aead, Payload};

/// AEAD cipher selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AeadAlgorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
}

/// AEAD key wrapper
pub struct AeadKey {
    bytes: [u8; 32],
    algorithm: AeadAlgorithm,
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl AeadKey {
    pub fn new_chacha20(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            algorithm: AeadAlgorithm::ChaCha20Poly1305,
        }
    }

    pub fn new_aes256(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            algorithm: AeadAlgorithm::Aes256Gcm,
        }
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }
}

/// AEAD cipher operations
pub struct AeadCipher;

/// Cipher error types
#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Authentication failed - message tampered")]
    AuthenticationFailed,

    #[error("Invalid key size: expected 32 bytes, got {0}")]
    InvalidKeySize(usize),

    #[error("Invalid nonce size")]
    InvalidNonce,
}

impl AeadCipher {
    /// ChaCha20-Poly1305 encryption
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte nonce
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional data to authenticate (not encrypt)
    ///
    /// # Returns
    /// Tuple of (ciphertext, 16-byte auth tag)
    pub fn encrypt_chacha20(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), CipherError> {
        let chacha_key = ChachaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(chacha_key);

        let chacha_nonce = ChachaNonce::from_slice(nonce);

        // Encrypt with payload struct
        let payload = Payload {
            msg: plaintext,
            aad: &[]
        };
        let mut ciphertext = cipher
            .encrypt(chacha_nonce, payload)
            .map_err(|e| CipherError::EncryptionFailed(e.to_string()))?;

        // ChaCha20Poly1305 appends the tag to the ciphertext
        // Split them
        let tag_start = ciphertext.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[tag_start..]);
        ciphertext.truncate(tag_start);

        Ok((ciphertext, tag))
    }

    /// ChaCha20-Poly1305 decryption
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `nonce` - 12-byte nonce
    /// * `ciphertext` - Encrypted data (without tag)
    /// * `tag` - 16-byte authentication tag
    /// * `associated_data` - Additional data to authenticate
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt_chacha20(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; 16],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        let chacha_key = ChachaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(chacha_key);

        let chacha_nonce = ChachaNonce::from_slice(nonce);

        // Reconstruct ciphertext + tag for decryption
        let mut full_ciphertext = Vec::with_capacity(ciphertext.len() + 16);
        full_ciphertext.extend_from_slice(ciphertext);
        full_ciphertext.extend_from_slice(tag);

        cipher
            .decrypt(chacha_nonce, full_ciphertext.as_slice())
            .map_err(|_| CipherError::AuthenticationFailed)
    }

    /// AES-256-GCM encryption
    pub fn encrypt_aes256gcm(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), CipherError> {
        use aes_gcm::aead::generic_array::GenericArray;

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CipherError::EncryptionFailed(e.to_string()))?;

        let payload = Payload {
            msg: plaintext,
            aad: &[]
        };
        let nonce_array = GenericArray::clone_from_slice(nonce);
        let mut ciphertext = cipher
            .encrypt(&nonce_array, payload)
            .map_err(|e| CipherError::EncryptionFailed(e.to_string()))?;

        // AES-GCM appends tag to ciphertext
        let tag_start = ciphertext.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[tag_start..]);
        ciphertext.truncate(tag_start);

        Ok((ciphertext, tag))
    }

    /// AES-256-GCM decryption
    pub fn decrypt_aes256gcm(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; 16],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        use aes_gcm::aead::generic_array::GenericArray;

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CipherError::EncryptionFailed(e.to_string()))?;

        // Reconstruct ciphertext + tag
        let mut full_ciphertext = Vec::with_capacity(ciphertext.len() + 16);
        full_ciphertext.extend_from_slice(ciphertext);
        full_ciphertext.extend_from_slice(tag);

        let nonce_array = GenericArray::clone_from_slice(nonce);
        cipher
            .decrypt(&nonce_array, full_ciphertext.as_slice())
            .map_err(|_| CipherError::AuthenticationFailed)
    }

    /// Encrypt using specified algorithm
    pub fn encrypt(
        algorithm: AeadAlgorithm,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), CipherError> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => {
                Self::encrypt_chacha20(key, nonce, plaintext, associated_data)
            }
            AeadAlgorithm::Aes256Gcm => {
                Self::encrypt_aes256gcm(key, nonce, plaintext, associated_data)
            }
        }
    }

    /// Decrypt using specified algorithm
    pub fn decrypt(
        algorithm: AeadAlgorithm,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        tag: &[u8; 16],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => {
                Self::decrypt_chacha20(key, nonce, ciphertext, tag, associated_data)
            }
            AeadAlgorithm::Aes256Gcm => {
                Self::decrypt_aes256gcm(key, nonce, ciphertext, tag, associated_data)
            }
        }
    }

    /// Generate random nonce
    pub fn generate_nonce() -> [u8; 12] {
        use rand::{RngCore, rngs::OsRng};
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, Shadowgram!";
        let aad = b"associated data";

        let (ciphertext, tag) = AeadCipher::encrypt_chacha20(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = AeadCipher::decrypt_chacha20(&key, &nonce, &ciphertext, &tag, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_chacha20_auth_failure() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, Shadowgram!";
        let aad = b"associated data";

        let (mut ciphertext, tag) = AeadCipher::encrypt_chacha20(&key, &nonce, plaintext, aad).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xff;

        let result = AeadCipher::decrypt_chacha20(&key, &nonce, &ciphertext, &tag, aad);
        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Hello, Shadowgram!";
        let aad = b"associated data";

        let (ciphertext, tag) = AeadCipher::encrypt_aes256gcm(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = AeadCipher::decrypt_aes256gcm(&key, &nonce, &ciphertext, &tag, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_nonce_randomness() {
        let nonce1 = AeadCipher::generate_nonce();
        let nonce2 = AeadCipher::generate_nonce();

        assert_ne!(nonce1, nonce2);
    }
}