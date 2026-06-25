//! Key Derivation Functions
//!
//! HKDF-SHA256 for deriving keys from shared secrets.
//! All key derivation uses a fixed context string "shadowgram"
//! to prevent cross-protocol attacks.

use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use sha2::Sha256;

/// Key derivation operations
pub struct KeyDerivation;

impl KeyDerivation {
    /// HKDF-SHA256 derive key
    ///
    /// # Arguments
    /// * `ikm` - Input keying material (shared secret)
    /// * `salt` - Salt value (use zeros for empty)
    /// * `info` - Context/application-specific info
    ///
    /// # Returns
    /// 32-byte derived key
    pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Option<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = [0u8; 32];
        hkdf.expand(info, &mut okm).ok()?;
        Some(okm)
    }

    /// HKDF-SHA256 with fixed Shadowgram salt
    pub fn derive_key(ikm: &[u8], context: &[u8]) -> Option<[u8; 32]> {
        const SHADOWGRAM_SALT: &[u8] = b"shadowgram-v1-hkdf-salt";
        Self::hkdf_sha256(ikm, SHADOWGRAM_SALT, context)
    }

    /// Derive multiple keys from a single source
    pub fn derive_keys(ikm: &[u8], contexts: &[&[u8]]) -> Option<Vec<[u8; 32]>> {
        contexts
            .iter()
            .map(|ctx| Self::derive_key(ikm, ctx))
            .collect()
    }

    /// BLAKE3 key derivation (faster, 256-bit output)
    pub fn blake3_derive(ikm: &[u8], context: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"shadowgram-blake3");
        hasher.update(context);
        hasher.update(ikm);
        hasher.finalize().into()
    }

    /// Chain key derivation (for Double Ratchet)
    pub fn kdf_chain(input: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut output = [[0u8; 32], [0u8; 32]];

        let hkdf = Hkdf::<Sha256>::new(None, input);
        let info = b"shadowgram-chain-key";

        // Extract two keys from chain
        let mut okm = [0u8; 64];
        hkdf.expand(info, &mut okm).expect("HKDF expand failed");

        output[0].copy_from_slice(&okm[0..32]);
        output[1].copy_from_slice(&okm[32..64]);

        (output[0], output[1])
    }

    /// Message key derivation from chain key
    pub fn kdf_message(chain_key: &[u8]) -> ([u8; 32], [u8; 32]) {
        // Returns: (message_key, new_chain_key)
        Self::kdf_chain(chain_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derivation() {
        let ikm = b"shared secret from key exchange";
        let context = b"shadowgram-message-key";

        let key1 = KeyDerivation::derive_key(ikm, context).unwrap();
        let key2 = KeyDerivation::derive_key(ikm, context).unwrap();

        assert_eq!(key1, key2); // Deterministic
    }

    #[test]
    fn test_blake3_derivation() {
        let ikm = b"shared secret";
        let context = b"test-context";

        let key = KeyDerivation::blake3_derive(ikm, context);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_chain_key_derivation() {
        let input = b"chain input bytes";
        let (msg_key, new_chain) = KeyDerivation::kdf_chain(input);

        assert_ne!(msg_key, new_chain); // Different keys
        assert_eq!(msg_key.len(), 32);
        assert_eq!(new_chain.len(), 32);
    }
}
