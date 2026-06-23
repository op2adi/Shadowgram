//! Pairwise Pseudonyms
//!
//! For privacy, each contact sees a different identity.
//! Pairwise pseudonyms are derived from both parties' identities
//! using HKDF, ensuring no correlation across contacts.

use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use shadowgram_crypto::kdf::KeyDerivation;
use crate::identity::{Identity, PublicIdentity};
use serde::{Serialize, Deserialize};

/// Pairwise identity derived for a specific contact
pub struct PairwiseIdentity {
    /// X25519 keypair for this specific contact
    x25519_secret: StaticSecret,
    x25519_public: X25519PublicKey,

    /// Ed25519 keypair for this contact
    _ed25519_secret: SigningKey,
    ed25519_public: VerifyingKey,

    /// Reference to the contact's identity (for lookup)
    contact_fingerprint: [u8; 32],
}

impl PairwiseIdentity {
    /// Derive pairwise identity from our identity and contact's public identity
    pub fn derive(our_identity: &Identity, their_public: &PublicIdentity) -> Self {
        // Combine fingerprints to create unique seed for this pair
        let our_fp = our_identity.public().fingerprint_full.as_bytes();
        let their_fp = their_public.fingerprint_full.as_bytes();

        // HKDF-expand to get seed material
        let seed = KeyDerivation::blake3_derive(
            &[our_fp, their_fp].concat(),
            b"shadowgram-pairwise-seed",
        );

        // Derive X25519 keypair from seed
        let x25519_secret = StaticSecret::from(seed);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Derive Ed25519 keypair from different seed
        let ed_seed = KeyDerivation::blake3_derive(
            &[our_fp, their_fp, b"ed25519"].concat(),
            b"shadowgram-pairwise-ed",
        );
        let ed25519_secret = SigningKey::from_bytes(&ed_seed);
        let ed25519_public = ed25519_secret.verifying_key();

        Self {
            x25519_secret,
            x25519_public,
            _ed25519_secret: ed25519_secret,
            ed25519_public,
            contact_fingerprint: their_public.fingerprint_full.as_bytes().try_into().unwrap_or([0u8; 32]),
        }
    }

    /// Get the X25519 public key for this pairwise identity
    pub fn x25519_public(&self) -> X25519PublicKey {
        self.x25519_public
    }

    /// Get the Ed25519 public key for this pairwise identity
    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519_public
    }

    /// Get X25519 secret for key exchange with this specific contact
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }

    /// Get contact fingerprint this identity was derived for
    pub fn contact_fingerprint(&self) -> &[u8; 32] {
        &self.contact_fingerprint
    }

    /// Serialize pairwise public identity for sending
    pub fn serialize_public(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.x25519_public.as_bytes());
        data.extend_from_slice(self.ed25519_public.as_bytes());
        data
    }
}

/// Pairwise public identity (what we send to a specific contact)
#[derive(Serialize, Deserialize)]
pub struct PairwisePublic {
    pub x25519_public: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub contact_fingerprint: Vec<u8>,
}

impl PairwisePublic {
    pub fn from_pairwise(pairwise: &PairwiseIdentity) -> Self {
        Self {
            x25519_public: pairwise.x25519_public.as_bytes().to_vec(),
            ed25519_public: pairwise.ed25519_public.as_bytes().to_vec(),
            contact_fingerprint: pairwise.contact_fingerprint.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairwise_derivation() {
        let identity1 = crate::identity::Identity::generate().unwrap();
        let identity2 = crate::identity::Identity::generate().unwrap();

        // Each sees a different identity for the other
        let pairwise_1_to_2 = PairwiseIdentity::derive(&identity1, identity2.public());
        let pairwise_2_to_1 = PairwiseIdentity::derive(&identity2, identity1.public());

        // They should be different
        assert_ne!(
            pairwise_1_to_2.x25519_public.as_bytes(),
            pairwise_2_to_1.x25519_public.as_bytes()
        );
    }

    #[test]
    fn test_pairwise_consistency() {
        let identity1 = crate::identity::Identity::generate().unwrap();
        let identity2 = crate::identity::Identity::generate().unwrap();

        // Deriving twice should give same result
        let pairwise1a = PairwiseIdentity::derive(&identity1, identity2.public());
        let pairwise1b = PairwiseIdentity::derive(&identity1, identity2.public());

        assert_eq!(
            pairwise1a.x25519_public.as_bytes(),
            pairwise1b.x25519_public.as_bytes()
        );
    }
}