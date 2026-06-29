//! Pairwise pseudonyms derived from secret relationship material.
//!
//! Public fingerprints remain public identifiers only. Pairwise identities are
//! derived from a local secret plus the contact's public identity so observers
//! cannot link relationships from public information alone.

use crate::identity::PublicIdentity;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use shadowgram_crypto::kdf::KeyDerivation;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret relationship seed stored locally for one contact.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairwiseRelationshipSecret([u8; 32]);

impl PairwiseRelationshipSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Pairwise identity derived for a specific contact.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairwiseIdentity {
    x25519_secret: StaticSecret,
    x25519_public: X25519PublicKey,
    #[zeroize(skip)]
    ed25519_secret: SigningKey,
    #[zeroize(skip)]
    ed25519_public: VerifyingKey,
    contact_binding: [u8; 32],
}

impl PairwiseIdentity {
    /// Derive a pairwise identity from secret relationship material and the
    /// contact's public identity. This intentionally does not use only public
    /// fingerprints, which would make relationships linkable.
    pub fn derive(
        relationship_secret: &PairwiseRelationshipSecret,
        their_public: &PublicIdentity,
    ) -> Result<Self, String> {
        let context = relationship_context(their_public)?;
        let x25519_seed = KeyDerivation::hkdf_sha256(
            relationship_secret.as_bytes(),
            b"shadowgram-pairwise-x25519",
            &context,
        )
        .ok_or_else(|| "Failed to derive X25519 pairwise seed".to_string())?;
        let ed25519_seed = KeyDerivation::hkdf_sha256(
            relationship_secret.as_bytes(),
            b"shadowgram-pairwise-ed25519",
            &context,
        )
        .ok_or_else(|| "Failed to derive Ed25519 pairwise seed".to_string())?;
        let contact_binding = KeyDerivation::hkdf_sha256(
            relationship_secret.as_bytes(),
            b"shadowgram-pairwise-binding",
            &context,
        )
        .ok_or_else(|| "Failed to derive contact binding".to_string())?;

        let x25519_secret = StaticSecret::from(x25519_seed);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let ed25519_secret = SigningKey::from_bytes(&ed25519_seed);
        let ed25519_public = ed25519_secret.verifying_key();

        Ok(Self {
            x25519_secret,
            x25519_public,
            ed25519_secret,
            ed25519_public,
            contact_binding,
        })
    }

    pub fn x25519_public(&self) -> X25519PublicKey {
        self.x25519_public
    }

    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519_public
    }

    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }

    pub fn ed25519_secret(&self) -> &SigningKey {
        &self.ed25519_secret
    }

    /// Local-only opaque binding used to associate this pseudonym with the
    /// intended contact. It is never transmitted and cannot be derived from
    /// public information.
    pub fn contact_binding(&self) -> &[u8; 32] {
        &self.contact_binding
    }

    pub fn serialize_public(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(&PairwisePublic::from_pairwise(self)).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PairwisePublic {
    pub x25519_public: [u8; 32],
    pub ed25519_public: [u8; 32],
}

impl PairwisePublic {
    pub fn from_pairwise(pairwise: &PairwiseIdentity) -> Self {
        Self {
            x25519_public: *pairwise.x25519_public.as_bytes(),
            ed25519_public: *pairwise.ed25519_public.as_bytes(),
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

fn relationship_context(their_public: &PublicIdentity) -> Result<Vec<u8>, String> {
    let mut context = Vec::new();
    context.extend_from_slice(their_public.fingerprint_full.as_bytes());
    context.extend_from_slice(&their_public.to_bytes().map_err(|e| e.to_string())?);
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use proptest::prelude::*;

    #[test]
    fn test_pairwise_derivation_requires_secret_material() {
        let their_identity = Identity::generate().unwrap();
        let secret_a = PairwiseRelationshipSecret::generate();
        let secret_b = PairwiseRelationshipSecret::generate();

        let pairwise_a = PairwiseIdentity::derive(&secret_a, their_identity.public()).unwrap();
        let pairwise_b = PairwiseIdentity::derive(&secret_b, their_identity.public()).unwrap();

        assert_ne!(
            pairwise_a.x25519_public().as_bytes(),
            pairwise_b.x25519_public().as_bytes()
        );
        assert_ne!(pairwise_a.contact_binding(), pairwise_b.contact_binding());
    }

    #[test]
    fn test_pairwise_consistency_for_same_secret() {
        let their_identity = Identity::generate().unwrap();
        let relationship_secret = PairwiseRelationshipSecret::generate();

        let pairwise_a =
            PairwiseIdentity::derive(&relationship_secret, their_identity.public()).unwrap();
        let pairwise_b =
            PairwiseIdentity::derive(&relationship_secret, their_identity.public()).unwrap();

        assert_eq!(
            pairwise_a.x25519_public().as_bytes(),
            pairwise_b.x25519_public().as_bytes()
        );
        assert_eq!(pairwise_a.contact_binding(), pairwise_b.contact_binding());
    }

    proptest! {
        #[test]
        fn prop_pairwise_public_roundtrip(secret in prop::array::uniform32(any::<u8>())) {
            let their_identity = Identity::generate().unwrap();
            let relationship_secret = PairwiseRelationshipSecret(secret);
            let pairwise = PairwiseIdentity::derive(&relationship_secret, their_identity.public()).unwrap();
            let serialized = pairwise.serialize_public().unwrap();
            let decoded = PairwisePublic::deserialize(&serialized).unwrap();

            prop_assert_eq!(decoded, PairwisePublic::from_pairwise(&pairwise));
        }
    }
}
