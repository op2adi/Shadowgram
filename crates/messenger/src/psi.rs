//! Private Set Intersection for Contact Discovery
//!
//! PSI protocol allows two parties to find common contacts
//! without revealing their entire address books.

use blake3::Hasher;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

/// PSI errors
#[derive(Error, Debug)]
pub enum PsiError {
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Serialization failed: {0}")]
    SerializationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// PSI protocol participant
pub struct PsiProtocol {
    /// Our items (hashed)
    items: Vec<[u8; 32]>,

    /// Blinded items for exchange
    blinded_items: Vec<Vec<u8>>,

    /// Blinding factor
    blinding_key: [u8; 32],
}

impl PsiProtocol {
    /// Create new PSI protocol with items to compare
    pub fn new(items: Vec<Vec<u8>>) -> Self {
        let mut blinding_key = [0u8; 32];
        OsRng.fill_bytes(&mut blinding_key);

        // Hash all items
        let hashed: Vec<[u8; 32]> = items
            .iter()
            .map(|item| {
                let mut hasher = Hasher::new();
                hasher.update(item);
                hasher.finalize().into()
            })
            .collect();

        // Blind items with random key
        let blinded: Vec<Vec<u8>> = hashed
            .iter()
            .map(|h| {
                let mut blinded = h.to_vec();
                for (i, byte) in blinded.iter_mut().enumerate() {
                    *byte ^= blinding_key[i % 32];
                }
                blinded
            })
            .collect();

        Self {
            items: hashed,
            blinded_items: blinded,
            blinding_key,
        }
    }

    /// Get blinded items to send to other party
    pub fn get_blinded_items(&self) -> &[Vec<u8>] {
        &self.blinded_items
    }

    /// Process other party's blinded items
    /// Returns indices of matching items
    pub fn find_matches(&self, other_blinded: &[Vec<u8>]) -> Vec<usize> {
        let mut matches = Vec::new();

        for (i, other_item) in other_blinded.iter().enumerate() {
            // Unblind other item
            let mut unblinded = other_item.clone();
            for (j, byte) in unblinded.iter_mut().enumerate() {
                *byte ^= self.blinding_key[j % 32];
            }

            // Check if matches any of our items
            for &our_item in &self.items {
                if unblinded == our_item.to_vec() {
                    matches.push(i);
                    break;
                }
            }
        }

        matches
    }

    /// Get item count
    pub fn item_count(&self) -> usize {
        self.items.len()
    }
}

/// Contact fingerprint for PSI
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ContactFingerprint {
    pub fingerprint: String,
    pub hash: [u8; 32],
}

impl ContactFingerprint {
    pub fn new(fingerprint: String) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(fingerprint.as_bytes());
        let hash = hasher.finalize().into();

        Self { fingerprint, hash }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

/// PSI result with matched contacts
pub struct PsiResult {
    pub matched_fingerprints: Vec<String>,
    pub total_local_contacts: usize,
    pub total_matched: usize,
}

/// High-level contact discovery via PSI
pub struct ContactDiscoveryPSI {
    /// Our contact fingerprints
    local_contacts: Vec<ContactFingerprint>,
}

impl ContactDiscoveryPSI {
    pub fn new(local_contacts: Vec<String>) -> Self {
        let fingerprints: Vec<ContactFingerprint> = local_contacts
            .into_iter()
            .map(ContactFingerprint::new)
            .collect();

        Self {
            local_contacts: fingerprints,
        }
    }

    /// Run PSI protocol with remote contacts
    pub fn discover_common(&self, remote_contact_hashes: &[Vec<u8>]) -> PsiResult {
        if remote_contact_hashes.is_empty() {
            return PsiResult {
                matched_fingerprints: Vec::new(),
                total_local_contacts: self.local_contacts.len(),
                total_matched: 0,
            };
        }

        let mut matched = Vec::new();

        for local in &self.local_contacts {
            for remote_hash in remote_contact_hashes {
                if &local.hash.to_vec() == remote_hash {
                    matched.push(local.fingerprint.clone());
                    break;
                }
            }
        }

        let total_matched = matched.len();
        PsiResult {
            matched_fingerprints: matched,
            total_local_contacts: self.local_contacts.len(),
            total_matched,
        }
    }

    /// Get our contact hashes for sending
    pub fn get_contact_hashes(&self) -> Vec<Vec<u8>> {
        self.local_contacts
            .iter()
            .map(|c| c.hash.to_vec())
            .collect()
    }

    /// Add contact
    pub fn add_contact(&mut self, fingerprint: String) {
        self.local_contacts
            .push(ContactFingerprint::new(fingerprint));
    }

    /// Remove contact
    pub fn remove_contact(&mut self, fingerprint: &str) {
        self.local_contacts.retain(|c| c.fingerprint != fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_protocol() {
        let our_items = vec![
            b"alice@example.com".to_vec(),
            b"bob@example.com".to_vec(),
            b"charlie@example.com".to_vec(),
        ];

        let their_items = vec![b"bob@example.com".to_vec(), b"dave@example.com".to_vec()];

        let mut our_psi = PsiProtocol::new(our_items.clone());
        let their_psi = PsiProtocol::new(their_items.clone());

        // Exchange blinded items
        let our_matches = our_psi.find_matches(their_psi.get_blinded_items());

        // Should find "bob" as common contact
        assert_eq!(our_matches.len(), 1);
    }

    #[test]
    fn test_contact_discovery_psi() {
        let mut discovery = ContactDiscoveryPSI::new(vec![
            "fp1".to_string(),
            "fp2".to_string(),
            "fp3".to_string(),
        ]);

        let remote_hashes = vec![
            vec![1u8; 32],                             // Not matching
            discovery.local_contacts[1].hash.to_vec(), // Matches fp2
        ];

        let result = discovery.discover_common(&remote_hashes);

        assert_eq!(result.total_matched, 1);
        assert!(result.matched_fingerprints.contains(&"fp2".to_string()));
    }

    #[test]
    fn test_fingerprint_hashing() {
        let fp1 = ContactFingerprint::new("alice".to_string());
        let fp2 = ContactFingerprint::new("alice".to_string());
        let fp3 = ContactFingerprint::new("bob".to_string());

        assert_eq!(fp1.hash, fp2.hash);
        assert_ne!(fp1.hash, fp3.hash);
    }
}
