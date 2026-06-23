//! Contact Management and Discovery
//!
//! Contact storage and Private Set Intersection for finding contacts
//! without revealing address books.

use std::collections::HashMap;
use thiserror::Error;

/// Contact errors
#[derive(Error, Debug)]
pub enum ContactError {
    #[error("Contact not found: {0}")]
    NotFound(String),

    #[error("Duplicate contact: {0}")]
    Duplicate(String),

    #[error("Invalid identity: {0}")]
    InvalidIdentity(String),

    #[error("Discovery error: {0}")]
    DiscoveryError(String),
}

/// Trust level for contacts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Unverified - just scanned QR
    Unverified = 0,

    /// Verified - fingerprints compared
    Verified = 1,

    /// Trusted - long-term trusted contact
    Trusted = 2,
}

/// Contact entry
#[derive(Clone)]
pub struct Contact {
    /// Contact's identity fingerprint
    pub fingerprint: String,

    /// Display name (local alias)
    pub alias: String,

    /// Public identity data
    pub public_identity: Vec<u8>,

    /// Pairwise identity for this contact
    pub pairwise_id: Option<Vec<u8>>,

    /// Trust level
    pub trust_level: TrustLevel,

    /// Added timestamp
    pub added_at: u64,

    /// Last seen timestamp
    pub last_seen: Option<u64>,

    /// Notes (encrypted)
    pub notes: Option<String>,
}

impl Contact {
    /// Create new contact from public identity
    pub fn new(
        fingerprint: String,
        alias: String,
        public_identity: Vec<u8>,
    ) -> Self {
        Self {
            fingerprint,
            alias,
            public_identity,
            pairwise_id: None,
            trust_level: TrustLevel::Unverified,
            added_at: current_timestamp(),
            last_seen: None,
            notes: None,
        }
    }

    /// Set trust level
    pub fn set_trust_level(&mut self, level: TrustLevel) {
        self.trust_level = level;
    }

    /// Mark as seen
    pub fn mark_seen(&mut self) {
        self.last_seen = Some(current_timestamp());
    }

    /// Check if contact is verified
    pub fn is_verified(&self) -> bool {
        self.trust_level >= TrustLevel::Verified
    }

    /// Check if contact is trusted
    pub fn is_trusted(&self) -> bool {
        self.trust_level == TrustLevel::Trusted
    }
}

/// Contact store trait
pub trait ContactStore: Send + Sync {
    type Error: std::error::Error;

    /// Add contact
    fn add(&self, contact: Contact) -> Result<(), Self::Error>;

    /// Get contact by fingerprint
    fn get(&self, fingerprint: &str) -> Result<Option<Contact>, Self::Error>;

    /// Remove contact
    fn remove(&self, fingerprint: &str) -> Result<(), Self::Error>;

    /// List all contacts
    fn list(&self) -> Result<Vec<Contact>, Self::Error>;

    /// Update contact
    fn update(&self, contact: Contact) -> Result<(), Self::Error>;

    /// Check if contact exists
    fn exists(&self, fingerprint: &str) -> Result<bool, Self::Error>;
}

/// In-memory contact store (for testing)
pub struct MemoryContactStore {
    contacts: std::sync::RwLock<HashMap<String, Contact>>,
}

impl MemoryContactStore {
    pub fn new() -> Self {
        Self {
            contacts: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryContactStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactStore for MemoryContactStore {
    type Error = std::convert::Infallible;

    fn add(&self, contact: Contact) -> Result<(), Self::Error> {
        let mut contacts = self.contacts.write().unwrap();
        contacts.insert(contact.fingerprint.clone(), contact);
        Ok(())
    }

    fn get(&self, fingerprint: &str) -> Result<Option<Contact>, Self::Error> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.get(fingerprint).cloned())
    }

    fn remove(&self, fingerprint: &str) -> Result<(), Self::Error> {
        let mut contacts = self.contacts.write().unwrap();
        contacts.remove(fingerprint);
        Ok(())
    }

    fn list(&self) -> Result<Vec<Contact>, Self::Error> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.values().cloned().collect())
    }

    fn update(&self, contact: Contact) -> Result<(), Self::Error> {
        let mut contacts = self.contacts.write().unwrap();
        contacts.insert(contact.fingerprint.clone(), contact);
        Ok(())
    }

    fn exists(&self, fingerprint: &str) -> Result<bool, Self::Error> {
        let contacts = self.contacts.read().unwrap();
        Ok(contacts.contains_key(fingerprint))
    }
}

/// Contact discovery via Private Set Intersection
pub struct ContactDiscovery {
    /// Local contact store
    store: Box<dyn ContactStore<Error = ContactError>>,

    /// Hash function for PSI
    hash_function: fn(&[u8]) -> [u8; 32],
}

impl ContactDiscovery {
    /// Create new discovery service
    pub fn new(store: Box<dyn ContactStore<Error = ContactError>>) -> Self {
        Self {
            store,
            hash_function: blake3_hash,
        }
    }

    /// Compute hash of fingerprint for PSI
    fn hash_fingerprint(&self, fingerprint: &[u8]) -> [u8; 32] {
        (self.hash_function)(fingerprint)
    }

    /// Get hashes of all local contacts (for PSI protocol)
    pub fn get_local_hashes(&self) -> Result<Vec<[u8; 32]>, ContactError> {
        let contacts = self.store.list()?;
        Ok(contacts
            .iter()
            .map(|c| self.hash_fingerprint(c.fingerprint.as_bytes()))
            .collect())
    }

    /// Find intersection with remote hashes (PSI result)
    pub fn find_common_contacts(
        &self,
        remote_hashes: &[[u8; 32]],
    ) -> Result<Vec<Contact>, ContactError> {
        let contacts = self.store.list()?;

        // In production, would use proper PSI protocol
        // For now, simple hash comparison
        let common = contacts
            .into_iter()
            .filter(|c| {
                let hash = self.hash_fingerprint(c.fingerprint.as_bytes());
                remote_hashes.contains(&hash)
            })
            .collect();

        Ok(common)
    }

    /// Add contact discovered via PSI
    pub fn add_discovered_contact(
        &self,
        fingerprint: String,
        alias: String,
        public_identity: Vec<u8>,
    ) -> Result<(), ContactError> {
        let contact = Contact::new(fingerprint, alias, public_identity);
        self.store.add(contact)
    }
}

/// BLAKE3 hash function
fn blake3_hash(input: &[u8]) -> [u8; 32] {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Helper for current timestamp
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Contact import/export format
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContactBackup {
    pub version: u8,
    pub contacts: Vec<ContactExport>,
    pub exported_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContactExport {
    pub fingerprint: String,
    pub alias: String,
    pub public_identity: String, // Base64 encoded
    pub trust_level: u8,
}

impl ContactExport {
    pub fn from_contact(contact: &Contact) -> Self {
        Self {
            fingerprint: contact.fingerprint.clone(),
            alias: contact.alias.clone(),
            public_identity: base64::prelude::BASE64_STANDARD.encode(&contact.public_identity),
            trust_level: contact.trust_level as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_creation() {
        let contact = Contact::new(
            "abc123".to_string(),
            "Alice".to_string(),
            vec![1, 2, 3],
        );

        assert_eq!(contact.alias, "Alice");
        assert_eq!(contact.trust_level, TrustLevel::Unverified);
        assert!(!contact.is_verified());
    }

    #[test]
    fn test_contact_trust_levels() {
        let mut contact = Contact::new("fp".to_string(), "Bob".to_string(), vec![]);

        assert_eq!(contact.trust_level, TrustLevel::Unverified);

        contact.set_trust_level(TrustLevel::Verified);
        assert!(contact.is_verified());
        assert!(!contact.is_trusted());

        contact.set_trust_level(TrustLevel::Trusted);
        assert!(contact.is_trusted());
    }

    #[test]
    fn test_memory_contact_store() {
        let store = MemoryContactStore::new();

        let contact = Contact::new("fp1".to_string(), "Test".to_string(), vec![]);

        store.add(contact.clone()).unwrap();
        assert!(store.exists("fp1").unwrap());

        let retrieved = store.get("fp1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().alias, "Test");
    }

    #[test]
    fn test_contact_discovery() {
        let store = Box::new(MemoryContactStore::new());
        let discovery = ContactDiscovery::new(store);

        // Should work with empty store
        let hashes = discovery.get_local_hashes().unwrap();
        assert!(hashes.is_empty());
    }
}