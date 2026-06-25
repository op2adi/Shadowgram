//! Zeroization traits and secure key storage
//!
//! All key material must be zeroized when dropped to prevent
//! memory scraping attacks. This module provides the traits
//! and implementations for secure key handling.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop as ZeroizeTrait};

/// Marker trait for types that must be zeroized
pub trait ZeroizeOnDrop: ZeroizeTrait {}

/// Key material wrapper with automatic zeroization
#[derive(Zeroize)]
pub struct KeyMaterial {
    inner: Vec<u8>,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl KeyMaterial {
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        // Take ownership of bytes without zeroizing (caller takes responsibility)
        let result = std::mem::take(&mut self.inner);
        // Prevent double-free since we stole the data
        std::mem::forget(self);
        result
    }

    /// Constant-time comparison for key equality checks
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner).into()
    }
}

impl From<Vec<u8>> for KeyMaterial {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for KeyMaterial {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// Secure key store trait
///
/// Implementors must ensure:
/// 1. Keys are encrypted at rest
/// 2. Keys are zeroized when removed
/// 3. Access is authenticated
pub trait KeyStore: Send + Sync {
    type Error: std::error::Error;

    /// Store a key material
    fn store(&self, key_id: &[u8], material: &KeyMaterial) -> Result<(), Self::Error>;

    /// Retrieve a key material
    fn retrieve(&self, key_id: &[u8]) -> Result<Option<KeyMaterial>, Self::Error>;

    /// Delete a key material (must zeroize)
    fn delete(&self, key_id: &[u8]) -> Result<(), Self::Error>;

    /// Check if a key exists
    fn exists(&self, key_id: &[u8]) -> Result<bool, Self::Error>;
}

/// In-memory key store for testing - NOT for production
#[cfg(test)]
pub struct MemoryKeyStore {
    store: std::collections::HashMap<Vec<u8>, KeyMaterial>,
}

#[cfg(test)]
impl MemoryKeyStore {
    pub fn new() -> Self {
        Self {
            store: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
impl KeyStore for MemoryKeyStore {
    type Error = std::convert::Infallible;

    fn store(&self, key_id: &[u8], material: &KeyMaterial) -> Result<(), Self::Error> {
        // Note: This is a simplified test implementation
        // Real implementation would need interior mutability
        Ok(())
    }

    fn retrieve(&self, key_id: &[u8]) -> Result<Option<KeyMaterial>, Self::Error> {
        Ok(None)
    }

    fn delete(&self, key_id: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn exists(&self, key_id: &[u8]) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[cfg(test)]
impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}
