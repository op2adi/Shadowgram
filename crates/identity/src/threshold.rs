//! Threshold Secret Sharing
//!
//! For multi-device synchronization, identity keys are split using
//! Shamir's Secret Sharing. Any M of N shares can reconstruct the secret.
//!
//! This enables:
//! - Multi-device access without any single device having full keys
//! - Key recovery from subset of trusted devices
//! - Distributed trust model

use rand::rngs::OsRng;
use rand::Rng;
use thiserror::Error;
use zeroize::Zeroize;

/// Threshold sharing errors
#[derive(Error, Debug)]
pub enum ShareError {
    #[error("Invalid threshold: m must be <= n")]
    InvalidThreshold,

    #[error("Too few shares: need {needed}, have {have}")]
    TooFewShares { needed: usize, have: usize },

    #[error("Invalid share index: {0}")]
    InvalidIndex(usize),

    #[error("Share verification failed")]
    VerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// A single share of a secret
#[derive(Clone)]
pub struct SecretShare {
    /// Share index (1-indexed)
    pub index: u8,

    /// Share data
    pub data: Vec<u8>,
}

impl Zeroize for SecretShare {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for SecretShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Threshold configuration
pub struct ThresholdConfig {
    /// Total number of shares (n)
    pub total: u8,

    /// Minimum shares needed to reconstruct (m)
    pub threshold: u8,
}

impl ThresholdConfig {
    /// Create new configuration with validation
    pub fn new(total: u8, threshold: u8) -> Result<Self, ShareError> {
        if threshold > total {
            return Err(ShareError::InvalidThreshold);
        }
        if threshold < 1 {
            return Err(ShareError::InvalidThreshold);
        }
        Ok(Self { total, threshold })
    }

    /// Default: 3-of-5 (need 3 of 5 devices)
    pub fn default() -> Self {
        Self {
            total: 5,
            threshold: 3,
        }
    }
}

/// Shamir Secret Sharing implementation
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Split a secret into n shares, requiring m shares to reconstruct
    ///
    /// # Arguments
    /// * `secret` - The secret bytes to split
    /// * `threshold` (m) - Minimum shares needed to reconstruct
    /// * `total` (n) - Total number of shares to create
    ///
    /// # Returns
    /// Vector of `total` shares
    pub fn split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<SecretShare>, ShareError> {
        let _config = ThresholdConfig::new(total, threshold)?;

        let mut shares = Vec::with_capacity(total as usize);

        // Split each byte independently (simplified - production should use
        // proper field arithmetic in GF(256))
        for byte_idx in 0..secret.len() {
            let secret_byte = secret[byte_idx];

            // Generate shares for this byte
            let byte_shares = Self::split_byte(secret_byte, threshold, total, byte_idx as u8);

            // Distribute shares across share vectors
            for (share_idx, share_byte) in byte_shares.into_iter().enumerate() {
                if share_idx >= shares.len() {
                    shares.push(SecretShare {
                        index: (share_idx + 1) as u8,
                        data: vec![0u8; secret.len()],
                    });
                }
                shares[share_idx].data[byte_idx] = share_byte;
            }
        }

        Ok(shares)
    }

    /// Reconstruct secret from at least `threshold` shares
    ///
    /// # Arguments
    /// * `shares` - At least `threshold` shares
    /// * `threshold` - Original threshold used in splitting
    ///
    /// # Returns
    /// The original secret
    pub fn reconstruct(shares: &[SecretShare], threshold: u8) -> Result<Vec<u8>, ShareError> {
        if shares.len() < threshold as usize {
            return Err(ShareError::TooFewShares {
                needed: threshold as usize,
                have: shares.len(),
            });
        }

        // Use only threshold number of shares
        let needed_shares = &shares[..threshold as usize];

        // Determine output length
        let output_len = needed_shares[0].data.len();
        let mut secret = vec![0u8; output_len];

        // Reconstruct each byte
        for byte_idx in 0..output_len {
            let share_bytes: Vec<(u8, u8)> = needed_shares
                .iter()
                .map(|s| (s.index, s.data[byte_idx]))
                .collect();

            secret[byte_idx] = Self::reconstruct_byte(&share_bytes, threshold);
        }

        Ok(secret)
    }

    // GF(256) Addition / Subtraction
    fn gf_add(a: u8, b: u8) -> u8 { a ^ b }
    fn gf_sub(a: u8, b: u8) -> u8 { a ^ b }

    // GF(256) Multiplication
    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0;
        for _ in 0..8 {
            if (b & 1) != 0 { p ^= a; }
            let hi_bit_set = (a & 0x80) != 0;
            a <<= 1;
            if hi_bit_set { a ^= 0x1B; } // x^8 + x^4 + x^3 + x + 1
            b >>= 1;
        }
        p
    }

    // GF(256) Inverse
    fn gf_inv(a: u8) -> u8 {
        if a == 0 { return 0; }
        for i in 1..=255 {
            if Self::gf_mul(a, i) == 1 { return i; }
        }
        0
    }

    /// Split a single byte using polynomial interpolation over GF(256)
    fn split_byte(secret: u8, threshold: u8, total: u8, _byte_index: u8) -> Vec<u8> {
        let mut coefficients = Vec::with_capacity(threshold as usize);
        coefficients.push(secret); // f(0) = secret

        for _ in 1..threshold {
            coefficients.push(OsRng.gen::<u8>());
        }

        let mut shares = Vec::with_capacity(total as usize);
        for x in 1..=total {
            let y = Self::eval_polynomial(&coefficients, x);
            shares.push(y);
        }

        shares
    }

    /// Reconstruct a byte from shares using Lagrange interpolation
    fn reconstruct_byte(share_bytes: &[(u8, u8)], threshold: u8) -> u8 {
        let mut result = 0u8;

        for i in 0..threshold as usize {
            let (xi, yi) = share_bytes[i];

            let mut li_num = 1u8;
            let mut li_den = 1u8;

            for j in 0..threshold as usize {
                if i != j {
                    let xj = share_bytes[j].0;
                    li_num = Self::gf_mul(li_num, Self::gf_sub(0, xj));
                    li_den = Self::gf_mul(li_den, Self::gf_sub(xi, xj));
                }
            }

            let li = Self::gf_mul(li_num, Self::gf_inv(li_den));
            result = Self::gf_add(result, Self::gf_mul(yi, li));
        }

        result
    }

    /// Evaluate polynomial at point x
    fn eval_polynomial(coefficients: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        let mut x_power = 1u8;

        for &coeff in coefficients {
            result = Self::gf_add(result, Self::gf_mul(coeff, x_power));
            x_power = Self::gf_mul(x_power, x);
        }

        result
    }

    /// Verify a share is valid (basic sanity check)
    pub fn verify_share(share: &SecretShare, _expected_length: usize) -> bool {
        // In production, would use cryptographic verification
        // like Feldman's VSS with commitments
        share.index > 0 && !share.data.is_empty()
    }
}

/// Helper for splitting identity keys across devices
pub struct MultiDeviceSync {
    config: ThresholdConfig,
}

impl MultiDeviceSync {
    pub fn new(config: ThresholdConfig) -> Self {
        Self { config }
    }

    /// Split identity private key for multi-device access
    pub fn split_identity_key(&self, private_key_bytes: &[u8]) -> Result<Vec<SecretShare>, ShareError> {
        ShamirSecretSharing::split(
            private_key_bytes,
            self.config.threshold,
            self.config.total,
        )
    }

    /// Reconstruct identity key from device shares
    pub fn reconstruct_identity_key(&self, shares: &[SecretShare]) -> Result<Vec<u8>, ShareError> {
        ShamirSecretSharing::reconstruct(shares, self.config.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_split_reconstruct() {
        let secret = b"My secret identity key!";

        let shares = ShamirSecretSharing::split(secret, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold shares
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..3], 3).unwrap();
        assert_eq!(secret.to_vec(), reconstructed);

        // Reconstruct with more than threshold
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[1..4], 3).unwrap();
        assert_eq!(secret.to_vec(), reconstructed);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Secret!";
        let shares = ShamirSecretSharing::split(secret, 3, 5).unwrap();

        // Try with too few shares
        let result = ShamirSecretSharing::reconstruct(&shares[0..2], 3);
        assert!(matches!(result, Err(ShareError::TooFewShares { .. })));
    }

    #[test]
    fn test_threshold_config_validation() {
        // Valid: threshold <= total
        assert!(ThresholdConfig::new(5, 3).is_ok());

        // Invalid: threshold > total
        assert!(ThresholdConfig::new(3, 5).is_err());

        // Invalid: threshold < 1
        assert!(ThresholdConfig::new(5, 0).is_err());
    }
}