//! QR Code Generation and Parsing
//!
//! Identities are exchanged via QR codes for:
//! - Initial contact addition
//! - One-time invitation links
//! - Identity verification
//!
//! QR codes contain the full public identity plus optional metadata.

use qrcode::{QrCode as QrImage, Color, EcLevel};
use image::{ImageBuffer, Rgb};
use crate::identity::PublicIdentity;
use thiserror::Error;

/// QR code error types
#[derive(Error, Debug)]
pub enum QrError {
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Invalid QR data: {0}")]
    InvalidData(String),

    #[error("Image error: {0}")]
    ImageError(String),
}

/// QR code wrapper for identity exchange
pub struct QrCode {
    /// The QR image
    image: QrImage,

    /// Encoded data
    data: Vec<u8>,
}

impl QrCode {
    /// Create QR code from public identity
    pub fn from_identity(identity: &PublicIdentity) -> Result<Self, QrError> {
        // Serialize identity to bytes
        let data = identity.to_bytes()
            .map_err(|e| QrError::EncodingFailed(e.to_string()))?;

        // Add magic bytes for Shadowgram QR identification
        let mut qr_data = Vec::new();
        qr_data.extend_from_slice(b"SGRAM"); // Magic bytes
        qr_data.extend_from_slice(&data);

        // Generate QR code with low error correction to maximize capacity
        let image = QrImage::with_error_correction_level(
            &qr_data,
            EcLevel::L, // Low error correction (up to 7% damage) - needed for large ML-KEM keys
        ).map_err(|e| QrError::EncodingFailed(e.to_string()))?;

        Ok(Self {
            image,
            data: qr_data,
        })
    }

    /// Parse QR code from image data
    pub fn from_image(_image_bytes: &[u8]) -> Result<Vec<u8>, QrError> {
        // In a real implementation, this would use a QR decoder
        // like zbar or quirc. For now, placeholder.
        //
        // Production code would:
        // 1. Parse image format (PNG/JPEG)
        // 2. Detect QR code boundaries
        // 3. Decode the QR payload
        // 4. Verify magic bytes
        // 5. Return identity data

        // Placeholder - real implementation needs qr detection library
        Err(QrError::DecodingFailed(
            "QR decoding not implemented - needs zbar/quirc binding".into()
        ))
    }

    /// Render QR code as RGB image
    pub fn render(&self, dark: [u8; 3], light: [u8; 3], scale: u32) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        let size = self.image.width() as u32;
        let scaled_size = size * scale;

        let mut img = ImageBuffer::new(scaled_size, scaled_size);

        for y in 0..size {
            for x in 0..size {
                let color = self.image[(x as usize, y as usize)];
                let pixel_color = match color {
                    Color::Light => Rgb(light),
                    Color::Dark => Rgb(dark),
                };

                // Scale up each module
                for dy in 0..scale {
                    for dx in 0..scale {
                        let px = x * scale + dx;
                        let py = y * scale + dy;
                        img.put_pixel(px, py, pixel_color);
                    }
                }
            }
        }

        img
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get QR dimensions
    pub fn size(&self) -> usize {
        self.image.width()
    }

    /// Verify QR data format and extract identity
    pub fn extract_identity(qr_data: &[u8]) -> Result<PublicIdentity, QrError> {
        // Check magic bytes
        if qr_data.len() < 5 || &qr_data[0..5] != b"SGRAM" {
            return Err(QrError::InvalidData(
                "Invalid QR format - missing Shadowgram magic bytes".into()
            ));
        }

        // Parse identity from remaining data
        PublicIdentity::from_serialized(&qr_data[5..])
            .map_err(|e| QrError::InvalidData(e.to_string()))
    }
}

/// Invitation QR code (one-time use)
pub struct InvitationQr {
    /// Base QR code
    qr: QrCode,

    /// Invitation metadata
    _invite_code: String,

    /// Expiration timestamp
    expires_at: u64,
}

impl InvitationQr {
    /// Create one-time invitation QR
    pub fn new(
        identity: &PublicIdentity,
        invite_code: String,
        expires_in_secs: u64,
    ) -> Result<Self, QrError> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expires_in_secs;

        // Create extended data with invitation info
        let mut invite_data = Vec::new();
        invite_data.extend_from_slice(identity.to_bytes()
            .map_err(|e| QrError::EncodingFailed(e.to_string()))?
            .as_slice());
        invite_data.extend_from_slice(invite_code.as_bytes());
        invite_data.extend_from_slice(&expires_at.to_le_bytes());

        let qr = QrCode::from_identity(identity)?;

        Ok(Self {
            qr,
            _invite_code: invite_code,
            expires_at,
        })
    }

    /// Check if invitation is still valid
    pub fn is_valid(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now < self.expires_at
    }

    /// Get expiration time
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Get the QR code
    pub fn qr_code(&self) -> &QrCode {
        &self.qr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_qr_generation() {
        let identity = Identity::generate().unwrap();
        let qr = QrCode::from_identity(identity.public()).unwrap();

        assert!(qr.size() > 0);
        assert!(qr.data().len() > 5);
    }

    #[test]
    fn test_qr_magic_bytes() {
        let identity = Identity::generate().unwrap();
        let qr = QrCode::from_identity(identity.public()).unwrap();

        assert_eq!(&qr.data()[0..5], b"SGRAM");
    }

    #[test]
    fn test_qr_identity_extraction() {
        let identity = Identity::generate().unwrap();
        let qr = QrCode::from_identity(identity.public()).unwrap();

        let extracted = QrCode::extract_identity(qr.data()).unwrap();

        assert_eq!(extracted.fingerprint_full, identity.public().fingerprint_full);
    }

    #[test]
    fn test_qr_rendering() {
        let identity = Identity::generate().unwrap();
        let qr = QrCode::from_identity(identity.public()).unwrap();

        let img = qr.render([0, 0, 0], [255, 255, 255], 4);

        assert_eq!(img.width(), qr.size() as u32 * 4);
        assert_eq!(img.height(), qr.size() as u32 * 4);
    }
}