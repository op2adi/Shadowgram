//! Transport-agnostic message delivery trait.
//!
//! `MessageTransport` decouples the messenger/crypto/outbox logic from the
//! concrete delivery mechanism.  `DirectTorTransport` implements it using Tor
//! hidden services.  A future `RelayTransport` can implement the same trait
//! without changing any of the crypto or session code.

use async_trait::async_trait;
use thiserror::Error;

use crate::tor_service::{OnionServiceError, ShadowgramTor, ONION_PORT};
use crate::NetworkEnvelope;

/// SGM1 magic bytes prefix for framed messages.
pub const FRAME_MAGIC: &[u8; 4] = b"SGM1";

/// Maximum frame body size (matches `MAX_ENVELOPE_BYTES`).
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Errors returned by [`MessageTransport`].
#[derive(Debug, Error)]
pub enum TransportDeliveryError {
    #[error("Not connected to Tor / Tor not initialized")]
    NotReady,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Frame too large ({0} bytes)")]
    TooLarge(usize),

    #[error("Framing error: {0}")]
    Framing(String),
}

/// Encode a [`NetworkEnvelope`] into a length-prefixed frame.
///
/// Wire format: `SGM1 | u32-LE-len | payload`
pub fn encode_frame(envelope: &NetworkEnvelope) -> Result<Vec<u8>, TransportDeliveryError> {
    let payload = envelope.serialize();
    if payload.len() > MAX_FRAME_BYTES {
        return Err(TransportDeliveryError::TooLarge(payload.len()));
    }
    let mut frame = Vec::with_capacity(4 + 4 + payload.len());
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode a single frame from a byte slice (must be an exact frame).
pub fn decode_frame(data: &[u8]) -> Result<NetworkEnvelope, TransportDeliveryError> {
    if data.len() < 8 {
        return Err(TransportDeliveryError::Framing("frame too short".into()));
    }
    if &data[..4] != FRAME_MAGIC {
        return Err(TransportDeliveryError::Framing("bad magic".into()));
    }
    let len = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| TransportDeliveryError::Framing("bad length field".into()))?,
    ) as usize;
    if data.len() < 8 + len {
        return Err(TransportDeliveryError::Framing("incomplete frame".into()));
    }
    NetworkEnvelope::deserialize(&data[8..8 + len])
        .map_err(|e| TransportDeliveryError::Framing(e.to_string()))
}

/// Transport-agnostic delivery.  Implement this to add a new transport
/// (Tor direct, relay node, LAN, etc.) without touching session or outbox code.
#[async_trait]
pub trait MessageTransport: Send + Sync {
    /// The local address/endpoint to publish in our invite.
    fn local_address(&self) -> Option<String>;

    /// Send a single framed `NetworkEnvelope` to `dest_address`.
    /// `dest_address` is whatever was stored from the peer's invite
    /// (e.g. `"abc.onion:7373"` for Tor).
    async fn send(
        &self,
        dest_address: &str,
        envelope: &NetworkEnvelope,
    ) -> Result<(), TransportDeliveryError>;

    /// Check whether the peer at `dest_address` is likely reachable right now.
    async fn is_reachable(&self, dest_address: &str) -> bool;
}

/// Direct Tor hidden-service transport.
pub struct DirectTorTransport {
    tor: ShadowgramTor,
}

impl DirectTorTransport {
    pub fn new(tor: ShadowgramTor) -> Self {
        Self { tor }
    }
}

#[async_trait]
impl MessageTransport for DirectTorTransport {
    fn local_address(&self) -> Option<String> {
        self.tor.onion_endpoint()
    }

    async fn send(
        &self,
        dest_address: &str,
        envelope: &NetworkEnvelope,
    ) -> Result<(), TransportDeliveryError> {
        use tokio::io::AsyncWriteExt;

        let frame = encode_frame(envelope)?;
        let mut stream = self
            .tor
            .connect(dest_address)
            .await
            .map_err(|e| TransportDeliveryError::Network(e.to_string()))?;
        stream
            .write_all(&frame)
            .await
            .map_err(|e| TransportDeliveryError::Network(e.to_string()))?;
        stream
            .shutdown()
            .await
            .map_err(|e| TransportDeliveryError::Network(e.to_string()))?;
        Ok(())
    }

    async fn is_reachable(&self, dest_address: &str) -> bool {
        // Try a lightweight probe: attempt to open a circuit.
        // This is best-effort; false just means the outbox will retry later.
        self.tor.connect(dest_address).await.is_ok()
    }
}
