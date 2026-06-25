//! Pluggable Transports
//!
//! Obfuscation layer for censorship resistance. Transforms traffic
//! to look like normal protocols (HTTPS, WebRTC, etc.)
//!
//! Supported transports:
//! - WebSocket transport (looks like normal WS traffic)
//! - HTTP polling (looks like web browsing)
//! - WebRTC data channels (future)
//! - Custom obfs4-like transport (future)

use base64::Engine;
use bytes::{Bytes, BytesMut};
use thiserror::Error;

/// Transport errors
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Transport type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// Direct TCP connection
    Direct,

    /// WebSocket transport
    WebSocket,

    /// HTTP long-polling
    HttpPoll,

    /// WebRTC data channel (future)
    WebRtc,

    /// Obfuscation (obfs4-style, future)
    Obfs,
}

/// Encoded frame ready for transport
pub struct TransportFrame {
    /// Encoded data
    pub data: Bytes,

    /// Transport type used
    pub transport: TransportType,

    /// Optional content-type hint
    pub content_type: Option<String>,
}

impl TransportFrame {
    pub fn new(data: Bytes, transport: TransportType) -> Self {
        Self {
            data,
            transport,
            content_type: None,
        }
    }

    pub fn with_content_type(data: Bytes, transport: TransportType, ct: &str) -> Self {
        Self {
            data,
            transport,
            content_type: Some(ct.to_string()),
        }
    }
}

/// Transport trait for pluggable implementations
pub trait Transport: Send + Sync {
    /// Get transport type
    fn transport_type(&self) -> TransportType;

    /// Encode message for this transport
    fn encode(&self, message: &[u8]) -> Result<TransportFrame, TransportError>;

    /// Decode message from this transport
    fn decode(&self, frame: &TransportFrame) -> Result<Bytes, TransportError>;

    /// Check if this transport is available
    fn is_available(&self) -> bool;
}

/// WebSocket transport implementation
pub struct WebSocketTransport {
    /// WebSocket server URL
    url: String,

    /// Subprotocol (optional)
    subprotocol: Option<String>,
}

impl WebSocketTransport {
    pub fn new(url: String) -> Self {
        Self {
            url,
            subprotocol: Some("shadowgram".to_string()),
        }
    }

    pub fn with_subprotocol(url: String, subprotocol: String) -> Self {
        Self {
            url,
            subprotocol: Some(subprotocol),
        }
    }

    /// Encode as WebSocket frame
    fn encode_ws(&self, data: &[u8]) -> Bytes {
        // In production, would use actual WebSocket framing
        // For now, just wrap with length prefix
        let mut frame = BytesMut::with_capacity(data.len() + 4);
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(data);
        frame.freeze()
    }

    /// Decode WebSocket frame
    fn decode_ws(&self, frame: &[u8]) -> Result<Bytes, TransportError> {
        if frame.len() < 4 {
            return Err(TransportError::DecodingError("Frame too short".into()));
        }

        let len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;

        if frame.len() < 4 + len {
            return Err(TransportError::DecodingError("Incomplete frame".into()));
        }

        Ok(Bytes::copy_from_slice(&frame[4..4 + len]))
    }
}

impl Transport for WebSocketTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    fn encode(&self, message: &[u8]) -> Result<TransportFrame, TransportError> {
        let data = self.encode_ws(message);
        Ok(TransportFrame::with_content_type(
            data,
            TransportType::WebSocket,
            "application/octet-stream",
        ))
    }

    fn decode(&self, frame: &TransportFrame) -> Result<Bytes, TransportError> {
        self.decode_ws(&frame.data)
    }

    fn is_available(&self) -> bool {
        // In production, would check connectivity
        true
    }
}

/// HTTP polling transport
pub struct HttpPollTransport {
    /// Poll endpoint URL
    poll_url: String,

    /// POST endpoint URL
    post_url: String,

    /// Poll interval (ms)
    poll_interval_ms: u64,
}

impl HttpPollTransport {
    pub fn new(poll_url: String, post_url: String) -> Self {
        Self {
            poll_url,
            post_url,
            poll_interval_ms: 1000,
        }
    }

    pub fn with_interval(poll_url: String, post_url: String, interval_ms: u64) -> Self {
        Self {
            poll_url,
            post_url,
            poll_interval_ms: interval_ms,
        }
    }

    /// Encode as HTTP-compatible payload (base64)
    fn encode_http(&self, data: &[u8]) -> Bytes {
        let encoded = base64::prelude::BASE64_STANDARD.encode(data);
        Bytes::from(encoded)
    }

    /// Decode from base64
    fn decode_http(&self, frame: &[u8]) -> Result<Bytes, TransportError> {
        let decoded = base64::prelude::BASE64_STANDARD
            .decode(frame)
            .map_err(|e| TransportError::DecodingError(e.to_string()))?;
        Ok(Bytes::from(decoded))
    }

    /// Get poll interval
    pub fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.poll_interval_ms)
    }
}

impl Transport for HttpPollTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::HttpPoll
    }

    fn encode(&self, message: &[u8]) -> Result<TransportFrame, TransportError> {
        let data = self.encode_http(message);
        Ok(TransportFrame::with_content_type(
            data,
            TransportType::HttpPoll,
            "text/plain",
        ))
    }

    fn decode(&self, frame: &TransportFrame) -> Result<Bytes, TransportError> {
        self.decode_http(&frame.data)
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Direct TCP transport (no obfuscation)
pub struct DirectTransport;

impl DirectTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DirectTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for DirectTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Direct
    }

    fn encode(&self, message: &[u8]) -> Result<TransportFrame, TransportError> {
        Ok(TransportFrame::new(
            Bytes::copy_from_slice(message),
            TransportType::Direct,
        ))
    }

    fn decode(&self, frame: &TransportFrame) -> Result<Bytes, TransportError> {
        Ok(frame.data.clone())
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Transport selector - chooses best available transport
pub struct TransportSelector {
    available: Vec<Box<dyn Transport>>,
}

impl TransportSelector {
    pub fn new() -> Self {
        Self {
            available: Vec::new(),
        }
    }

    /// Add transport to selector
    pub fn add_transport(&mut self, transport: impl Transport + 'static) {
        self.available.push(Box::new(transport));
    }

    /// Get best available transport
    pub fn select(&self, preferred: Option<TransportType>) -> Option<&dyn Transport> {
        if let Some(pref) = preferred {
            // Try preferred first
            if let Some(t) = self.available.iter().find(|t| t.transport_type() == pref) {
                if t.is_available() {
                    return Some(t.as_ref());
                }
            }
        }

        // Fall back to any available
        self.available
            .iter()
            .find(|t| t.is_available())
            .map(|t| t.as_ref())
    }

    /// Get all available transports
    pub fn all_available(&self) -> Vec<&dyn Transport> {
        self.available
            .iter()
            .filter(|t| t.is_available())
            .map(|t| t.as_ref())
            .collect()
    }

    /// Count available transports
    pub fn count(&self) -> usize {
        self.available.len()
    }
}

impl Default for TransportSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Obfuscated transport (stub for future obfs4 implementation)
pub struct ObfsTransport {
    /// Seed for obfuscation
    seed: Vec<u8>,

    /// State for stateful obfuscation
    state: u64,
}

impl ObfsTransport {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            state: 0,
        }
    }

    /// Simple XOR obfuscation (placeholder - real obfs4 is much more complex)
    fn obfuscate(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            let key_byte = self.seed[i % self.seed.len()] ^ ((self.state & 0xFF) as u8);
            output.push(byte ^ key_byte);
            self.state = self.state.wrapping_add(1);
        }

        output
    }

    fn deobfuscate(&mut self, data: &[u8]) -> Vec<u8> {
        // XOR is symmetric
        self.obfuscate(data)
    }
}

impl Transport for ObfsTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Obfs
    }

    fn encode(&self, message: &[u8]) -> Result<TransportFrame, TransportError> {
        // Placeholder
        Ok(TransportFrame::new(
            Bytes::copy_from_slice(message),
            TransportType::Obfs,
        ))
    }

    fn decode(&self, frame: &TransportFrame) -> Result<Bytes, TransportError> {
        Ok(frame.data.clone())
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_transport() {
        let transport = DirectTransport::new();
        let original = b"Hello, Shadowgram!";

        let frame = transport.encode(original).unwrap();
        let decoded = transport.decode(&frame).unwrap();

        assert_eq!(original, &decoded[..]);
    }

    #[test]
    fn test_websocket_transport() {
        let transport = WebSocketTransport::new("ws://example.com".into());
        let original = b"Test message";

        let frame = transport.encode(original).unwrap();
        let decoded = transport.decode(&frame).unwrap();

        assert_eq!(original, &decoded[..]);
    }

    #[test]
    fn test_http_transport() {
        let transport = HttpPollTransport::new(
            "https://example.com/poll".into(),
            "https://example.com/post".into(),
        );
        let original = b"Test HTTP transport";

        let frame = transport.encode(original).unwrap();
        let decoded = transport.decode(&frame).unwrap();

        assert_eq!(original, &decoded[..]);
    }

    #[test]
    fn test_transport_selector() {
        let mut selector = TransportSelector::new();
        selector.add_transport(DirectTransport::new());
        selector.add_transport(WebSocketTransport::new("ws://test".into()));

        let transport = selector.select(Some(TransportType::WebSocket));
        assert!(transport.is_some());

        let all = selector.all_available();
        assert_eq!(all.len(), 2);
    }
}
