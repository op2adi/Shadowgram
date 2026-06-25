//! Application State Management

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct StoredIdentity {
    pub fingerprint: String,
    pub qr_data: String,
    pub generation: u32,
    pub rotated_from: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone)]
pub struct StoredContact {
    pub id: String,
    pub fingerprint: String,
    pub alias: String,
    pub trust_level: u8,
    pub status: String,
    pub previous_fingerprints: Vec<String>,
    pub updated_at: u64,
}

#[derive(Clone)]
pub struct StoredChat {
    pub id: String,
    pub contact_fingerprint: String,
    pub created_at: u64,
    pub immutable_history: bool,
}

#[derive(Clone)]
pub struct StoredMessage {
    pub id: String,
    pub content: String,
    pub direction: String,
    pub timestamp: u64,
    pub status: String,
    pub error: Option<String>,
    pub destination_fingerprint: String,
    pub immutable: bool,
}

/// Shared application state for the desktop and mobile shell.
pub struct AppState {
    pub client_running: Arc<Mutex<bool>>,
    pub identity: Arc<Mutex<Option<StoredIdentity>>>,
    pub contacts: Arc<Mutex<Vec<StoredContact>>>,
    pub chats: Arc<Mutex<Vec<StoredChat>>>,
    pub messages: Arc<Mutex<HashMap<String, Vec<StoredMessage>>>>,
}

impl AppState {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            client_running: Arc::new(Mutex::new(false)),
            identity: Arc::new(Mutex::new(None)),
            contacts: Arc::new(Mutex::new(Vec::new())),
            chats: Arc::new(Mutex::new(Vec::new())),
            messages: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
