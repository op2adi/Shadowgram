//! Application State Management

use parking_lot::Mutex;
use std::sync::Arc;

/// Shared application state
pub struct AppState {
    /// Client running status
    pub client: Arc<Mutex<bool>>,

    /// Current identity fingerprint (if any)
    pub identity: Arc<Mutex<Option<String>>>,

    /// Database connection (when implemented)
    // pub db: Arc<Mutex<Option<Database>>>,
}

impl AppState {
    /// Create new application state
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            client: Arc::new(Mutex::new(false)),
            identity: Arc::new(Mutex::new(None)),
        })
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().unwrap()
    }
}