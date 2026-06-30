//! Application state for the Shadowgram shell.

use crate::profile::ProfileStore;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Commands dispatched from synchronous Tauri handlers to the async Tor manager.
#[derive(Debug)]
pub enum TorCommand {
    /// Send `content` on `chat_id`; update message `message_id` status on result.
    SendMessage {
        chat_id: String,
        message_id: String,
        content: String,
        dest_onion: String,
    },
    /// Retry all queued outbound messages now.
    RetryPending,
}

/// Current Tor bootstrap / onion-service status (reported to the frontend).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TorStatus {
    pub bootstrapped: bool,
    pub onion_address: Option<String>,
    pub error: Option<String>,
}

impl Default for TorStatus {
    fn default() -> Self {
        Self {
            bootstrapped: false,
            onion_address: None,
            error: None,
        }
    }
}

pub struct AppState {
    pub store: Arc<Mutex<ProfileStore>>,
    pub client_running: Arc<Mutex<bool>>,
    /// Kept for backward-compat with the old TCP transport (port-based); unused by Tor path.
    pub listener_port: Arc<Mutex<Option<u16>>>,
    /// Tokio runtime owned by the Tauri process for async Tor work.
    pub runtime: Arc<Runtime>,
    /// Channel into the async TorManager task.  None until `start_tor` is called.
    pub tor_tx: Arc<Mutex<Option<mpsc::Sender<TorCommand>>>>,
    /// Latest Tor status, readable from any command handler.
    pub tor_status: Arc<Mutex<TorStatus>>,
}

impl AppState {
    pub fn new(profile_dir: std::path::PathBuf) -> Result<Self, String> {
        let store = ProfileStore::load_or_init(profile_dir)?;
        let runtime = Runtime::new().map_err(|e| e.to_string())?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            client_running: Arc::new(Mutex::new(false)),
            listener_port: Arc::new(Mutex::new(None)),
            runtime: Arc::new(runtime),
            tor_tx: Arc::new(Mutex::new(None)),
            tor_status: Arc::new(Mutex::new(TorStatus::default())),
        })
    }
}
