//! Application state for the Shadowgram shell.

use crate::profile::ProfileStore;
use parking_lot::Mutex;
use std::sync::Arc;

pub struct AppState {
    pub store: Arc<Mutex<ProfileStore>>,
    pub client_running: Arc<Mutex<bool>>,
    pub listener_port: Arc<Mutex<Option<u16>>>,
}

impl AppState {
    pub fn new(profile_dir: std::path::PathBuf) -> Result<Self, String> {
        let store = ProfileStore::load_or_init(profile_dir)?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            client_running: Arc::new(Mutex::new(false)),
            listener_port: Arc::new(Mutex::new(None)),
        })
    }
}
