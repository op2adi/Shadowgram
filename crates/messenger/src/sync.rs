//! Multi-Device Synchronization
//!
//! Sync state across multiple devices using threshold secret sharing.

use thiserror::Error;

/// Sync errors
#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Key share error: {0}")]
    KeyShareError(String),

    #[error("Conflict detected: {0}")]
    Conflict(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Device info for multi-device sync
#[derive(Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub public_key: Vec<u8>,
    pub last_sync: u64,
    pub is_current: bool,
}

/// Sync state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Idle,
    Syncing,
    Conflict,
    Error,
}

/// Device synchronization manager
pub struct DeviceSync {
    /// Our device ID
    current_device: String,

    /// Known devices
    devices: Vec<DeviceInfo>,

    /// Current sync status
    status: SyncStatus,

    /// Pending sync operations
    pending_ops: Vec<SyncOperation>,
}

impl DeviceSync {
    /// Create new sync manager
    pub fn new(current_device: String) -> Self {
        Self {
            current_device,
            devices: Vec::new(),
            status: SyncStatus::Idle,
            pending_ops: Vec::new(),
        }
    }

    /// Register a new device
    pub fn register_device(&mut self, device: DeviceInfo) {
        self.devices.push(device);
    }

    /// Get list of known devices
    pub fn devices(&self) -> &[DeviceInfo] {
        &self.devices
    }

    /// Start sync process
    pub fn start_sync(&mut self) -> Result<(), SyncError> {
        if self.status == SyncStatus::Syncing {
            return Err(SyncError::SyncFailed("Already syncing".into()));
        }

        self.status = SyncStatus::Syncing;

        // In production:
        // 1. Gather pending operations
        // 2. Exchange with other devices
        // 3. Resolve conflicts
        // 4. Apply changes

        self.status = SyncStatus::Idle;
        Ok(())
    }

    /// Queue sync operation
    pub fn queue_operation(&mut self, op: SyncOperation) {
        self.pending_ops.push(op);
    }

    /// Get pending operations
    pub fn take_pending_ops(&mut self) -> Vec<SyncOperation> {
        std::mem::take(&mut self.pending_ops)
    }

    /// Get sync status
    pub fn status(&self) -> SyncStatus {
        self.status
    }

    /// Mark device as synced
    pub fn mark_synced(&mut self, device_id: &str) {
        if let Some(device) = self.devices.iter_mut().find(|d| d.device_id == device_id) {
            device.last_sync = current_timestamp();
        }
    }
}

/// Types of sync operations
#[derive(Clone)]
pub enum SyncOperation {
    /// New message to sync
    NewMessage { message_id: String, data: Vec<u8> },

    /// Contact added
    NewContact { fingerprint: String },

    /// Identity update
    IdentityUpdate { new_fingerprint: String },

    /// Device registration
    DeviceRegistered { device_id: String },
}

/// Sync result after processing
#[derive(Clone)]
pub struct SyncResult {
    pub applied_ops: usize,
    pub skipped_ops: usize,
    pub conflicts: Vec<String>,
}

impl SyncResult {
    pub fn success(applied: usize) -> Self {
        Self {
            applied_ops: applied,
            skipped_ops: 0,
            conflicts: Vec::new(),
        }
    }

    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_sync_creation() {
        let sync = DeviceSync::new("device1".to_string());

        assert_eq!(sync.status(), SyncStatus::Idle);
        assert_eq!(sync.devices().len(), 0);
    }

    #[test]
    fn test_device_registration() {
        let mut sync = DeviceSync::new("device1".to_string());

        sync.register_device(DeviceInfo {
            device_id: "device2".to_string(),
            device_name: "Phone".to_string(),
            public_key: vec![1, 2, 3],
            last_sync: 0,
            is_current: false,
        });

        assert_eq!(sync.devices().len(), 1);
    }

    #[test]
    fn test_sync_operations() {
        let mut sync = DeviceSync::new("device1".to_string());

        sync.queue_operation(SyncOperation::NewMessage {
            message_id: "msg1".to_string(),
            data: vec![1, 2, 3],
        });

        let ops = sync.take_pending_ops();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_sync_status_transitions() {
        let mut sync = DeviceSync::new("d1".to_string());

        assert_eq!(sync.status(), SyncStatus::Idle);

        sync.start_sync().unwrap();
        assert_eq!(sync.status(), SyncStatus::Idle); // Goes back to idle after "sync"
    }
}
