//! Identity Rotation Scheduler
//!
//! Automatic key rotation for enhanced security.
//! Rotated identities maintain contact mappings via pairwise derivation.

use crate::identity::{Identity, RotationPolicy};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Rotation scheduler errors
#[derive(Error, Debug)]
pub enum RotationError {
    #[error("Failed to generate new identity: {0}")]
    GenerationFailed(String),

    #[error("Migration failed: {0}")]
    MigrationFailed(String),
}

/// Tracks identity rotation state
pub struct RotationScheduler {
    /// Current policy
    policy: RotationPolicy,

    /// Last check timestamp
    last_check: u64,

    /// Pending rotation (if any)
    pending_rotation: Option<u64>,
}

impl RotationScheduler {
    /// Create new scheduler with policy
    pub fn new(policy: RotationPolicy) -> Self {
        Self {
            policy,
            last_check: current_timestamp(),
            pending_rotation: None,
        }
    }

    /// Default scheduler
    pub fn default() -> Self {
        Self::new(RotationPolicy::default())
    }

    /// Check if rotation is needed
    pub fn check_rotation(&mut self, identity: &Identity) -> bool {
        self.last_check = current_timestamp();

        if identity.should_rotate(&self.policy) {
            self.pending_rotation = Some(self.last_check);
            true
        } else {
            false
        }
    }

    /// Get time until next rotation
    pub fn time_until_rotation(&self, identity: &Identity) -> u64 {
        let now = current_timestamp();
        let base_time = identity.rotated_at().unwrap_or(identity.created_at());
        let next_rotation = base_time + self.policy.rotation_interval;

        if now >= next_rotation {
            0
        } else {
            next_rotation - now
        }
    }

    /// Get warning status
    pub fn should_warn(&self, identity: &Identity) -> bool {
        let time_left = self.time_until_rotation(identity);
        time_left <= self.policy.warning_threshold
    }

    /// Clear pending rotation
    pub fn rotation_completed(&mut self) {
        self.pending_rotation = None;
        self.last_check = current_timestamp();
    }

    /// Get pending rotation status
    pub fn has_pending_rotation(&self) -> bool {
        self.pending_rotation.is_some()
    }
}

/// Manages identity rotation with contact notification
pub struct IdentityRotator {
    _scheduler: RotationScheduler,

    /// Mapping of old identity fingerprints to new
    /// (for contact transition period)
    transition_map: std::collections::HashMap<String, String>,
}

impl IdentityRotator {
    pub fn new(scheduler: RotationScheduler) -> Self {
        Self {
            _scheduler: scheduler,
            transition_map: std::collections::HashMap::new(),
        }
    }

    /// Rotate identity, returning old -> new mapping
    pub fn rotate_identity(&mut self, old_identity: &Identity) -> Result<RotationResult, RotationError> {
        // Generate new identity
        let new_identity = Identity::generate()
            .map_err(|e| RotationError::GenerationFailed(e.to_string()))?;

        // Record transition
        let old_fp = old_identity.public().fingerprint_full.clone();
        let new_fp = new_identity.public().fingerprint_full.clone();

        self.transition_map.insert(old_fp.clone(), new_fp.clone());

        Ok(RotationResult {
            old_fingerprint: old_fp,
            new_identity,
            transition_active: true,
        })
    }

    /// Check if a fingerprint is in transition
    pub fn is_transitioning(&self, fingerprint: &str) -> bool {
        self.transition_map.contains_key(fingerprint)
    }

    /// Get new fingerprint for transitioning identity
    pub fn get_new_fingerprint(&self, old_fingerprint: &str) -> Option<&String> {
        self.transition_map.get(old_fingerprint)
    }

    /// Clear completed transitions (called after contacts have updated)
    pub fn clear_transition(&mut self, old_fingerprint: &str) {
        self.transition_map.remove(old_fingerprint);
    }
}

/// Result of identity rotation
pub struct RotationResult {
    pub old_fingerprint: String,
    pub new_identity: Identity,
    pub transition_active: bool,
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_rotation_scheduler() {
        let mut scheduler = RotationScheduler::default();
        let identity = Identity::generate().unwrap();

        // Should not need rotation immediately
        assert!(!scheduler.check_rotation(&identity));
        assert!(scheduler.time_until_rotation(&identity) > 0);
    }

    #[test]
    fn test_identity_rotator() {
        let mut rotator = IdentityRotator::new(RotationScheduler::default());
        let old_identity = Identity::generate().unwrap();

        let result = rotator.rotate_identity(&old_identity).unwrap();

        assert_ne!(result.old_fingerprint, result.new_identity.public().fingerprint_full);
        assert!(rotator.is_transitioning(&result.old_fingerprint));
    }
}