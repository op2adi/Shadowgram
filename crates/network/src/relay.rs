//! Multi-Path Relay Routing
//!
//! Send messages through multiple paths simultaneously for:
//! - Redundancy (message gets through even if some paths fail)
//! - Analysis resistance (observer can't tell which path is "real")
//! - Load balancing

use rand::{Rng, seq::SliceRandom};
use std::collections::HashMap;
use thiserror::Error;

/// Relay configuration
#[derive(Clone)]
pub struct RelayConfig {
    /// Minimum number of paths to use
    pub min_paths: usize,

    /// Maximum number of paths to use
    pub max_paths: usize,

    /// Whether to send duplicate messages on all paths
    pub send_duplicates: bool,

    /// Timeout for each path (ms)
    pub path_timeout_ms: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            min_paths: 2,
            max_paths: 3,
            send_duplicates: true,
            path_timeout_ms: 5000,
        }
    }
}

/// Relay errors
#[derive(Error, Debug)]
pub enum RelayError {
    #[error("No available relays")]
    NoRelays,

    #[error("Path construction failed: {0}")]
    PathConstructionFailed(String),

    #[error("All paths failed")]
    AllPathsFailed,

    #[error("Timeout exceeded")]
    Timeout,
}

/// A relay node in the network
#[derive(Clone)]
pub struct RelayNode {
    /// Unique identifier
    pub id: String,

    /// Onion address
    pub address: String,

    /// Public key for encryption
    pub public_key: Vec<u8>,

    /// Latency in ms (measured)
    pub latency_ms: u64,

    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,

    /// Current load (0.0 - 1.0)
    pub load: f64,

    /// Whether relay is active
    pub active: bool,
}

impl RelayNode {
    pub fn new(id: String, address: String, public_key: Vec<u8>) -> Self {
        Self {
            id,
            address,
            public_key,
            latency_ms: 0,
            success_rate: 1.0,
            load: 0.0,
            active: true,
        }
    }

    /// Calculate relay score (higher is better)
    pub fn score(&self) -> f64 {
        if !self.active {
            return 0.0;
        }

        // Weighted score: success rate most important, then latency, then load
        self.success_rate * 0.5
            + (1.0 - self.load) * 0.3
            + (1.0 - (self.latency_ms as f64 / 1000.0).min(1.0)) * 0.2
    }
}

/// Relay pool manager
pub struct RelayPool {
    /// Available relays
    relays: HashMap<String, RelayNode>,

    /// Configuration
    config: RelayConfig,

    /// Path history for performance tracking
    path_history: Vec<PathResult>,
}

impl RelayPool {
    /// Create new relay pool
    pub fn new(config: RelayConfig) -> Self {
        Self {
            relays: HashMap::new(),
            config,
            path_history: Vec::new(),
        }
    }

    /// Add relay to pool
    pub fn add_relay(&mut self, relay: RelayNode) {
        self.relays.insert(relay.id.clone(), relay);
    }

    /// Remove relay from pool
    pub fn remove_relay(&mut self, relay_id: &str) {
        self.relays.remove(relay_id);
    }

    /// Get relay by ID
    pub fn get_relay(&self, relay_id: &str) -> Option<&RelayNode> {
        self.relays.get(relay_id)
    }

    /// Get all active relays
    pub fn active_relays(&self) -> Vec<&RelayNode> {
        self.relays.values()
            .filter(|r| r.active)
            .collect()
    }

    /// Select best relays for multi-path routing
    pub fn select_relays(&self, count: usize) -> Vec<&RelayNode> {
        let mut scored: Vec<_> = self.active_relays();

        // Sort by score (descending)
        scored.sort_by(|a, b| {
            b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top N
        scored.into_iter().take(count).collect()
    }

    /// Select relays randomly (for analysis resistance)
    pub fn select_random_relays(&self, count: usize) -> Vec<&RelayNode> {
        let mut relays: Vec<_> = self.active_relays();

        if relays.len() <= count {
            return relays;
        }

        // Shuffle and take
        relays.shuffle(&mut rand::thread_rng());
        relays.into_iter().take(count).collect()
    }

    /// Record path result for future selection
    pub fn record_path_result(&mut self, result: PathResult) {
        self.path_history.push(result);

        // Keep only recent history
        if self.path_history.len() > 1000 {
            self.path_history.drain(0..self.path_history.len() - 1000);
        }

        // Update relay statistics
        if let Some(latency) = result.latency_ms {
            if let Some(relay) = self.relays.get_mut(&result.relay_id) {
                // Exponential moving average
                relay.latency_ms = (relay.latency_ms as f64 * 0.9 + latency as f64 * 0.1) as u64;
            }
        }

        if !result.success {
            if let Some(relay) = self.relays.get_mut(&result.relay_id) {
                relay.success_rate *= 0.95; // Decay on failure
            }
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> RelayPoolStats {
        let active = self.active_relays().len();
        let avg_score = self.relays.values()
            .filter(|r| r.active)
            .map(|r| r.score())
            .sum::<f64>()
            / active.max(1) as f64;

        RelayPoolStats {
            total_relays: self.relays.len(),
            active_relays: active,
            average_score: avg_score,
            recent_paths: self.path_history.len(),
        }
    }
}

/// Result of sending via a path
pub struct PathResult {
    pub relay_id: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub timestamp: std::time::Instant,
}

/// Relay pool statistics
pub struct RelayPoolStats {
    pub total_relays: usize,
    pub active_relays: usize,
    pub average_score: f64,
    pub recent_paths: usize,
}

/// Multi-path routing for sending same message via multiple relays
pub struct MultiPathRouting {
    pool: RelayPool,
    config: RelayConfig,
}

impl MultiPathRouting {
    /// Create new multi-path router
    pub fn new(pool: RelayPool, config: RelayConfig) -> Self {
        Self { pool, config }
    }

    /// Build multiple paths for redundancy
    pub fn build_paths(&self) -> Result<Vec<Vec<&RelayNode>>, RelayError> {
        let relays = self.pool.active_relays();

        if relays.len() < self.config.min_paths {
            return Err(RelayError::NoRelays);
        }

        let num_paths = relays.len().min(self.config.max_paths);
        let mut paths = Vec::with_capacity(num_paths);

        // Simple: each path is single relay
        // In production: paths could be multiple hops
        for relay in relays.into_iter().take(num_paths) {
            paths.push(vec![relay]);
        }

        Ok(paths)
    }

    /// Send message via all paths
    pub async fn send_multi_path(
        &self,
        message: &[u8],
    ) -> Result<SendResult, RelayError> {
        let paths = self.build_paths()?;

        if paths.is_empty() {
            return Err(RelayError::NoRelays);
        }

        // In production, would actually send via all paths concurrently
        // For now, simulate with success

        Ok(SendResult {
            paths_used: paths.len(),
            successes: paths.len(),
            failures: 0,
            min_latency_ms: 0,
        })
    }

    /// Send and wait for first successful delivery
    pub async fn send_first_wins(
        &self,
        message: &[u8],
    ) -> Result<SendResult, RelayError> {
        let paths = self.build_paths()?;

        if paths.is_empty() {
            return Err(RelayError::NoRelays);
        }

        // In production, would race all paths and cancel losers

        Ok(SendResult {
            paths_used: paths.len(),
            successes: 1, // First one wins
            failures: paths.len() - 1,
            min_latency_ms: 0,
        })
    }

    /// Get relay pool reference
    pub fn pool(&self) -> &RelayPool {
        &self.pool
    }

    /// Get relay pool mutable reference
    pub fn pool_mut(&mut self) -> &mut RelayPool {
        &mut self.pool
    }
}

/// Result of multi-path send
pub struct SendResult {
    pub paths_used: usize,
    pub successes: usize,
    pub failures: usize,
    pub min_latency_ms: u64,
}

/// Path selection strategy
pub enum PathStrategy {
    /// Use best-scoring relays
    BestScore,

    /// Use random relays (analysis resistance)
    Random,

    /// Use least-loaded relays
    LeastLoaded,

    /// Use lowest-latency relays
    LowestLatency,
}

impl PathStrategy {
    /// Select relays based on strategy
    pub fn select(&self, pool: &RelayPool, count: usize) -> Vec<&RelayNode> {
        match self {
            PathStrategy::BestScore => pool.select_relays(count),
            PathStrategy::Random => pool.select_random_relays(count),
            PathStrategy::LeastLoaded => {
                let mut relays = pool.active_relays();
                relays.sort_by(|a, b| a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal));
                relays.into_iter().take(count).collect()
            }
            PathStrategy::LowestLatency => {
                let mut relays = pool.active_relays();
                relays.sort_by(|a, b| a.latency_ms.cmp(&b.latency_ms));
                relays.into_iter().take(count).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_node_scoring() {
        let mut relay = RelayNode::new("r1".into(), "r1.onion:8080".into(), vec![1; 32]);
        relay.success_rate = 0.99;
        relay.load = 0.1;
        relay.latency_ms = 50;

        let score = relay.score();
        assert!(score > 0.5); // High score for good relay
    }

    #[test]
    fn test_relay_pool_selection() {
        let mut pool = RelayPool::new(RelayConfig::default());

        // Add some relays
        for i in 0..5 {
            let mut relay = RelayNode::new(
                format!("relay{}", i),
                format!("relay{}.onion:8080", i),
                vec![i as u8; 32],
            );
            relay.success_rate = 0.9 + (i as f64 * 0.02);
            pool.add_relay(relay);
        }

        let selected = pool.select_relays(3);
        assert_eq!(selected.len(), 3);

        // Should select best scoring
        let best = pool.select_relays(1);
        assert_eq!(best[0].id, "relay4"); // Highest success rate
    }

    #[test]
    fn test_multi_path_building() {
        let mut pool = RelayPool::new(RelayConfig::default());

        for i in 0..3 {
            pool.add_relay(RelayNode::new(
                format!("r{}", i),
                format!("r{}.onion", i),
                vec![i as u8; 32],
            ));
        }

        let routing = MultiPathRouting::new(pool, RelayConfig::default());
        let paths = routing.build_paths().unwrap();

        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn test_pool_stats() {
        let mut pool = RelayPool::new(RelayConfig::default());

        pool.add_relay(RelayNode::new("r1".into(), "r1.onion".into(), vec![1; 32]));
        pool.add_relay(RelayNode::new("r2".into(), "r2.onion".into(), vec![2; 32]));

        let stats = pool.stats();
        assert_eq!(stats.total_relays, 2);
        assert_eq!(stats.active_relays, 2);
    }
}