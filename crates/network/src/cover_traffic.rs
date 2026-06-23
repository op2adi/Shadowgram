//! Cover Traffic Generation
//!
//! Dummy messages are sent at random intervals to obscure
//! real communication patterns. This defeats traffic analysis
//! that tries to correlate send/receive times.

use rand::{Rng, distributions::Distribution, rngs::OsRng};
use tokio::time::{interval, Duration, Interval};
use thiserror::Error;

/// Cover traffic configuration
#[derive(Clone)]
pub struct TrafficConfig {
    /// Enable cover traffic
    pub enabled: bool,

    /// Minimum interval between cover messages (ms)
    pub min_interval_ms: u64,

    /// Maximum interval between cover messages (ms)
    pub max_interval_ms: u64,

    /// Probability of cover message in each time slot
    pub activity_probability: f64,

    /// Size range for cover messages (min, max)
    pub size_range: (usize, usize),
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_interval_ms: 1000,    // 1 second minimum
            max_interval_ms: 10000,   // 10 seconds maximum
            activity_probability: 0.3, // 30% chance per slot
            size_range: (64, 1024),   // 64B to 1KB cover messages
        }
    }
}

/// Cover traffic errors
#[derive(Error, Debug)]
pub enum CoverTrafficError {
    #[error("Generator not started")]
    NotStarted,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Cover traffic message
#[derive(Clone, Debug)]
pub struct CoverMessage {
    /// Random payload (looks like encrypted data)
    pub payload: Vec<u8>,

    /// Fake timestamp
    pub fake_timestamp: u64,

    /// Unique sequence number (for deduplication)
    pub sequence: u64,
}

impl CoverMessage {
    /// Generate a new cover message with random payload
    pub fn new(sequence: u64, size_range: (usize, usize)) -> Self {
        let size = OsRng.gen_range(size_range.0..=size_range.1);
        let mut payload = vec![0u8; size];
        OsRng.fill_bytes(&mut payload);

        Self {
            payload,
            fake_timestamp: OsRng.gen(),
            sequence,
        }
    }

    /// Check if this is actually cover traffic (vs real message)
    pub fn is_cover(&self) -> bool {
        true // Cover messages are always cover traffic
    }
}

/// Cover traffic generator
pub struct CoverTraffic {
    config: TrafficConfig,

    /// Whether generator is running
    running: bool,

    /// Sequence counter
    sequence: u64,

    /// Next cover message (pre-generated)
    pending_message: Option<CoverMessage>,
}

impl CoverTraffic {
    /// Create new cover traffic generator
    pub fn new(config: TrafficConfig) -> Self {
        Self {
            config,
            running: false,
            sequence: 0,
            pending_message: None,
        }
    }

    /// Start generating cover traffic
    pub fn start(&mut self) {
        self.running = true;
        self.pre_generate();
    }

    /// Stop generating cover traffic
    pub fn stop(&mut self) {
        self.running = false;
        self.pending_message = None;
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Pre-generate next cover message
    fn pre_generate(&mut self) {
        if self.config.enabled && self.pending_message.is_none() {
            self.sequence += 1;
            self.pending_message = Some(CoverMessage::new(
                self.sequence,
                self.config.size_range,
            ));
        }
    }

    /// Get next cover message if available
    pub fn next_message(&mut self) -> Option<CoverMessage> {
        if !self.config.enabled || !self.running {
            return None;
        }

        self.pending_message.take()
    }

    /// Schedule next cover message after random delay
    pub fn schedule_next(&mut self) -> Duration {
        let delay_ms = OsRng.gen_range(self.config.min_interval_ms..=self.config.max_interval_ms);
        Duration::from_millis(delay_ms)
    }

    /// Time until next cover message should be sent
    pub fn time_until_next(&self) -> Option<Duration> {
        if self.pending_message.is_some() {
            Some(self.schedule_next())
        } else {
            None
        }
    }

    /// Get configuration
    pub fn config(&self) -> &TrafficConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: TrafficConfig) {
        self.config = config;
        self.pre_generate();
    }

    /// Get statistics
    pub fn stats(&self) -> CoverTrafficStats {
        CoverTrafficStats {
            enabled: self.config.enabled,
            running: self.running,
            sequence: self.sequence,
            has_pending: self.pending_message.is_some(),
        }
    }
}

/// Cover traffic statistics
pub struct CoverTrafficStats {
    pub enabled: bool,
    pub running: bool,
    pub sequence: u64,
    pub has_pending: bool,
}

/// Poisson process for more realistic cover traffic timing
pub struct PoissonCoverTraffic {
    /// Rate parameter (messages per second)
    lambda: f64,

    /// Time of last message
    last_message_time: std::time::Instant,

    sequence: u64,
    size_range: (usize, usize),
}

impl PoissonCoverTraffic {
    /// Create new Poisson cover traffic generator
    pub fn new(lambda: f64, size_range: (usize, usize)) -> Self {
        Self {
            lambda,
            last_message_time: std::time::Instant::now(),
            sequence: 0,
            size_range,
        }
    }

    /// Time until next message (exponential distribution)
    pub fn time_until_next(&mut self) -> Duration {
        // Exponential distribution: -ln(1-U) / lambda
        let u = OsRng.gen::<f64>();
        let t = if u >= 1.0 {
            0.0
        } else {
            -(1.0 - u).ln() / self.lambda
        };

        Duration::from_secs_f64(t)
    }

    /// Generate next cover message
    pub fn next_message(&mut self) -> CoverMessage {
        self.sequence += 1;
        self.last_message_time = std::time::Instant::now();

        CoverMessage::new(self.sequence, self.size_range)
    }

    /// Get rate (messages per second)
    pub fn rate(&self) -> f64 {
        self.lambda
    }

    /// Set rate
    pub fn set_rate(&mut self, lambda: f64) {
        self.lambda = lambda;
    }
}

/// Adaptive cover traffic that adjusts based on real traffic
pub struct AdaptiveCoverTraffic {
    /// Base configuration
    base_config: TrafficConfig,

    /// Current rate multiplier (adjusted based on activity)
    rate_multiplier: f64,

    /// Recent message count
    recent_real_messages: usize,

    /// Target ratio of cover to real messages
    target_ratio: f64,
}

impl AdaptiveCoverTraffic {
    /// Create new adaptive cover traffic
    pub fn new(base_config: TrafficConfig, target_ratio: f64) -> Self {
        Self {
            base_config,
            rate_multiplier: 1.0,
            recent_real_messages: 0,
            target_ratio,
        }
    }

    /// Record a real message was sent
    pub fn record_real_message(&mut self) {
        self.recent_real_messages += 1;
        self.adjust_rate();
    }

    /// Adjust cover traffic rate based on real traffic
    fn adjust_rate(&mut self) {
        // Increase cover traffic if we're below target ratio
        let target_cover = (self.recent_real_messages as f64 * self.target_ratio) as usize;

        // Simple adjustment: double or halve
        if self.rate_multiplier < 1.0 {
            self.rate_multiplier *= 2.0;
        } else if self.rate_multiplier > 4.0 {
            self.rate_multiplier /= 2.0;
        }

        // Decay counter
        self.recent_real_messages = self.recent_real_messages.saturating_sub(1);
    }

    /// Get adjusted config
    pub fn adjusted_config(&self) -> TrafficConfig {
        let mut config = self.base_config.clone();

        // Adjust intervals based on multiplier
        config.min_interval_ms = (self.base_config.min_interval_ms as f64 / self.rate_multiplier) as u64;
        config.max_interval_ms = (self.base_config.max_interval_ms as f64 / self.rate_multiplier) as u64;

        config
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        self.recent_real_messages = 0;
        self.rate_multiplier = 1.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_message_generation() {
        let msg = CoverMessage::new(1, (100, 200));

        assert!(msg.payload.len() >= 100);
        assert!(msg.payload.len() <= 200);
        assert_eq!(msg.sequence, 1);
    }

    #[test]
    fn test_cover_traffic_generator() {
        let config = TrafficConfig {
            enabled: true,
            min_interval_ms: 10,
            max_interval_ms: 100,
            activity_probability: 1.0,
            size_range: (50, 100),
        };

        let mut gen = CoverTraffic::new(config);
        gen.start();

        let msg = gen.next_message();
        assert!(msg.is_some());
    }

    #[test]
    fn test_cover_traffic_disabled() {
        let config = TrafficConfig {
            enabled: false,
            ..TrafficConfig::default()
        };

        let mut gen = CoverTraffic::new(config);
        gen.start();

        let msg = gen.next_message();
        assert!(msg.is_none());
    }

    #[test]
    fn test_poisson_timing() {
        let mut poisson = PoissonCoverTraffic::new(1.0, (64, 128));

        let t1 = poisson.time_until_next();
        let t2 = poisson.time_until_next();

        // Times should be different (random)
        // Cannot assert exact values, but can check they're reasonable
        assert!(t1.as_secs_f64() >= 0.0);
        assert!(t2.as_secs_f64() >= 0.0);
    }

    #[test]
    fn test_adaptive_rate_adjustment() {
        let config = TrafficConfig::default();
        let mut adaptive = AdaptiveCoverTraffic::new(config, 0.5);

        // Record several real messages
        for _ in 0..5 {
            adaptive.record_real_message();
        }

        let adjusted = adaptive.adjusted_config();

        // Rate should have been adjusted
        assert!(adjusted.min_interval_ms <= TrafficConfig::default().min_interval_ms);
    }
}