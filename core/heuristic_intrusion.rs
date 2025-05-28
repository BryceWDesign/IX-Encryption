// ix-encryption/core/heuristic_intrusion.rs

//! Heuristic-based intrusion detection engine for real-time threat analysis.

use std::time::{Duration, Instant};

pub struct HeuristicIntrusionDetector {
    last_entropy_score: f64,
    last_timestamp: Instant,
}

impl HeuristicIntrusionDetector {
    pub fn new() -> Self {
        Self {
            last_entropy_score: 0.0,
            last_timestamp: Instant::now(),
        }
    }

    /// Analyze new entropy signature and compare it against historical behavior.
    pub fn analyze_entropy(&mut self, current_entropy: f64) -> bool {
        let now = Instant::now();
        let time_delta = now.duration_since(self.last_timestamp);
        let entropy_delta = (current_entropy - self.last_entropy_score).abs();

        // Arbitrary thresholds can be tuned per deployment
        let suspicious_entropy_jump = entropy_delta > 2.0;
        let suspicious_frequency = time_delta < Duration::from_millis(50);

        self.last_entropy_score = current_entropy;
        self.last_timestamp = now;

        suspicious_entropy_jump && suspicious_frequency
    }

    /// Analyze I/O timing jitter for anomaly detection.
    pub fn analyze_timing_jitter(&self, event_times: &[Duration]) -> bool {
        if event_times.len() < 2 {
            return false;
        }

        let mean = event_times.iter().map(|d| d.as_micros()).sum::<u128>() as f64
            / event_times.len() as f64;
        let variance = event_times.iter().map(|d| {
