// ix-encryption/core/self_defense.rs

//! Self-defense monitoring for encryption module.
//! Detects suspicious activities or illegal access attempts and triggers hardware lockdown.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::core::hardware_lockdown::HardwareLockdown;

pub struct SelfDefense {
    lockdown: Arc<HardwareLockdown>,
    last_activity: Mutex<Instant>,
    suspicious_activity_count: Mutex<u32>,
    threshold: u32,
    cooldown_period: Duration,
}

impl SelfDefense {
    pub fn new(lockdown: Arc<HardwareLockdown>, threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            lockdown,
            last_activity: Mutex::new(Instant::now()),
            suspicious_activity_count: Mutex::new(0),
            threshold,
            cooldown_period: Duration::from_secs(cooldown_secs),
        }
    }

    /// Report suspicious activity; triggers lockdown if threshold exceeded
    pub fn report_activity(&self) {
        let mut count = self.suspicious_activity_count.lock().unwrap();
        let mut last = self.last_activity.lock().unwrap();
        let now = Instant::now();

        if now.duration_since(*last) > self.cooldown_period {
            *count = 0; // reset counter after cooldown
        }

        *count += 1;
        *last = now;

        if *count >= self.threshold {
            self.lockdown.initiate_lockdown();
        }
    }

    /// Check if lockdown is active
    pub fn is_lockdown_active(&self) -> bool {
        self.lockdown.lockdown_triggered()
    }
}
