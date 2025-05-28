// ix-encryption/core/self_defense.rs

//! Self-defense module that initiates system lockdown on illegal access detection.

use std::process::Command;
use std::time::{Duration, SystemTime};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;

pub struct SelfDefense {
    illegal_triggered: Arc<AtomicBool>,
}

impl SelfDefense {
    pub fn new() -> Self {
        Self {
            illegal_triggered: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn monitor(&self) {
        let flag = self.illegal_triggered.clone();

        thread::spawn(move || {
            // Simulate a basic polling watchdog.
            loop {
                if flag.load(Ordering::SeqCst) {
                    SelfDefense::initiate_shutdown();
                    break;
                }
                thread::sleep(Duration::from_secs(2));
            }
        });
    }

    pub fn trigger_illegal_access(&self) {
        self.illegal_triggered.store(true, Ordering::SeqCst);
    }

    fn initiate_shutdown() {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("shutdown")
                .args(["/s", "/t", "1", "/f"])
                .spawn();
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let _ = Command::new("shutdown")
                .args(["-h", "now"])
                .spawn();
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            eprintln!("Unsupported OS for shutdown procedure");
        }
    }
}
