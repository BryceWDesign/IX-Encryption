// ix-encryption/core/audit_logger.rs

//! Secure audit logger for encryption operations.
//! Logs events with tamper-evident chaining using cryptographic hashes.

use std::fs::{OpenOptions, File};
use std::io::{Write, BufReader, BufRead};
use std::path::Path;
use sha2::{Sha256, Digest};
use chrono::Utc;

const LOG_FILE_PATH: &str = "ix_encryption_audit.log";

pub struct AuditLogger {
    last_hash: Option<Vec<u8>>,
    log_file: File,
}

impl AuditLogger {
    pub fn new(log_path: &str) -> std::io::Result<Self> {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(log_path)?;

        let last_hash = Self::get_last_hash(log_path).unwrap_or(None);

        Ok(Self {
            last_hash,
            log_file,
        })
    }

    fn get_last_hash(log_path: &str) -> std::io::Result<Option<Vec<u8>>> {
        if !Path::new(log_path).exists() {
            return Ok(None);
        }
        let file = File::open(log_path)?;
        let reader = BufReader::new(file);
        let mut last_line = None;
        for line in reader.lines() {
            last_line = Some(line?);
        }
        if let Some(line) = last_line {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let hash_hex = parts[2];
                return Ok(Some(hex::decode(hash_hex).unwrap_or_default()));
            }
        }
        Ok(None)
    }

    pub fn log_event(&mut self, event: &str) -> std::io::Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        let mut hasher = Sha256::new();
        hasher.update(timestamp.as_bytes());
        hasher.update(event.as_bytes());
        if let Some(ref prev_hash) = self.last_hash {
            hasher.update(prev_hash);
        }
        let new_hash = hasher.finalize();
        let hash_hex = hex::encode(&new_hash);

        let log_entry = format!("{}|{}|{}\n", timestamp, event, hash_hex);
        self.log_file.write_all(log_entry.as_bytes())?;
        self.log_file.flush()?;

        self.last_hash = Some(new_hash.to_vec());
        Ok(())
    }
}
