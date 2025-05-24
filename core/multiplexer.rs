// ix-encryption/core/multiplexer.rs

//! Multiplexer to combine multiple IXCipherCore implementations into one unified hybrid cipher.
//! Enables dynamic selection and layered encryption for defense in depth.

use crate::core::IXCipherCore;

pub struct IXCipherMultiplexer {
    ciphers: Vec<Box<dyn IXCipherCore>>,
}

impl IXCipherMultiplexer {
    pub fn new() -> Self {
        Self {
            ciphers: Vec::new(),
        }
    }

    /// Add a cipher implementation to the multiplexer
    pub fn add_cipher(&mut self, cipher: Box<dyn IXCipherCore>) {
        self.ciphers.push(cipher);
    }

    /// Trigger lockdown on all ciphers
    pub fn trigger_lockdown_all(&self) -> bool {
        for cipher in &self.ciphers {
            if cipher.trigger_lockdown() {
                return true;
            }
        }
        false
    }
}

impl IXCipherCore for IXCipherMultiplexer {
    fn initialize(&mut self, key: &[u8], salt: Option<&[u8]>) {
        // Split key per cipher equally for initialization
        let part_len = key.len() / self.ciphers.len().max(1);
        for (i, cipher) in self.ciphers.iter_mut().enumerate() {
            let start = i * part_len;
            let end = start + part_len;
            let part_key = &key[start..end.min(key.len())];
            cipher.initialize(part_key, salt);
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Layered encryption: encrypt through each cipher in order
        let mut data = plaintext.to_vec();
        for cipher in &self.ciphers {
            data = cipher.encrypt(&data);
        }
        data
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        // Reverse layered decryption
        let mut data = ciphertext.to_vec();
        for cipher in self.ciphers.iter().rev() {
            data = cipher.decrypt(&data);
        }
        data
    }

    fn wipe(&mut self) {
        for cipher in &mut self.ciphers {
            cipher.wipe();
        }
    }

    fn algorithm_id(&self) -> &'static str {
        "IX-Multiplexer-v1"
    }

    fn trigger_lockdown(&self) -> bool {
        self.trigger_lockdown_all()
    }
}
