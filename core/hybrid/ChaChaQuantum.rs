// ix-encryption/core/hybrid/ChaChaQuantum.rs

//! Hybrid implementation using ChaCha20-Poly1305 with planned lattice augmentation.
//! Designed for embedded, high-performance, and space-grade environments.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use crate::core::IXCipherCore;

pub struct ChaChaQuantum {
    cipher: Option<ChaCha20Poly1305>,
    nonce: [u8; 12],
    lockdown_enabled: bool,
}

impl ChaChaQuantum {
    pub fn new() -> Self {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).expect("Nonce generation failed");
        Self {
            cipher: None,
            nonce,
            lockdown_enabled: false,
        }
    }
}

impl IXCipherCore for ChaChaQuantum {
    fn initialize(&mut self, key: &[u8], _salt: Option<&[u8]>) {
        let key = Key::from_slice(&key[0..32]); // truncate or pad key externally
        self.cipher = Some(ChaCha20Poly1305::new(key));
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(&self.nonce);
        self.cipher
            .as_ref()
            .expect("Cipher not initialized")
            .encrypt(nonce, plaintext)
            .expect("Encryption failed")
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(&self.nonce);
        self.cipher
            .as_ref()
            .expect("Cipher not initialized")
            .decrypt(nonce, ciphertext)
            .expect("Decryption failed")
    }

    fn wipe(&mut self) {
        self.cipher = None;
        self.nonce = [0u8; 12];
    }

    fn algorithm_id(&self) -> &'static str {
        "IX-ChaChaQuantum-v1"
    }

    fn trigger_lockdown(&self) -> bool {
        if self.lockdown_enabled {
            println!("[IX] Unauthorized access detected. Triggering lockdown...");
            std::process::exit(1337);
        }
        false
    }
}
