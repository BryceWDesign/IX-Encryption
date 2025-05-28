// ix-encryption/core/mode_cascade.rs

//! Cascade mode: sequential block cipher chaining for layered security

use crate::core::blockcipher::BlockCipher;

/// CascadeMode allows chaining multiple block ciphers in sequence
pub struct CascadeMode<'a> {
    ciphers: Vec<&'a dyn BlockCipher>,
}

impl<'a> CascadeMode<'a> {
    pub fn new(ciphers: Vec<&'a dyn BlockCipher>) -> Self {
        assert!(!ciphers.is_empty(), "At least one cipher required for cascade mode");

        let size = ciphers[0].block_size();
        for c in &ciphers {
            assert_eq!(c.block_size(), size, "All ciphers must have the same block size");
        }

        CascadeMode { ciphers }
    }

    /// Encrypt a block through the entire cascade
    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        self.ciphers.iter().fold(block.to_vec(), |acc, cipher| cipher.encrypt_block(&acc))
    }

    /// Decrypt a block through the entire cascade in reverse
    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        self.ciphers.iter().rev().fold(block.to_vec(), |acc, cipher| cipher.decrypt_block(&acc))
    }
}
