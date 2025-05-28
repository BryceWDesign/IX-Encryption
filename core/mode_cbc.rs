// ix-encryption/core/mode_cbc.rs

//! Cipher Block Chaining (CBC) mode encryption/decryption

use crate::core::blockcipher::BlockCipher;
use crate::core::padding::{pkcs7_pad, pkcs7_unpad};

pub struct CBCMode<'a, C: BlockCipher> {
    cipher: &'a C,
    iv: Vec<u8>,
}

impl<'a, C: BlockCipher> CBCMode<'a, C> {
    pub fn new(cipher: &'a C, iv: Vec<u8>) -> Self {
        assert_eq!(iv.len(), cipher.block_size(), "IV length mismatch");
        CBCMode { cipher, iv }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let block_size = self.cipher.block_size();
        let padded = pkcs7_pad(plaintext, block_size);
        let mut ciphertext = Vec::with_capacity(padded.len());
        let mut previous_block = self.iv.clone();

        for chunk in padded.chunks(block_size) {
            let block: Vec<u8> = chunk.iter()
                .zip(previous_block.iter())
                .map(|(&a, &b)| a ^ b)
                .collect();

            let encrypted = self.cipher.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted);
            previous_block = encrypted;
        }

        ciphertext
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let block_size = self.cipher.block_size();
        if ciphertext.len() % block_size != 0 {
            return Err("Ciphertext length not aligned");
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut previous_block = self.iv.clone();

        for chunk in ciphertext.chunks(block_size) {
            let decrypted = self.cipher.decrypt_block(chunk);
            let block: Vec<u8> = decrypted.iter()
                .zip(previous_block.iter())
                .map(|(&a, &b)| a ^ b)
                .collect();

            plaintext.extend_from_slice(&block);
            previous_block = chunk.to_vec();
        }

        pkcs7_unpad(&plaintext)
    }
}
