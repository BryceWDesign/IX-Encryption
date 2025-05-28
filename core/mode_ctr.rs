// ix-encryption/core/mode_ctr.rs

//! Counter (CTR) mode stream cipher implementation

use crate::core::blockcipher::BlockCipher;

/// CTR mode struct holding cipher and nonce/counter
pub struct CTRMode<'a, C: BlockCipher> {
    cipher: &'a C,
    nonce: Vec<u8>,
}

impl<'a, C: BlockCipher> CTRMode<'a, C> {
    pub fn new(cipher: &'a C, nonce: Vec<u8>) -> Self {
        assert_eq!(nonce.len(), cipher.block_size(), "Nonce length must match block size");
        CTRMode { cipher, nonce }
    }

    /// Encrypt or decrypt input using CTR mode (symmetric stream)
    pub fn process(&self, input: &[u8]) -> Vec<u8> {
        let block_size = self.cipher.block_size();
        let mut output = Vec::with_capacity(input.len());
        let mut counter_block = self.nonce.clone();

        for (i, chunk) in input.chunks(block_size).enumerate() {
            let keystream = self.cipher.encrypt_block(&counter_block);
            let block: Vec<u8> = chunk.iter()
                .zip(keystream.iter())
                .map(|(&x, &k)| x ^ k)
                .collect();

            output.extend_from_slice(&block);
            Self::increment_counter(&mut counter_block);
        }

        output
    }

    fn increment_counter(counter: &mut [u8]) {
        for i in (0..counter.len()).rev() {
            if counter[i] == 0xFF {
                counter[i] = 0;
            } else {
                counter[i] += 1;
                break;
            }
        }
    }
}
