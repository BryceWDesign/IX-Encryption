// ix-encryption/core/entropy_pool.rs

//! Gathers entropy from multiple sources including OS RNG and optional hardware TRNG.
//! Used to seed cryptographic operations with high entropy input.

use rand::rngs::OsRng;
use rand::RngCore;

#[cfg(feature = "hw_trng")]
use crate::hw::trng::HardwareTrng;

pub struct EntropyPool {
    buffer: Vec<u8>,
}

impl EntropyPool {
    pub fn new(size: usize) -> Self {
        let mut buffer = vec![0u8; size];
        OsRng.fill_bytes(&mut buffer);

        #[cfg(feature = "hw_trng")]
        {
            let mut hw = HardwareTrng::new();
            let mut hw_buf = vec![0u8; size];
            hw.fill_bytes(&mut hw_buf);
            for i in 0..size {
                buffer[i] ^= hw_buf[i];
            }
        }

        EntropyPool { buffer }
    }

    pub fn derive_seed(&self, output_size: usize) -> Vec<u8> {
        use sha2::{Digest, Sha512};

        let mut seed = Vec::with_capacity(output_size);
        let mut hasher = Sha512::new();
        hasher.update(&self.buffer);
        let hash = hasher.finalize();

        seed.extend_from_slice(&hash[..output_size.min(hash.len())]);
        seed
    }
}
