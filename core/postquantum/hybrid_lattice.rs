// ix-encryption/core/postquantum/hybrid_lattice.rs

//! Hybrid encryption combining lattice-based KEM with symmetric ChaCha20-Poly1305 cipher.
//! Designed for quantum-resistant session key exchange and efficient data encryption.

use crate::core::IXCipherCore;
use crate::core::hybrid::ChaChaQuantum;
use crate::core::postquantum::lattice_kem::LatticeKEM;

pub struct HybridLatticeCipher {
    lattice_kem: LatticeKEM,
    symmetric_cipher: ChaChaQuantum,
    session_key: Option<Vec<u8>>,
}

impl HybridLatticeCipher {
    pub fn new() -> Self {
        Self {
            lattice_kem: LatticeKEM::keypair(),
            symmetric_cipher: ChaChaQuantum::new(),
            session_key: None,
        }
    }

    /// Generate and encapsulate session key to encrypt data
    pub fn encapsulate_key(&mut self, peer_public_key: &[u8]) -> Vec<u8> {
        let (ciphertext, shared_secret) = self.lattice_kem.encapsulate(peer_public_key);
        self.session_key = Some(shared_secret.clone());
        self.symmetric_cipher.initialize(&shared_secret, None);
        ciphertext
    }

    /// Decapsulate session key from ciphertext and initialize symmetric cipher
    pub fn decapsulate_key(&mut self, ciphertext: &[u8]) {
        let shared_secret = self.lattice_kem.decapsulate(ciphertext);
        self.session_key = Some(shared_secret.clone());
        self.symmetric_cipher.initialize(&shared_secret, None);
    }
}

impl IXCipherCore for HybridLatticeCipher {
    fn initialize(&mut self, key: &[u8], salt: Option<&[u8]>) {
        // For compatibility, initialize symmetric cipher directly with key
        self.symmetric_cipher.initialize(key, salt);
        self.session_key = Some(key.to_vec());
    }

    f
