// ix-encryption/core/IXCipherCore.rs

//! Core trait for the IX Encryption Engine.
//! This defines the interface for hybrid cryptographic methods
//! supporting classical, quantum-resistant, and adaptive extensions.

pub trait IXCipherCore {
    /// Initialize cipher with a given key and optional salt or IV.
    fn initialize(&mut self, key: &[u8], salt: Option<&[u8]>);

    /// Encrypts a block of data. Returns ciphertext as Vec<u8>.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;

    /// Decrypts a block of data. Returns plaintext as Vec<u8>.
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;

    /// Securely wipes internal state from memory.
    fn wipe(&mut self);

    /// Returns a unique identifier for this cipher method (used for multiplexing).
    fn algorithm_id(&self) -> &'static str;

    /// Optional: activates a lockdown state (used for system kill switch or terminal shutdown logic).
    fn trigger_lockdown(&self) -> bool;
}
