// ix-encryption/core/zeroization.rs

//! Implements secure zeroization of memory regions to prevent leakage of sensitive data.

use zeroize::Zeroize;

/// Trait alias for types that support secure zeroization
pub trait SecureZeroize {
    fn secure_zeroize(&mut self);
}

impl SecureZeroize for Vec<u8> {
    fn secure_zeroize(&mut self) {
        self.zeroize();
    }
}

impl SecureZeroize for [u8] {
    fn secure_zeroize(&mut self) {
        self.zeroize();
    }
}

impl SecureZeroize for [u8; 32] {
    fn secure_zeroize(&mut self) {
        self.zeroize();
    }
}

impl SecureZeroize for [u8; 64] {
    fn secure_zeroize(&mut self) {
        self.zeroize();
    }
}

/// Helper to zeroize optional secrets
pub fn zeroize_optional<T: SecureZeroize>(opt: &mut Option<T>) {
    if let Some(inner) = opt {
        inner.secure_zeroize();
    }
    *opt = None;
}
