// ix-encryption/core/padding.rs

//! Implements PKCS7 padding to ensure plaintext is a multiple of block size.

/// Pads input using PKCS7 to match a given block size
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size > 0 && block_size <= 255, "Invalid block size");

    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    padded
}

/// Removes PKCS7 padding and validates result
pub fn pkcs7_unpad(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if padded.is_empty() {
        return Err("Empty input");
    }

    let last_byte = *padded.last().unwrap();
    let pad_len = last_byte as usize;

    if pad_len == 0 || pad_len > padded.len() {
        return Err("Invalid padding");
    }

    if !padded[padded.len() - pad_len..].iter().all(|&b| b == last_byte) {
        return Err("Malformed padding");
    }

    Ok(padded[..padded.len() - pad_len].to_vec())
}
