//! Cryptographic helpers — SHA-256 hashing and HMAC-SHA256 signing.
//!
//! Used for:
//!   - Policy integrity: HMAC-SHA256 signature over rules.json content
//!   - Audit log hash-chain: SHA-256 of each entry body
//!   - Input correlation: SHA-256 of raw prompt/tool input

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Returns the hex-encoded SHA-256 hash of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    bytes_to_hex(Sha256::digest(data).as_slice())
}

/// Returns the hex-encoded HMAC-SHA256 signature of `data` under `key`.
pub fn hmac_sign(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    bytes_to_hex(mac.finalize().into_bytes().as_slice())
}

/// Verifies an HMAC-SHA256 signature using constant-time comparison to
/// prevent timing side-channel attacks.
pub fn hmac_verify(key: &[u8], data: &[u8], expected_hex: &str) -> bool {
    let actual = hmac_sign(key, data);
    constant_time_eq(actual.as_bytes(), expected_hex.as_bytes())
}

/// Encodes a byte slice to lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decodes a lowercase hex string to bytes. Returns `None` on invalid input.
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    // Reject non-ASCII input before any byte-indexing to prevent a panic when
    // a multi-byte UTF-8 char lands on an even byte boundary (L2 audit finding).
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Constant-time byte equality — prevents timing oracles in HMAC verification.
/// Both the length check and the XOR loop run in constant time relative to
/// the longer of the two inputs, eliminating the timing difference between
/// "wrong length" and "correct length, wrong value".
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Process bytes up to the longer length so the loop duration is independent
    // of where the inputs diverge or how long each actually is.
    let max_len = a.len().max(b.len());
    let mut diff = 0u8;
    for i in 0..max_len {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        diff |= x ^ y;
    }
    // Also encode length mismatch so equal-content different-length slices fail.
    diff |= (a.len() != b.len()) as u8;
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- sha256_hex ---

    #[test]
    fn sha256_hex_known_empty() {
        // SHA-256("") is a well-known constant
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_different_inputs_differ() {
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    // --- hmac_sign / hmac_verify ---

    #[test]
    fn hmac_sign_is_deterministic() {
        let key = b"secret";
        let data = b"payload";
        assert_eq!(hmac_sign(key, data), hmac_sign(key, data));
    }

    #[test]
    fn hmac_verify_valid_signature() {
        let key = b"secret-key";
        let data = b"some data";
        let sig = hmac_sign(key, data);
        assert!(hmac_verify(key, data, &sig));
    }

    #[test]
    fn hmac_verify_wrong_key_fails() {
        let data = b"some data";
        let sig = hmac_sign(b"correct-key", data);
        assert!(!hmac_verify(b"wrong-key", data, &sig));
    }

    #[test]
    fn hmac_verify_tampered_data_fails() {
        let key = b"key";
        let sig = hmac_sign(key, b"original");
        assert!(!hmac_verify(key, b"tampered", &sig));
    }

    #[test]
    fn hmac_verify_wrong_hex_fails() {
        let key = b"key";
        let data = b"data";
        assert!(!hmac_verify(
            key,
            data,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    // --- bytes_to_hex / hex_to_bytes roundtrip ---

    #[test]
    fn hex_roundtrip() {
        let original = vec![0u8, 1, 127, 128, 255];
        let hex = bytes_to_hex(&original);
        assert_eq!(hex_to_bytes(&hex), Some(original));
    }

    #[test]
    fn hex_to_bytes_empty_string() {
        assert_eq!(hex_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn hex_to_bytes_odd_length_fails() {
        assert_eq!(hex_to_bytes("abc"), None);
    }

    #[test]
    fn hex_to_bytes_invalid_char_fails() {
        assert_eq!(hex_to_bytes("gg"), None);
    }

    #[test]
    fn hex_to_bytes_non_ascii_fails() {
        // Multi-byte UTF-8 on even byte boundary must not panic
        assert_eq!(hex_to_bytes("é0"), None);
    }

    // --- constant_time_eq ---

    #[test]
    fn constant_time_eq_equal_slices() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_content() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"hello", b"hello!"));
    }

    #[test]
    fn constant_time_eq_same_content_different_length_fails() {
        // "ab" padded with \0 must not equal "ab\0"
        assert!(!constant_time_eq(b"ab", b"ab\0"));
    }

    #[test]
    fn constant_time_eq_empty_slices() {
        assert!(constant_time_eq(b"", b""));
    }
}
