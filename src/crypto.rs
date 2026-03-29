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
    if !hex.len().is_multiple_of(2) {
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
