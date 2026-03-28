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
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Constant-time byte equality — prevents timing oracles in HMAC verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
