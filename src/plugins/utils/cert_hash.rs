use base64::Engine;
use sha2::{Digest, Sha256};

pub fn sha256_hex_lower(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn sha256_base64url_no_pad(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}
