//! Crypto helpers for the Signal protocol (re-exported from `baileys-crypto`).

use baileys_crypto::{aes_decrypt_cbc, aes_encrypt_cbc, derive_secrets as crypto_derive_secrets, hmac_sign, HmacVariant};

use crate::error::SignalError;
use crate::Result;

/// `calculateMAC` — HMAC-SHA256.
pub fn calculate_mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_sign(data, key, HmacVariant::Sha256)
}

/// `deriveSecrets` — até 3 chunks de 32 bytes.
pub fn derive_secrets(input: &[u8], salt: &[u8], info: &[u8], chunks: usize) -> Result<Vec<Vec<u8>>> {
    crypto_derive_secrets(input, salt, info, chunks).map_err(SignalError::from)
}

/// `encrypt` — AES-256-CBC PKCS7.
pub fn encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    aes_encrypt_cbc(data, key, iv).map_err(SignalError::from)
}

/// `decrypt` — AES-256-CBC PKCS7.
pub fn decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    aes_decrypt_cbc(data, key, iv).map_err(SignalError::from)
}

/// `verifyMAC` — compara HMAC-SHA256 truncado com `length` bytes.
pub fn verify_mac(data: &[u8], key: &[u8], mac: &[u8], length: usize) -> Result<()> {
    let calculated = calculate_mac(key, data);
    if mac.len() != length || calculated.len() < length {
        return Err(SignalError::BadMac);
    }
    if !constant_time_eq(&calculated[..length], mac) {
        return Err(SignalError::BadMac);
    }
    Ok(())
}

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
