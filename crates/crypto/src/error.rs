//! Tipos de erro do `baileys-crypto`.

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("hkdf failed")]
    HkdfFailed,
    #[error("pbkdf2 failed")]
    Pbkdf2Failed,
    #[error("hmac failed")]
    HmacFailed,
}
