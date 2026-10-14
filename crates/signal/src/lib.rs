//! `baileys-signal` — protocolo Signal (E2E) compatível byte a byte.
//!
//! Port fiel de:
//! - `Hineken/src/Signal/libsignal.ts` (repositório de alto nível)
//! - `Hineken/src/Signal/Group/*` (GroupCipher, SenderKey)
//! - `libsignal-node` (`@whiskeysockets/libsignal-node`) para o ratchet 1:1
//!
//! Garantias:
//! - Serialização de `SessionRecord` idêntica (base64, `_sessions`, `_chains`).
//! - Serialização de `SenderKeyRecord` idêntica (array JSON de estados).
//! - `WhisperMessage`/`PreKeyWhisperMessage` protobuf com os MESMOS números de campo.
//! - Derivação de chaves via `crypto.deriveSecrets` (HMAC-SHA256, info `WhisperText`).

pub mod error;
pub mod protocol;

pub use error::SignalError;

/// Resultado padrão do crate.
pub type Result<T> = std::result::Result<T, SignalError>;
