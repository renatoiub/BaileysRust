//! `baileys-repository` — repositório de alto nível do Signal.
//!
//! Port fiel de `Hineken/src/Signal/libsignal.ts` (`makeLibSignalRepository`):
//! conecta o protocolo `baileys-signal` (ratchet 1:1 e sender key) ao
//! armazenamento persistente compatível com o Node (`baileys-store`).

mod repository;
mod store;

pub use repository::{
    GroupEncryptResult, InjectPreKey, InjectSession, InjectSignedPreKey, SignalRepository,
};
pub use store::{SignalStoreExtension, SqliteSignalStore};

/// Resultado padrão do crate.
pub type Result<T> = std::result::Result<T, baileys_signal::error::SignalError>;
