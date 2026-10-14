//! `baileys-store` — auth state compatível com o Baileys.
//!
//! Implementa leitura/escrita de sessões no formato exato do container Node,
//! com SQLite nativo como armazenamento padrão:
//!
//! - SQLite `db/{key}/db.sqlite`, tabela `auth_data (key TEXT PRIMARY KEY, value TEXT)`.
//! - Serialização `BufferJSON` (buffers → `{"type":"Buffer","data":"<base64>"}`).
//!
//! A camada Redis (como o `authKeysRedis.ts` do Node) pertence ao app
//! (containerRust) e é injetada via `SignalStoreExtension` no
//! `baileys-repository` — a biblioteca em si só depende de SQLite.
//!
//! Ver `BaileysRust/docs/SESSION_FORMAT.md` para a spec completa.

pub mod buffer_json;
pub mod creds;
pub mod sqlite;

pub use creds::{init_auth_creds, AuthenticationCreds, BufferValue, SerializedKeyPair, SignedKeyPair};
