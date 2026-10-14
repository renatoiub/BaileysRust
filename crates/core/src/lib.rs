//! `baileys-core` — núcleo do BaileysRust.
//!
//! Este crate contém os tipos e utilidades fundamentais usados pelos demais
//! crates do workspace, espelhando os módulos `WABinary/jid-utils.ts`,
//! `WABinary/types.ts` e `Utils/generics.ts` do Baileys/Hineken.

pub mod constants;
pub mod ids;
pub mod jid;
pub mod node;

pub use constants::*;
pub use ids::*;
pub use jid::*;
pub use node::{BinaryContent, BinaryNode};
