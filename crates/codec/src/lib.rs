//! `baileys-codec` — codec binário do WhatsApp (WABinary).
//!
//! Port fiel de `Hineken/src/WABinary/` (`encode.ts`, `decode.ts`, `constants.ts`).
//! As tabelas de tokens em [`constants`] são GERADAS a partir do fonte do Baileys
//! para garantir paridade byte a byte.

pub mod constants;
pub mod decode;
pub mod encode;

pub use decode::{decompress_if_required, decode_binary_node, DecodeError};
pub use encode::encode_binary_node;
