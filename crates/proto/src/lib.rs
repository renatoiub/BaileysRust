//! `baileys-proto` — definições protobuf do WhatsApp.
//!
//! O módulo `proto` é gerado pelo `prost-build` a partir do `WAProto.proto`
//! (cópia exata do `Hineken/WAProto/WAProto.proto`).

/// Módulo gerado (prost). Package = `proto`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

pub use proto::*;
