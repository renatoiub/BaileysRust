//! `baileys-call` — chamadas de voz/vídeo (Fase 4).
//!
//! Placeholder do crate; a implementação completa (webrtc-rs + FFI para
//! `libopus_mlow` + port de sctp-relay/udp-relay/stun) será feita na Fase 4.

/// Estado de uma chamada em andamento.
pub struct Call {
    pub call_id: String,
}

impl Call {
    pub fn new(call_id: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
        }
    }
}
