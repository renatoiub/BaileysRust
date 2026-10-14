//! `baileys-call` — chamadas de voz/vídeo do WhatsApp.
//!
//! Fase 4: port de `container/src/services/call/*` (RTP/SRTP, STUN,
//! libopus_mlow via FFI, signaling e relays UDP/SCTP).

pub mod audio;
pub mod call_manager;
pub mod encryption;
pub mod mlow;
pub mod player;
pub mod rtp;
pub mod signaling;
pub mod srtp;
pub mod state;
pub mod stun;
pub mod types;
pub mod udp_relay;

pub use call_manager::NativeCallManager;
pub use encryption::{derive_per_jid_srtp_key, generate_call_key};
pub use rtp::{RtpHeader, RtpPacket, RtpSession};
pub use signaling::{
    build_accept_stanza, build_accepted_elsewhere_stanza, build_offer_stanza,
    build_preaccept_stanza, build_reject_stanza, build_relay_latency_stanza,
    build_terminate_stanza, build_terminate_to_device_stanza, build_transport_stanza,
    create_call_ack, decrypt_call_key_in_node, ensure_device_jid, extract_node_info,
    extract_relay_endpoints, generate_call_id, generate_call_stanza_id, needs_decryption,
};
pub use srtp::{SrtpContext, SrtpError, SrtpSession};
pub use state::{CallInfo, InvalidTransition};
pub use types::*;
