//! `baileys-call` — chamadas de voz/vídeo do WhatsApp.
//!
//! Port de `container/src/services/call/*`: signaling, RTP/SRTP, STUN,
//! libopus_mlow via FFI (decode isolado em processo filho) e relays
//! WebRTC/SCTP.

pub mod audio;
pub mod call_manager;
pub mod encryption;
pub mod mlow;
pub mod mlow_isolated;
pub mod player;
pub mod rtp;
pub mod sctp_relay;
pub mod signaling;
pub mod srtp;
pub mod state;
pub mod stun;
pub mod types;
pub mod udp_relay;

pub use call_manager::{
    is_call_recently_ended, mark_call_ended, note_terminate_webhook_sent,
    was_terminate_webhook_sent, CallError, CallEvent, CallSocket, NativeCallManager,
};
pub use encryption::{derive_per_jid_srtp_key, generate_call_key};
pub use mlow_isolated::run_decode_worker_if_requested;
pub use rtp::{RtpHeader, RtpPacket, RtpSession};
pub use signaling::{
    build_accept_stanza, build_accepted_elsewhere_stanza, build_offer_stanza,
    build_post_accept_transport_stanza, build_preaccept_stanza, build_reject_stanza,
    build_relay_latency_stanza, build_terminate_stanza, build_terminate_to_device_stanza,
    build_transport_stanza, create_call_ack, decrypt_call_key_in_node, ensure_device_jid,
    extract_node_info, extract_relay_endpoints, generate_call_id, generate_call_stanza_id,
    needs_decryption, parse_relay_from_ack,
};
pub use srtp::{SrtpContext, SrtpError, SrtpSession};
pub use state::{CallInfo, InvalidTransition};
pub use types::*;
