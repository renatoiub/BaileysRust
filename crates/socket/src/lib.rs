//! `baileys-socket` — socket WhatsApp (handshake Noise, WebSocket, eventos).

pub mod app_state;
pub mod cache;
pub mod client;
pub mod groups;
pub mod handshake;
pub mod link_preview;
pub mod media;
pub mod noise;
pub mod reporting;
pub mod usync;

pub use cache::{CacheStore, TtlCache};
pub use client::{
    CallInfo, ChatUpdate, Client, ClientError, ClientEvent, ConnectionUpdate, ContactUpsert,
    DebugRetryParams, GroupParticipantInfo, GroupParticipantsUpdate, GroupUpdate, MediaUpload, MessageKeyExtras,
    MessageReceiptUpdate, MessageReaction, MessageStatusUpdate, MessageUpdateData, MessageUpdateKey,
    MessagingHistorySet, PresenceData, RelayParticipant, SendMessageResult, UserReceipt, WsSink,
};
pub use groups::{extract_group_metadata, GroupMetadata, GroupParticipant};
pub use handshake::{
    configure_successful_pairing, generate_login_node, generate_registration_node, ClientConfig,
    HandshakeError,
};
pub use noise::{client_hello, encode_node, parse_server_hello, Frame, NoiseError, NoiseHandler, WA_CERT_SERIAL};
pub use usync::{usync_query, parse_usync_result, USyncDevice, USyncProtocol, USyncResult, USyncUser};
