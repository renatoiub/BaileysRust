//! `WhisperMessage` / `PreKeyWhisperMessage` — protos `textsecure` do libsignal.
//!
//! Campos (números idênticos aos do `WhisperTextProtocol.js`):
//!
//! ```proto
//! message WhisperMessage {
//!     bytes  ephemeralKey    = 1;
//!     uint32 counter         = 2;
//!     uint32 previousCounter = 3;
//!     bytes  ciphertext      = 4;
//! }
//! message PreKeyWhisperMessage {
//!     uint32 registrationId = 5;
//!     uint32 preKeyId       = 1;
//!     uint32 signedPreKeyId = 6;
//!     bytes  baseKey        = 2;
//!     bytes  identityKey    = 3;
//!     bytes  message        = 4;
//! }
//! ```

/// Mensagem de ratchet.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WhisperMessage {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ephemeral_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    pub counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub previous_counter: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub ciphertext: Option<Vec<u8>>,
}

/// Mensagem pre-key.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PreKeyWhisperMessage {
    #[prost(uint32, optional, tag = "5")]
    pub registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "1")]
    pub pre_key_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub signed_pre_key_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub base_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub identity_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub message: Option<Vec<u8>>,
}
