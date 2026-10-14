//! Erros do protocolo Signal.

use std::string::FromUtf8Error;

#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("crypto: {0}")]
    Crypto(#[from] baileys_crypto::error::CryptoError),
    #[error("prost decode: {0}")]
    ProstDecode(#[from] prost::DecodeError),
    #[error("prost encode: {0}")]
    ProstEncode(#[from] prost::EncodeError),
    #[error("invalid address encoding")]
    InvalidAddress,
    #[error("id required for address")]
    MissingAddressId,
    #[error("deviceId required for address")]
    MissingDeviceId,
    #[error("no session record")]
    NoSessionRecord,
    #[error("no sessions")]
    NoSessions,
    #[error("no open session")]
    NoOpenSession,
    #[error("no matching sessions found for message")]
    NoMatchingSessions,
    #[error("tried to encrypt on a receiving chain")]
    EncryptOnReceivingChain,
    #[error("tried to decrypt on a sending chain")]
    DecryptOnSendingChain,
    #[error("chain closed")]
    ChainClosed,
    #[error("over 2000 messages into the future")]
    TooFarIntoFuture,
    #[error("key used already or never filled")]
    MessageCounterError,
    #[error("bad MAC")]
    BadMac,
    #[error("incompatible version number")]
    IncompatibleVersion,
    #[error("no registrationId")]
    MissingRegistrationId,
    #[error("invalid pre-key ID")]
    InvalidPreKeyId,
    #[error("missing signed pre-key")]
    MissingSignedPreKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("untrusted identity key")]
    UntrustedIdentityKey,
    #[error("no SenderKeyRecord found for {0}")]
    NoSenderKeyRecord(String),
    #[error("no session to encrypt/decrypt message")]
    NoSenderKeyState,
    #[error("received message with old counter: {chain}, {iteration}")]
    OldCounter { chain: u32, iteration: u32 },
    #[error("no sender message key found for iteration")]
    MissingSenderMessageKey,
    #[error("corrupt sessions object")]
    CorruptSessions,
    #[error("overwrite attempt")]
    OverwriteChain,
    #[error("chain not found")]
    ChainNotFound,
    #[error("utf8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("group id required for sender key distribution")]
    MissingGroupId,
    #[error("unknown message type: {0}")]
    UnknownMessageType(String),
    #[error("store: {0}")]
    Store(String),
}
