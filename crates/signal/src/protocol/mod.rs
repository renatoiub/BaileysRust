//! Primitive data structures and ciphers of the Signal protocol.
//!
//! This module is a byte-for-byte port of `libsignal-node` + `WASignalGroup`
//! (see `Hineken/src/Signal/`). The storage layer is abstracted behind
//! [`SignalStore`] so both the socket crate and tests can supply their own
//! persistence (SQLite/Redis or in-memory).

pub mod address;
pub mod chain;
pub mod crypto;
pub mod group;
pub mod prekey;
pub mod record;
pub mod session;
pub mod whisper;

pub use address::ProtocolAddress;
pub use chain::{BaseKeyType, ChainType};
pub use crypto::derive_secrets;
pub use prekey::{SignedPreKeyRecord, PreKeyRecord};
pub use record::{Chain, ChainKey, SessionEntry, SessionRecord};
pub use session::{SessionBuilder, SessionCipher};
pub use group::{GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage, SenderKeyName, SenderKeyRecord};

use std::collections::HashMap;

use crate::Result;

/// Abstraction over Signal storage (mirrors the `SignalKeyStore` bits that
/// the cipher needs, plus `SenderKeyStore`).
pub trait SignalStore: Send + Sync {
    /// Load a session record by address string.
    fn load_session(&self, id: &str) -> Result<Option<SessionRecord>>;
    /// Persist a session record.
    fn store_session(&self, id: &str, session: &SessionRecord) -> Result<()>;
    /// Always trusted in Baileys (identity trust handled by the app layer).
    fn is_trusted_identity(&self, _id: &str, _identity_key: &[u8]) -> bool {
        true
    }
    /// Load a pre-key by id (returns `(public, private)`).
    fn load_pre_key(&self, id: u32) -> Result<Option<(Vec<u8>, Vec<u8>)>>;
    /// Remove a pre-key after use.
    fn remove_pre_key(&self, id: u32) -> Result<()>;
    /// Load the signed pre-key (returns `(public, private)`).
    fn load_signed_pre_key(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Our identity key (returns `(public_with_05_prefix, private)`).
    fn get_our_identity(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Our registration id.
    fn get_our_registration_id(&self) -> Result<u32>;

    // Sender key store
    fn load_sender_key(&self, name: &SenderKeyName) -> Result<SenderKeyRecord>;
    fn store_sender_key(&self, name: &SenderKeyName, record: &SenderKeyRecord) -> Result<()>;
}

/// In-memory signal store (used in tests).
pub struct MemoryStore {
    sessions: std::sync::Mutex<HashMap<String, SessionRecord>>,
    pre_keys: std::sync::Mutex<HashMap<u32, (Vec<u8>, Vec<u8>)>>,
    sender_keys: std::sync::Mutex<HashMap<String, SenderKeyRecord>>,
    identity: (Vec<u8>, Vec<u8>),
    signed_pre_key: (Vec<u8>, Vec<u8>),
    registration_id: u32,
}

impl MemoryStore {
    pub fn new(
        identity: (Vec<u8>, Vec<u8>),
        signed_pre_key: (Vec<u8>, Vec<u8>),
        registration_id: u32,
    ) -> Self {
        Self {
            sessions: Default::default(),
            pre_keys: Default::default(),
            sender_keys: Default::default(),
            identity,
            signed_pre_key,
            registration_id,
        }
    }

    pub fn insert_pre_key(&self, id: u32, pair: (Vec<u8>, Vec<u8>)) {
        self.pre_keys.lock().unwrap().insert(id, pair);
    }
}

impl SignalStore for MemoryStore {
    fn load_session(&self, id: &str) -> Result<Option<SessionRecord>> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }
    fn store_session(&self, id: &str, session: &SessionRecord) -> Result<()> {
        self.sessions.lock().unwrap().insert(id.to_string(), session.clone());
        Ok(())
    }
    fn load_pre_key(&self, id: u32) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self.pre_keys.lock().unwrap().get(&id).cloned())
    }
    fn remove_pre_key(&self, id: u32) -> Result<()> {
        self.pre_keys.lock().unwrap().remove(&id);
        Ok(())
    }
    fn load_signed_pre_key(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok(self.signed_pre_key.clone())
    }
    fn get_our_identity(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok(self.identity.clone())
    }
    fn get_our_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }
    fn load_sender_key(&self, name: &SenderKeyName) -> Result<SenderKeyRecord> {
        Ok(self
            .sender_keys
            .lock()
            .unwrap()
            .get(&name.to_string())
            .cloned()
            .unwrap_or_default())
    }
    fn store_sender_key(&self, name: &SenderKeyName, record: &SenderKeyRecord) -> Result<()> {
        self.sender_keys.lock().unwrap().insert(name.to_string(), record.clone());
        Ok(())
    }
}
