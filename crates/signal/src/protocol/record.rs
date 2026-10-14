//! Session records — espelho byte a byte de `session_record.js`.
//!
//! A serialização usa **base64** para todas as chaves/bytes e o formato:
//!
//! ```json
//! {
//!   "_sessions": {
//!     "<baseKey b64>": {
//!       "registrationId": 123,
//!       "currentRatchet": {
//!         "ephemeralKeyPair": { "pubKey": "<b64>", "privKey": "<b64>" },
//!         "lastRemoteEphemeralKey": "<b64>",
//!         "previousCounter": 0,
//!         "rootKey": "<b64>"
//!       },
//!       "indexInfo": {
//!         "baseKey": "<b64>", "baseKeyType": 1, "closed": -1,
//!         "used": 123, "created": 123, "remoteIdentityKey": "<b64>"
//!       },
//!       "_chains": { "<pubKey b64>": { "chainKey": { "counter": -1, "key": "<b64>" }, "chainType": 1, "messageKeys": { "0": "<b64>" } } },
//!       "pendingPreKey": { "signedKeyId": 1, "baseKey": "<b64>", "preKeyId": 2 }
//!     }
//!   },
//!   "version": "v1"
//! }
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::SignalError;
use crate::Result;

use super::chain::{BaseKeyType, ChainType};

pub const CLOSED_SESSIONS_MAX: usize = 40;
pub const SESSION_RECORD_VERSION: &str = "v1";

/// `ChainKey` — contador + chave (base64 na serialização).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainKey {
    pub counter: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl ChainKey {
    pub fn new(counter: i32, key: Vec<u8>) -> Self {
        Self {
            counter,
            key: Some(encode_b64(&key)),
        }
    }

    /// Retorna a chave como bytes (None se fechada).
    pub fn key_bytes(&self) -> Option<Vec<u8>> {
        self.key.as_deref().map(decode_b64)
    }
}

/// Uma `Chain` (envio ou recepção).
///
/// Aceita também as chaves em snake_case (`chain_key`/`chain_type`/
/// `message_keys`) que uma versão antiga do `record.rs` gravou no SQLite/Redis
/// antes do `rename_all = "camelCase"`. A serialização continua sempre em
/// camelCase (formato do Node).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chain {
    #[serde(alias = "chain_key")]
    pub chain_key: ChainKey,
    #[serde(alias = "chain_type")]
    pub chain_type: u32,
    #[serde(default, alias = "message_keys")]
    pub message_keys: HashMap<String, String>,
}

impl Chain {
    pub fn new_sending(counter: i32, key: Vec<u8>) -> Self {
        Self {
            chain_key: ChainKey::new(counter, key),
            chain_type: ChainType::Sending as u32,
            message_keys: HashMap::new(),
        }
    }

    pub fn new_receiving(counter: i32, key: Vec<u8>) -> Self {
        Self {
            chain_key: ChainKey::new(counter, key),
            chain_type: ChainType::Receiving as u32,
            message_keys: HashMap::new(),
        }
    }

    pub fn chain_type(&self) -> Option<ChainType> {
        ChainType::from_u32(self.chain_type)
    }
}

/// `PendingPreKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PendingPreKey {
    #[serde(alias = "signed_key_id")]
    pub signed_key_id: u32,
    #[serde(alias = "base_key")]
    pub base_key: String,
    #[serde(skip_serializing_if = "Option::is_none", alias = "pre_key_id")]
    pub pre_key_id: Option<u32>,
}

/// `Ratchet` (currentRatchet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ratchet {
    #[serde(alias = "ephemeral_key_pair")]
    pub ephemeral_key_pair: SerializedKeyPair,
    #[serde(alias = "last_remote_ephemeral_key")]
    pub last_remote_ephemeral_key: String,
    #[serde(alias = "previous_counter")]
    pub previous_counter: u32,
    #[serde(alias = "root_key")]
    pub root_key: String,
}

/// `KeyPair` serializado em base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedKeyPair {
    #[serde(rename = "pubKey")]
    pub pub_key: String,
    #[serde(rename = "privKey")]
    pub priv_key: String,
}

/// `IndexInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexInfo {
    #[serde(alias = "base_key")]
    pub base_key: String,
    #[serde(alias = "base_key_type")]
    pub base_key_type: u32,
    #[serde(alias = "closed")]
    pub closed: i64,
    #[serde(alias = "used")]
    pub used: i64,
    #[serde(alias = "created")]
    pub created: i64,
    #[serde(alias = "remote_identity_key")]
    pub remote_identity_key: String,
}

/// `SessionEntry` — uma sessão dentro do registro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEntry {
    #[serde(alias = "registration_id")]
    pub registration_id: u32,
    #[serde(alias = "current_ratchet")]
    pub current_ratchet: Ratchet,
    #[serde(alias = "index_info")]
    pub index_info: IndexInfo,
    #[serde(rename = "_chains")]
    pub chains: HashMap<String, Chain>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "pending_pre_key")]
    pub pending_pre_key: Option<PendingPreKey>,
}

impl SessionEntry {
    /// `addChain`
    pub fn add_chain(&mut self, key: &[u8], value: Chain) -> Result<()> {
        let id = encode_b64(key);
        if self.chains.contains_key(&id) {
            return Err(SignalError::OverwriteChain);
        }
        self.chains.insert(id, value);
        Ok(())
    }

    /// `getChain`
    pub fn get_chain(&self, key: &[u8]) -> Option<&Chain> {
        self.chains.get(&encode_b64(key))
    }

    pub fn get_chain_mut(&mut self, key: &[u8]) -> Option<&mut Chain> {
        self.chains.get_mut(&encode_b64(key))
    }

    /// `deleteChain`
    pub fn delete_chain(&mut self, key: &[u8]) -> Result<()> {
        let id = encode_b64(key);
        if !self.chains.contains_key(&id) {
            return Err(SignalError::ChainNotFound);
        }
        self.chains.remove(&id);
        Ok(())
    }
}

/// `SessionRecord` — coleção de sessões.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    #[serde(rename = "_sessions")]
    pub sessions: HashMap<String, SessionEntry>,
    pub version: String,
}

impl Default for SessionRecord {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            version: SESSION_RECORD_VERSION.to_string(),
        }
    }
}

impl SessionRecord {
    /// `haveOpenSession`
    pub fn have_open_session(&self) -> bool {
        self.get_open_session().is_some()
    }

    /// `getSession(key)` — falha se a sessão tiver `baseKeyType == OURS`.
    pub fn get_session(&self, key: &[u8]) -> Result<Option<&SessionEntry>> {
        let session = self.sessions.get(&encode_b64(key));
        match session {
            Some(s) if s.index_info.base_key_type == BaseKeyType::Ours as u32 => {
                Err(SignalError::NoOpenSession)
            }
            other => Ok(other),
        }
    }

    pub fn get_session_mut(&mut self, key: &[u8]) -> Result<Option<&mut SessionEntry>> {
        let id = encode_b64(key);
        let base_key_type = self.sessions.get(&id).map(|s| s.index_info.base_key_type);
        match base_key_type {
            Some(bt) if bt == BaseKeyType::Ours as u32 => Err(SignalError::NoOpenSession),
            _ => Ok(self.sessions.get_mut(&id)),
        }
    }

    /// `getOpenSession`
    pub fn get_open_session(&self) -> Option<&SessionEntry> {
        self.sessions.values().find(|s| !self.is_closed(s))
    }

    /// `setSession`
    pub fn set_session(&mut self, session: SessionEntry) {
        let base = session.index_info.base_key.clone();
        self.sessions.insert(base, session);
    }

    /// `getSessions` — most recently used first.
    pub fn get_sessions(&self) -> Vec<&SessionEntry> {
        let mut v: Vec<&SessionEntry> = self.sessions.values().collect();
        v.sort_by(|a, b| {
            let au = a.index_info.used;
            let bu = b.index_info.used;
            bu.cmp(&au)
        });
        v
    }

    /// `closeSession`
    pub fn close_session(&mut self, session: &SessionEntry) {
        let id = session.index_info.base_key.clone();
        if let Some(s) = self.sessions.get_mut(&id) {
            if s.index_info.closed != -1 {
                return;
            }
            s.index_info.closed = now_ms();
        }
    }

    /// `openSession`
    pub fn open_session(&mut self, session: &SessionEntry) {
        let id = session.index_info.base_key.clone();
        if let Some(s) = self.sessions.get_mut(&id) {
            s.index_info.closed = -1;
        }
    }

    pub fn is_closed(&self, session: &SessionEntry) -> bool {
        session.index_info.closed != -1
    }

    /// `removeOldSessions`
    pub fn remove_old_sessions(&mut self) {
        while self.sessions.len() > CLOSED_SESSIONS_MAX {
            let mut oldest: Option<(String, i64)> = None;
            for (key, session) in self.sessions.iter() {
                if session.index_info.closed != -1 {
                    match oldest {
                        None => oldest = Some((key.clone(), session.index_info.closed)),
                        Some((_, c)) if session.index_info.closed < c => {
                            oldest = Some((key.clone(), session.index_info.closed))
                        }
                        _ => {}
                    }
                }
            }
            if let Some((key, _)) = oldest {
                self.sessions.remove(&key);
            } else {
                return;
            }
        }
    }

    pub fn delete_all_sessions(&mut self) {
        self.sessions.clear();
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn encode_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn decode_b64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}
