//! Group cipher (Sender Key protocol) — port fiel de `Hineken/src/Signal/Group/`.
//!
//! Serialização dos registros: array JSON de estados (`SenderKeyStateStructure[]`),
//! cada estado com `senderKeyId`, `senderChainKey {iteration, seed}`,
//! `senderSigningKey {public, private?}`, `senderMessageKeys []`.
//!
//! A derivação das chaves usa `deriveSecrets(seed, zeros, "WhisperGroup")` e
//! AES-256-CBC (via `encrypt`/`decrypt` do libsignal).

use baileys_crypto::Curve;
use baileys_proto::proto as wa;
use prost::Message;

use crate::error::SignalError;
use crate::Result;

use super::address::ProtocolAddress;
use super::crypto::{calculate_mac, derive_secrets};
use super::SignalStore;

const CURRENT_VERSION: u8 = 3;
const SIGNATURE_LENGTH: usize = 64;
const MAX_MESSAGE_KEYS: usize = 2000;
const MAX_STATES: usize = 5;

/// `SenderKeyName` — `{groupId}::{sender.id}::{sender.deviceId}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SenderKeyName {
    pub group_id: String,
    pub sender: ProtocolAddress,
}

impl SenderKeyName {
    pub fn new(group_id: impl Into<String>, sender: ProtocolAddress) -> Self {
        Self {
            group_id: group_id.into(),
            sender,
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}::{}::{}", self.group_id, self.sender.id, self.sender.device_id)
    }

    pub fn equals(&self, other: &SenderKeyName) -> bool {
        self.group_id == other.group_id && self.sender.to_string() == other.sender.to_string()
    }
}

/// `SenderChainKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderChainKey {
    pub iteration: u32,
    pub seed: Vec<u8>,
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02];

    pub fn get_sender_message_key(&self) -> SenderMessageKey {
        SenderMessageKey::new(self.iteration, calculate_mac(&self.seed, &Self::MESSAGE_KEY_SEED))
    }

    pub fn get_next(&self) -> SenderChainKey {
        SenderChainKey {
            iteration: self.iteration + 1,
            seed: calculate_mac(&self.seed, &Self::CHAIN_KEY_SEED),
        }
    }
}

/// `SenderMessageKey` — deriva `iv` e `cipherKey` de `WhisperGroup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderMessageKey {
    pub iteration: u32,
    pub seed: Vec<u8>,
    pub iv: Vec<u8>,
    pub cipher_key: Vec<u8>,
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: Vec<u8>) -> Self {
        let derivative = derive_secrets(&seed, &[0u8; 32], b"WhisperGroup", 2)
            .unwrap_or_else(|_| vec![vec![0u8; 32], vec![0u8; 32]]);

        let mut keys = vec![0u8; 32];
        keys[..16].copy_from_slice(&derivative[0][16..]);
        keys[16..].copy_from_slice(&derivative[1][..16]);

        SenderMessageKey {
            iteration,
            seed,
            iv: derivative[0][..16].to_vec(),
            cipher_key: keys,
        }
    }
}

/// Estado serializado de uma sender key (formato JSON do Baileys).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyStateStructure {
    #[serde(rename = "senderKeyId")]
    pub sender_key_id: u32,
    #[serde(rename = "senderChainKey")]
    pub sender_chain_key: SenderChainKeyStructure,
    #[serde(rename = "senderSigningKey")]
    pub sender_signing_key: SenderSigningKeyStructure,
    #[serde(rename = "senderMessageKeys")]
    #[serde(default)]
    pub sender_message_keys: Vec<SenderMessageKeyStructure>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderChainKeyStructure {
    pub iteration: u32,
    pub seed: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderSigningKeyStructure {
    pub public: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SenderMessageKeyStructure {
    pub iteration: u32,
    pub seed: Vec<u8>,
}

/// `SenderKeyRecord` — coleção de estados (máx. 5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderKeyRecord {
    states: Vec<SenderKeyStateStructure>,
}

impl SenderKeyRecord {
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn get_sender_key_state(&self, key_id: Option<u32>) -> Option<&SenderKeyStateStructure> {
        match key_id {
            None => self.states.last(),
            Some(id) => self.states.iter().find(|s| s.sender_key_id == id),
        }
    }

    pub fn add_sender_key_state(&mut self, id: u32, iteration: u32, chain_key: Vec<u8>, signature_key: Vec<u8>) {
        self.states.push(SenderKeyStateStructure {
            sender_key_id: id,
            sender_chain_key: SenderChainKeyStructure {
                iteration,
                seed: chain_key,
            },
            sender_signing_key: SenderSigningKeyStructure {
                public: signature_key,
                private: None,
            },
            sender_message_keys: vec![],
        });
        if self.states.len() > MAX_STATES {
            self.states.remove(0);
        }
    }

    pub fn set_sender_key_state(&mut self, id: u32, iteration: u32, chain_key: Vec<u8>, key_pair: (Vec<u8>, Vec<u8>)) {
        self.states.clear();
        self.states.push(SenderKeyStateStructure {
            sender_key_id: id,
            sender_chain_key: SenderChainKeyStructure {
                iteration,
                seed: chain_key,
            },
            sender_signing_key: SenderSigningKeyStructure {
                public: key_pair.0,
                private: Some(key_pair.1),
            },
            sender_message_keys: vec![],
        });
    }

    pub fn serialize(&self) -> Vec<SenderKeyStateStructure> {
        self.states.clone()
    }

    /// Serializa como JSON no formato EXATO do Baileys.
    ///
    /// O Baileys faz `JSON.stringify(key.serialize())` onde os campos de bytes
    /// são `Buffer`/`Uint8Array`. O `Buffer.toJSON()` do Node produz
    /// `{"type":"Buffer","data":[1,2,3,...]}` (array de bytes, NÃO base64).
    pub fn serialize_json(&self) -> String {
        let arr: Vec<serde_json::Value> = self.states.iter().map(state_to_json).collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let s = String::from_utf8(data.to_vec())?;
        let value: serde_json::Value =
            serde_json::from_str(&s).map_err(|_| SignalError::NoSenderKeyRecord("parse".into()))?;
        let arr = value
            .as_array()
            .ok_or_else(|| SignalError::NoSenderKeyRecord("array".into()))?;
        let mut states = Vec::with_capacity(arr.len());
        for item in arr {
            states.push(state_from_json(item)?);
        }
        Ok(Self { states })
    }
}

/// Converte um estado para o JSON do Baileys (`Buffer.toJSON`).
fn state_to_json(state: &SenderKeyStateStructure) -> serde_json::Value {
    serde_json::json!({
        "senderKeyId": state.sender_key_id,
        "senderChainKey": {
            "iteration": state.sender_chain_key.iteration,
            "seed": buffer_to_json(&state.sender_chain_key.seed),
        },
        "senderSigningKey": {
            "public": buffer_to_json(&state.sender_signing_key.public),
            "private": state.sender_signing_key.private.as_ref().map(|p| buffer_to_json(p)),
        },
        "senderMessageKeys": state.sender_message_keys.iter().map(|k| serde_json::json!({
            "iteration": k.iteration,
            "seed": buffer_to_json(&k.seed),
        })).collect::<Vec<_>>(),
    })
}

fn buffer_to_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "type": "Buffer",
        "data": bytes.iter().map(|&b| b as u64).collect::<Vec<_>>(),
    })
}

fn json_to_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    // Aceita {"type":"Buffer","data":[...]} (Buffer.toJSON) ou array direto.
    if let Some(data) = value.get("data").and_then(|d| d.as_array()) {
        return data
            .iter()
            .map(|v| v.as_u64().map(|n| n as u8).ok_or(SignalError::NoSenderKeyRecord("byte".into())))
            .collect();
    }
    if let Some(arr) = value.as_array() {
        return arr
            .iter()
            .map(|v| v.as_u64().map(|n| n as u8).ok_or(SignalError::NoSenderKeyRecord("byte".into())))
            .collect();
    }
    Ok(vec![])
}

fn state_from_json(value: &serde_json::Value) -> Result<SenderKeyStateStructure> {
    let get = |k: &str| value.get(k);
    let sender_key_id = get("senderKeyId")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let chain = get("senderChainKey").ok_or_else(|| SignalError::NoSenderKeyRecord("chain".into()))?;
    let iteration = chain.get("iteration").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let seed = json_to_bytes(chain.get("seed").unwrap_or(&serde_json::Value::Null))?;

    let signing = get("senderSigningKey").ok_or_else(|| SignalError::NoSenderKeyRecord("signing".into()))?;
    let public = json_to_bytes(signing.get("public").unwrap_or(&serde_json::Value::Null))?;
    let private = signing.get("private").and_then(|p| json_to_bytes(p).ok());

    let message_keys = get("senderMessageKeys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|k| SenderMessageKeyStructure {
                    iteration: k.get("iteration").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    seed: json_to_bytes(k.get("seed").unwrap_or(&serde_json::Value::Null)).unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(SenderKeyStateStructure {
        sender_key_id,
        sender_chain_key: SenderChainKeyStructure { iteration, seed },
        sender_signing_key: SenderSigningKeyStructure { public, private },
        sender_message_keys: message_keys,
    })
}

/// `SenderKeyDistributionMessage`.
pub struct SenderKeyDistributionMessage {
    pub id: u32,
    pub iteration: u32,
    pub chain_key: Vec<u8>,
    pub signature_key: Vec<u8>,
    serialized: Vec<u8>,
}

impl SenderKeyDistributionMessage {
    fn ints_to_byte_high_and_low(high: u8, low: u8) -> u8 {
        (((high as u16) << 4) | low as u16) as u8
    }

    pub fn new(id: u32, iteration: u32, chain_key: Vec<u8>, signature_key: Vec<u8>) -> Self {
        let version = Self::ints_to_byte_high_and_low(CURRENT_VERSION, CURRENT_VERSION);
        let message = wa::SenderKeyDistributionMessage {
            id: Some(id),
            iteration: Some(iteration),
            chain_key: Some(chain_key.clone()),
            signing_key: Some(signature_key.clone()),
        }
        .encode_to_vec();

        let mut serialized = Vec::with_capacity(1 + message.len());
        serialized.push(version);
        serialized.extend_from_slice(&message);

        Self {
            id,
            iteration,
            chain_key,
            signature_key,
            serialized,
        }
    }

    pub fn from_serialized(serialized: Vec<u8>) -> Result<Self> {
        let message = wa::SenderKeyDistributionMessage::decode(&serialized[1..])?;
        Ok(Self {
            id: message.id.unwrap_or(0),
            iteration: message.iteration.unwrap_or(0),
            chain_key: message.chain_key.unwrap_or_default(),
            signature_key: message.signing_key.unwrap_or_default(),
            serialized,
        })
    }

    pub fn serialize(&self) -> &[u8] {
        &self.serialized
    }
}

/// `SenderKeyMessage`.
pub struct SenderKeyMessage {
    key_id: u32,
    iteration: u32,
    ciphertext: Vec<u8>,
    serialized: Vec<u8>,
}

impl SenderKeyMessage {
    fn get_signature(signature_key: &[u8], serialized: &[u8]) -> Vec<u8> {
        Curve::sign(signature_key, serialized).unwrap_or_default()
    }

    pub fn new(key_id: u32, iteration: u32, ciphertext: Vec<u8>, signature_key: &[u8]) -> Self {
        let version = SenderKeyDistributionMessage::ints_to_byte_high_and_low(CURRENT_VERSION, CURRENT_VERSION);
        let message = wa::SenderKeyMessage {
            id: Some(key_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.clone()),
        }
        .encode_to_vec();

        let mut prefix = Vec::with_capacity(1 + message.len());
        prefix.push(version);
        prefix.extend_from_slice(&message);
        let signature = Self::get_signature(signature_key, &prefix);

        let mut serialized = prefix;
        serialized.extend_from_slice(&signature);

        Self {
            key_id,
            iteration,
            ciphertext,
            serialized,
        }
    }

    pub fn from_serialized(serialized: Vec<u8>) -> Result<Self> {
        let _version = serialized[0];
        let message = &serialized[1..serialized.len() - SIGNATURE_LENGTH];
        let sender_key_message = wa::SenderKeyMessage::decode(message)?;
        Ok(Self {
            key_id: sender_key_message.id.unwrap_or(0),
            iteration: sender_key_message.iteration.unwrap_or(0),
            ciphertext: sender_key_message.ciphertext.unwrap_or_default(),
            serialized,
        })
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn verify_signature(&self, signature_key: &[u8]) -> Result<()> {
        let part1 = &self.serialized[..self.serialized.len() - SIGNATURE_LENGTH];
        let part2 = &self.serialized[self.serialized.len() - SIGNATURE_LENGTH..];
        if !Curve::verify(signature_key, part1, part2) {
            return Err(SignalError::InvalidSignature);
        }
        Ok(())
    }

    pub fn serialize(&self) -> &[u8] {
        &self.serialized
    }
}

/// `GroupCipher`.
pub struct GroupCipher<'a> {
    store: &'a dyn SignalStore,
    name: SenderKeyName,
}

impl<'a> GroupCipher<'a> {
    pub fn new(store: &'a dyn SignalStore, name: SenderKeyName) -> Self {
        Self { store, name }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut record = self.store.load_sender_key(&self.name)?;
        if record.is_empty() {
            return Err(SignalError::NoSenderKeyRecord(self.name.to_string()));
        }

        let state_index = record.states.len() - 1;
        let (key_id, sender_key, signing_priv) = {
            let (sender_key, new_state) = {
                let state = &record.states[state_index];
                let sender_chain = SenderChainKey {
                    iteration: state.sender_chain_key.iteration,
                    seed: state.sender_chain_key.seed.clone(),
                };
                let iteration = if sender_chain.iteration == 0 {
                    0
                } else {
                    sender_chain.iteration + 1
                };
                // getSenderKey mutates the state (advances chain + caches skipped keys).
                get_sender_key(state, iteration)?
            };
            record.states[state_index] = new_state;
            let state = &record.states[state_index];
            (
                state.sender_key_id,
                sender_key,
                state.sender_signing_key.private.clone(),
            )
        };
        let signing_priv = signing_priv.ok_or(SignalError::NoSenderKeyState)?;

        let ciphertext = super::crypto::encrypt(&sender_key.cipher_key, plaintext, &sender_key.iv)?;
        let message = SenderKeyMessage::new(key_id, sender_key.iteration, ciphertext, &signing_priv);

        self.store.store_sender_key(&self.name, &record)?;
        Ok(message.serialize().to_vec())
    }

    pub fn decrypt(&self, message_bytes: &[u8]) -> Result<Vec<u8>> {
        let mut record = self.store.load_sender_key(&self.name)?;
        if record.is_empty() {
            return Err(SignalError::NoSenderKeyRecord(self.name.to_string()));
        }

        let message = SenderKeyMessage::from_serialized(message_bytes.to_vec())?;
        let state_index = record
            .states
            .iter()
            .position(|s| s.sender_key_id == message.key_id())
            .ok_or(SignalError::NoSenderKeyState)?;
        {
            let state = &record.states[state_index];
            message.verify_signature(&state.sender_signing_key.public)?;
        }

        let (sender_key, new_state) = {
            let state = &record.states[state_index];
            get_sender_key(state, message.iteration())?
        };
        record.states[state_index] = new_state;

        let plaintext = super::crypto::decrypt(&sender_key.cipher_key, message.ciphertext(), &sender_key.iv)?;

        self.store.store_sender_key(&self.name, &record)?;
        Ok(plaintext)
    }
}

/// `getSenderKey` — deriva a message key e retorna o estado MUTADO
/// (chain key avançada + message keys cacheadas), espelhando `getSenderKey` do JS.
fn get_sender_key(
    state: &SenderKeyStateStructure,
    iteration: u32,
) -> Result<(SenderMessageKey, SenderKeyStateStructure)> {
    let mut new_state = state.clone();
    let mut sender_chain = SenderChainKey {
        iteration: state.sender_chain_key.iteration,
        seed: state.sender_chain_key.seed.clone(),
    };

    if sender_chain.iteration > iteration {
        if let Some((idx, mk)) = state
            .sender_message_keys
            .iter()
            .enumerate()
            .find(|(_, k)| k.iteration == iteration)
        {
            new_state.sender_message_keys.remove(idx);
            return Ok((SenderMessageKey::new(mk.iteration, mk.seed.clone()), new_state));
        }
        return Err(SignalError::OldCounter {
            chain: sender_chain.iteration,
            iteration,
        });
    }

    if iteration - sender_chain.iteration > 2000 {
        return Err(SignalError::TooFarIntoFuture);
    }

    while sender_chain.iteration < iteration {
        new_state
            .sender_message_keys
            .push(SenderMessageKeyStructure {
                iteration: sender_chain.iteration,
                seed: sender_chain.get_sender_message_key().seed.clone(),
            });
        sender_chain = sender_chain.get_next();
    }

    // setSenderChainKey(next)
    let next = sender_chain.get_next();
    new_state.sender_chain_key = SenderChainKeyStructure {
        iteration: next.iteration,
        seed: next.seed.clone(),
    };
    if new_state.sender_message_keys.len() > MAX_MESSAGE_KEYS {
        new_state.sender_message_keys.remove(0);
    }

    Ok((sender_chain.get_sender_message_key(), new_state))
}

/// `GroupSessionBuilder`.
pub struct GroupSessionBuilder<'a> {
    store: &'a dyn SignalStore,
}

impl<'a> GroupSessionBuilder<'a> {
    pub fn new(store: &'a dyn SignalStore) -> Self {
        Self { store }
    }

    pub fn process(
        &self,
        name: &SenderKeyName,
        distribution: &SenderKeyDistributionMessage,
    ) -> Result<()> {
        let mut record = self.store.load_sender_key(name)?;
        record.add_sender_key_state(
            distribution.id,
            distribution.iteration,
            distribution.chain_key.clone(),
            distribution.signature_key.clone(),
        );
        self.store.store_sender_key(name, &record)
    }

    pub fn create(&self, name: &SenderKeyName) -> Result<SenderKeyDistributionMessage> {
        let mut record = self.store.load_sender_key(name)?;

        if record.is_empty() {
            let key_id = generate_sender_key_id();
            let sender_key = generate_sender_key();
            let signing_key = generate_sender_signing_key();
            record.set_sender_key_state(key_id, 0, sender_key, signing_key);
            self.store.store_sender_key(name, &record)?;
        }

        let state = record
            .get_sender_key_state(None)
            .ok_or(SignalError::NoSenderKeyState)?;
        Ok(SenderKeyDistributionMessage::new(
            state.sender_key_id,
            state.sender_chain_key.iteration,
            state.sender_chain_key.seed.clone(),
            state.sender_signing_key.public.clone(),
        ))
    }
}

/// `generateSenderKey`
pub fn generate_sender_key() -> Vec<u8> {
    let mut out = vec![0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// `generateSenderKeyId` — `randomInt(2147483647)`.
pub fn generate_sender_key_id() -> u32 {
    use rand::Rng;
    rand::rngs::OsRng.gen_range(0..2147483647)
}

/// `generateSenderSigningKey`
pub fn generate_sender_signing_key() -> (Vec<u8>, Vec<u8>) {
    let kp = Curve::generate_signal_key_pair();
    (kp.public, kp.private)
}
