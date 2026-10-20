//! App-state (syncd) — port de `Utils/chat-utils.ts` (decode de patches e
//! snapshots) e `Utils/lt-hash.ts` do Hineken.
//!
//! A decodificação é síncrona (as chaves vêm do store); o download dos blobs
//! externos (`md-app-state`) e a query `w:sync:app:state` ficam no client.

use std::collections::HashMap;

use base64::Engine;
use baileys_core::BinaryNode;
use baileys_proto::proto as wa;
use baileys_store::creds::BufferValue;
use prost::Message;

/// `ALL_WA_PATCH_NAMES`.
pub const ALL_WA_PATCH_NAMES: [&str; 5] = [
    "critical_block",
    "critical_unblock_low",
    "regular_high",
    "regular_low",
    "regular",
];

/// `MAX_SYNC_ATTEMPTS` do `resyncAppState`.
pub const MAX_SYNC_ATTEMPTS: u32 = 2;

/// `appStateMacVerification` default do Hineken (`{ patch: false, snapshot: false }`).
pub const VALIDATE_SNAPSHOT_MACS: bool = false;
pub const VALIDATE_PATCH_SNAPSHOT_MACS: bool = false;

const LT_HASH_SALT: &str = "WhatsApp Patch Integrity";
const HASH_LEN: usize = 128;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn to_buffer(bytes: &[u8]) -> BufferValue {
    BufferValue::Buffer { type_: "Buffer".to_string(), data: b64(bytes) }
}

fn from_buffer(value: &BufferValue) -> Vec<u8> {
    match value {
        BufferValue::Buffer { data, .. } | BufferValue::Raw(data) => {
            base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default()
        }
    }
}

/// Erros do app-state. `KeyNotFound` é o 404 do Node (irrecuperável).
#[derive(Debug, Clone)]
pub enum AppStateError {
    KeyNotFound(String),
    Invalid(String),
}

impl std::fmt::Display for AppStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppStateError::KeyNotFound(k) => write!(f, "failed to find key \"{k}\" to decode mutation"),
            AppStateError::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl AppStateError {
    pub fn is_key_not_found(&self) -> bool {
        matches!(self, AppStateError::KeyNotFound(_))
    }
}

fn invalid(e: impl std::fmt::Display) -> AppStateError {
    AppStateError::Invalid(e.to_string())
}

/// `{ valueMac }` do `indexValueMap`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexValue {
    pub value_mac: BufferValue,
}

/// `LTHashState` (gravado em `app-state-sync-version` no formato BufferJSON).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LtHashState {
    pub version: u64,
    pub hash: BufferValue,
    #[serde(default)]
    pub index_value_map: HashMap<String, IndexValue>,
}

impl LtHashState {
    /// `newLTHashState`.
    pub fn new() -> Self {
        Self { version: 0, hash: to_buffer(&[0u8; HASH_LEN]), index_value_map: HashMap::new() }
    }

    fn hash_bytes(&self) -> Vec<u8> {
        let mut hash = from_buffer(&self.hash);
        hash.resize(HASH_LEN, 0);
        hash
    }
}

impl Default for LtHashState {
    fn default() -> Self {
        Self::new()
    }
}

/// `ChatMutation` — ação decodificada + `index` (JSON array).
#[derive(Debug, Clone)]
pub struct ChatMutation {
    pub sync_action: wa::SyncActionData,
    pub index: Vec<String>,
}

/// `ChatMutationMap` (objeto JS: ordem de inserção, chave repetida sobrescreve).
#[derive(Debug, Default)]
pub struct MutationMap {
    order: Vec<ChatMutation>,
    positions: HashMap<String, usize>,
}

impl MutationMap {
    fn insert(&mut self, key: String, mutation: ChatMutation) {
        match self.positions.get(&key) {
            Some(&pos) => self.order[pos] = mutation,
            None => {
                self.positions.insert(key, self.order.len());
                self.order.push(mutation);
            }
        }
    }

    /// `Object.assign(globalMutationMap, other)`.
    pub fn extend(&mut self, other: MutationMap) {
        let mut entries: Vec<(String, usize)> = other.positions.into_iter().collect();
        entries.sort_by_key(|(_, pos)| *pos);
        let mut order: Vec<Option<ChatMutation>> = other.order.into_iter().map(Some).collect();
        for (key, pos) in entries {
            if let Some(mutation) = order[pos].take() {
                self.insert(key, mutation);
            }
        }
    }

    pub fn into_mutations(self) -> Vec<ChatMutation> {
        self.order
    }
}

/// Chave da `ChatMutationMap` (`syncAction.index?.toString()`).
fn mutation_key(mutation: &ChatMutation) -> String {
    String::from_utf8_lossy(mutation.sync_action.index.as_deref().unwrap_or_default()).into_owned()
}

/// `mutationKeys` — HKDF 160 bytes "WhatsApp Mutation Keys".
pub struct MutationKeys {
    pub index_key: Vec<u8>,
    pub value_encryption_key: Vec<u8>,
    pub value_mac_key: Vec<u8>,
    pub snapshot_mac_key: Vec<u8>,
    pub patch_mac_key: Vec<u8>,
}

pub fn mutation_keys(key_data: &[u8]) -> Result<MutationKeys, AppStateError> {
    let expanded = baileys_crypto::hkdf(key_data, 160, None, "WhatsApp Mutation Keys").map_err(invalid)?;
    Ok(MutationKeys {
        index_key: expanded[0..32].to_vec(),
        value_encryption_key: expanded[32..64].to_vec(),
        value_mac_key: expanded[64..96].to_vec(),
        snapshot_mac_key: expanded[96..128].to_vec(),
        patch_mac_key: expanded[128..160].to_vec(),
    })
}

/// `generateMac` — HMAC-SHA512(op || keyId || data || len8)[0..32].
fn generate_mac(operation: i32, data: &[u8], key_id: &[u8], key: &[u8]) -> Vec<u8> {
    let op_byte = if operation == wa::syncd_mutation::SyncdOperation::Remove as i32 { 0x02 } else { 0x01 };
    let mut key_data = vec![op_byte];
    key_data.extend_from_slice(key_id);
    let mut last = [0u8; 8];
    last[7] = key_data.len() as u8;
    let mut total = key_data;
    total.extend_from_slice(data);
    total.extend_from_slice(&last);
    let mut mac = baileys_crypto::hmac_sign(&total, key, baileys_crypto::HmacVariant::Sha512);
    mac.truncate(32);
    mac
}

/// `to64BitNetworkOrder`.
fn to_64bit_network_order(e: u64) -> [u8; 8] {
    let mut buff = [0u8; 8];
    buff[4..8].copy_from_slice(&(e as u32).to_be_bytes());
    buff
}

/// `generateSnapshotMac`.
fn generate_snapshot_mac(lt_hash: &[u8], version: u64, name: &str, key: &[u8]) -> Vec<u8> {
    let mut total = lt_hash.to_vec();
    total.extend_from_slice(&to_64bit_network_order(version));
    total.extend_from_slice(name.as_bytes());
    baileys_crypto::hmac_sign(&total, key, baileys_crypto::HmacVariant::Sha256)
}

/// `generatePatchMac`.
fn generate_patch_mac(snapshot_mac: &[u8], value_macs: &[Vec<u8>], version: u64, name: &str, key: &[u8]) -> Vec<u8> {
    let mut total = snapshot_mac.to_vec();
    for mac in value_macs {
        total.extend_from_slice(mac);
    }
    total.extend_from_slice(&to_64bit_network_order(version));
    total.extend_from_slice(name.as_bytes());
    baileys_crypto::hmac_sign(&total, key, baileys_crypto::HmacVariant::Sha256)
}

/// `LT_HASH_ANTI_TAMPERING.subtractThenAdd` (soma pointwise de u16 LE com overflow).
fn lt_hash_subtract_then_add(hash: &[u8], add: &[Vec<u8>], sub: &[Vec<u8>]) -> Result<Vec<u8>, AppStateError> {
    let mut out = hash.to_vec();
    out.resize(HASH_LEN, 0);
    let mut apply = |item: &[u8], adding: bool| -> Result<(), AppStateError> {
        let expanded = baileys_crypto::hkdf(item, HASH_LEN, None, LT_HASH_SALT).map_err(invalid)?;
        for i in (0..HASH_LEN).step_by(2) {
            let a = u16::from_le_bytes([out[i], out[i + 1]]);
            let b = u16::from_le_bytes([expanded[i], expanded[i + 1]]);
            let r = if adding { a.wrapping_add(b) } else { a.wrapping_sub(b) };
            out[i..i + 2].copy_from_slice(&r.to_le_bytes());
        }
        Ok(())
    };
    for item in sub {
        apply(item.as_slice(), false)?;
    }
    for item in add {
        apply(item.as_slice(), true)?;
    }
    Ok(out)
}

/// `makeLtHashGenerator`.
struct LtHashGenerator {
    index_value_map: HashMap<String, IndexValue>,
    add: Vec<Vec<u8>>,
    sub: Vec<Vec<u8>>,
    hash: Vec<u8>,
}

impl LtHashGenerator {
    fn new(state: &LtHashState) -> Self {
        Self {
            index_value_map: state.index_value_map.clone(),
            add: Vec::new(),
            sub: Vec::new(),
            hash: state.hash_bytes(),
        }
    }

    fn mix(&mut self, index_mac: &[u8], value_mac: &[u8], operation: i32) -> Result<(), AppStateError> {
        let index_b64 = b64(index_mac);
        let prev = self.index_value_map.get(&index_b64).map(|v| from_buffer(&v.value_mac));
        if operation == wa::syncd_mutation::SyncdOperation::Remove as i32 {
            if prev.is_none() {
                return Err(invalid("tried remove, but no previous op"));
            }
            self.index_value_map.remove(&index_b64);
        } else {
            self.add.push(value_mac.to_vec());
            self.index_value_map.insert(index_b64, IndexValue { value_mac: to_buffer(value_mac) });
        }
        if let Some(prev) = prev {
            self.sub.push(prev);
        }
        Ok(())
    }

    fn finish(self) -> Result<(Vec<u8>, HashMap<String, IndexValue>), AppStateError> {
        let hash = lt_hash_subtract_then_add(&self.hash, &self.add, &self.sub)?;
        Ok((hash, self.index_value_map))
    }
}

/// Getter de `keyData` por id base64 (`getAppStateSyncKey`).
pub type KeyGetter<'a> = &'a dyn Fn(&str) -> Option<Vec<u8>>;

fn get_key(get_app_state_sync_key: KeyGetter<'_>, key_id: &[u8]) -> Result<MutationKeys, AppStateError> {
    let base64_key = b64(key_id);
    let key_data = get_app_state_sync_key(&base64_key).ok_or(AppStateError::KeyNotFound(base64_key))?;
    mutation_keys(&key_data)
}

/// `decodeSyncdMutations` — `(operation, record)`; snapshots usam SET.
fn decode_syncd_mutations(
    mutations: &[(i32, &wa::SyncdRecord)],
    initial_state: &LtHashState,
    get_app_state_sync_key: KeyGetter<'_>,
    on_mutation: &mut dyn FnMut(ChatMutation),
    validate_macs: bool,
) -> Result<(Vec<u8>, HashMap<String, IndexValue>), AppStateError> {
    let mut generator = LtHashGenerator::new(initial_state);
    for (operation, record) in mutations {
        let key_id = record.key_id.as_ref().and_then(|k| k.id.as_deref()).unwrap_or_default();
        let key = get_key(get_app_state_sync_key, key_id)?;
        let content = record.value.as_ref().and_then(|v| v.blob.as_deref()).unwrap_or_default();
        if content.len() < 32 + 16 {
            return Err(invalid("syncd record value too short"));
        }
        let (enc_content, og_value_mac) = content.split_at(content.len() - 32);
        if validate_macs {
            let content_hmac = generate_mac(*operation, enc_content, key_id, &key.value_mac_key);
            if content_hmac != og_value_mac {
                return Err(invalid("HMAC content verification failed"));
            }
        }

        // `aesDecrypt`: IV nos 16 primeiros bytes.
        let (iv, ciphertext) = enc_content.split_at(16);
        let decrypted = baileys_crypto::aes_decrypt_cbc(ciphertext, &key.value_encryption_key, iv).map_err(invalid)?;
        let sync_action = wa::SyncActionData::decode(decrypted.as_slice()).map_err(invalid)?;

        let index_blob = record.index.as_ref().and_then(|i| i.blob.as_deref()).unwrap_or_default();
        if validate_macs {
            let hmac = baileys_crypto::hmac_sign(
                sync_action.index.as_deref().unwrap_or_default(),
                &key.index_key,
                baileys_crypto::HmacVariant::Sha256,
            );
            if hmac != index_blob {
                return Err(invalid("HMAC index verification failed"));
            }
        }

        let index: Vec<String> = serde_json::from_slice::<Vec<serde_json::Value>>(
            sync_action.index.as_deref().unwrap_or_default(),
        )
        .map_err(invalid)?
        .into_iter()
        .map(|v| match v {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
        .collect();
        on_mutation(ChatMutation { sync_action, index });

        generator.mix(index_blob, og_value_mac, *operation)?;
    }
    generator.finish()
}

/// `decodeSyncdPatch`.
fn decode_syncd_patch(
    patch: &wa::SyncdPatch,
    name: &str,
    initial_state: &LtHashState,
    get_app_state_sync_key: KeyGetter<'_>,
    on_mutation: &mut dyn FnMut(ChatMutation),
    validate_macs: bool,
) -> Result<(Vec<u8>, HashMap<String, IndexValue>), AppStateError> {
    if validate_macs {
        let key_id = patch.key_id.as_ref().and_then(|k| k.id.as_deref()).unwrap_or_default();
        let main_key = get_key(get_app_state_sync_key, key_id)?;
        let mutation_macs: Vec<Vec<u8>> = patch
            .mutations
            .iter()
            .map(|m| {
                let blob = m.record.as_ref().and_then(|r| r.value.as_ref()).and_then(|v| v.blob.as_deref()).unwrap_or_default();
                blob[blob.len().saturating_sub(32)..].to_vec()
            })
            .collect();
        let version = patch.version.and_then(|v| v.version).unwrap_or(0);
        let patch_mac = generate_patch_mac(
            patch.snapshot_mac.as_deref().unwrap_or_default(),
            &mutation_macs,
            version,
            name,
            &main_key.patch_mac_key,
        );
        if patch.patch_mac.as_deref() != Some(patch_mac.as_slice()) {
            return Err(invalid("Invalid patch mac"));
        }
    }

    let default_record = wa::SyncdRecord::default();
    let mutations: Vec<(i32, &wa::SyncdRecord)> = patch
        .mutations
        .iter()
        .map(|m| (m.operation.unwrap_or(0), m.record.as_ref().unwrap_or(&default_record)))
        .collect();
    decode_syncd_mutations(&mutations, initial_state, get_app_state_sync_key, on_mutation, validate_macs)
}

/// `decodeSyncdSnapshot`.
pub fn decode_syncd_snapshot(
    name: &str,
    snapshot: &wa::SyncdSnapshot,
    get_app_state_sync_key: KeyGetter<'_>,
    minimum_version_number: Option<u64>,
    validate_macs: bool,
) -> Result<(LtHashState, MutationMap), AppStateError> {
    let mut new_state = LtHashState::new();
    new_state.version = snapshot.version.and_then(|v| v.version).unwrap_or(0);

    let mut mutation_map = MutationMap::default();
    let are_mutations_required = minimum_version_number.map_or(true, |min| new_state.version > min);

    let set = wa::syncd_mutation::SyncdOperation::Set as i32;
    let records: Vec<(i32, &wa::SyncdRecord)> = snapshot.records.iter().map(|r| (set, r)).collect();
    let mut on_mutation = |m: ChatMutation| {
        if are_mutations_required {
            mutation_map.insert(mutation_key(&m), m);
        }
    };
    let (hash, index_value_map) =
        decode_syncd_mutations(&records, &new_state, get_app_state_sync_key, &mut on_mutation, validate_macs)?;
    new_state.hash = to_buffer(&hash);
    new_state.index_value_map = index_value_map;

    if validate_macs {
        let key_id = snapshot.key_id.as_ref().and_then(|k| k.id.as_deref()).unwrap_or_default();
        let keys = get_key(get_app_state_sync_key, key_id)?;
        let computed = generate_snapshot_mac(&hash, new_state.version, name, &keys.snapshot_mac_key);
        if snapshot.mac.as_deref() != Some(computed.as_slice()) {
            return Err(invalid(format!("failed to verify LTHash at {} of {name} from snapshot", new_state.version)));
        }
    }

    Ok((new_state, mutation_map))
}

/// `decodePatches` — as `externalMutations` já devem ter sido baixadas e
/// anexadas às `mutations` pelo chamador.
pub fn decode_patches(
    name: &str,
    syncds: &[wa::SyncdPatch],
    initial: &LtHashState,
    get_app_state_sync_key: KeyGetter<'_>,
    minimum_version_number: Option<u64>,
    validate_macs: bool,
) -> Result<(LtHashState, MutationMap), AppStateError> {
    let mut new_state = initial.clone();
    let mut mutation_map = MutationMap::default();

    for syncd in syncds {
        let patch_version = syncd.version.and_then(|v| v.version).unwrap_or(0);
        new_state.version = patch_version;
        let should_mutate = minimum_version_number.map_or(true, |min| patch_version > min);

        let mut on_mutation = |m: ChatMutation| {
            if should_mutate {
                mutation_map.insert(mutation_key(&m), m);
            }
        };
        // O Node sempre valida os MACs do patch (`decodeSyncdPatch(..., true)`).
        let (hash, index_value_map) =
            decode_syncd_patch(syncd, name, &new_state, get_app_state_sync_key, &mut on_mutation, true)?;
        new_state.hash = to_buffer(&hash);
        new_state.index_value_map = index_value_map;

        if validate_macs {
            let key_id = syncd.key_id.as_ref().and_then(|k| k.id.as_deref()).unwrap_or_default();
            let keys = get_key(get_app_state_sync_key, key_id)?;
            let computed = generate_snapshot_mac(&hash, new_state.version, name, &keys.snapshot_mac_key);
            if syncd.snapshot_mac.as_deref() != Some(computed.as_slice()) {
                return Err(invalid(format!("failed to verify LTHash at {} of {name}", new_state.version)));
            }
        }
    }

    Ok((new_state, mutation_map))
}

/// Uma coleção do resultado do `w:sync:app:state` (`extractSyncdPatches`),
/// antes do download do snapshot externo.
pub struct CollectionResult {
    pub name: String,
    pub patches: Vec<wa::SyncdPatch>,
    pub has_more_patches: bool,
    pub snapshot_ref: Option<wa::ExternalBlobReference>,
}

/// Parte síncrona do `extractSyncdPatches`.
pub fn parse_syncd_collections(result: &BinaryNode) -> Result<Vec<CollectionResult>, AppStateError> {
    let Some(sync_node) = result.child("sync") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for collection in sync_node.children("collection") {
        let name = collection.attr("name").unwrap_or_default().to_string();
        let has_more_patches = collection.attr("has_more_patches") == Some("true");
        let collection_version: u64 = collection.attr("version").and_then(|v| v.parse().ok()).unwrap_or(0);

        let snapshot_ref = match collection.child("snapshot").and_then(|s| s.child_bytes_self()) {
            Some(bytes) if !bytes.is_empty() => {
                Some(wa::ExternalBlobReference::decode(bytes).map_err(invalid)?)
            }
            _ => None,
        };

        let patches_parent = collection.child("patches").unwrap_or(collection);
        let mut patches = Vec::new();
        for patch in patches_parent.children("patch") {
            let Some(bytes) = patch.child_bytes_self() else { continue };
            let mut syncd = wa::SyncdPatch::decode(bytes).map_err(invalid)?;
            if syncd.version.is_none() {
                syncd.version = Some(wa::SyncdVersion { version: Some(collection_version + 1) });
            }
            patches.push(syncd);
        }

        out.push(CollectionResult { name, patches, has_more_patches, snapshot_ref });
    }
    Ok(out)
}

/// Bytes do `content` de um nó (quando é binário).
trait NodeBytes {
    fn child_bytes_self(&self) -> Option<&[u8]>;
}

impl NodeBytes for BinaryNode {
    fn child_bytes_self(&self) -> Option<&[u8]> {
        match &self.content {
            Some(baileys_core::BinaryContent::Bytes(b)) => Some(b.as_slice()),
            _ => None,
        }
    }
}

/// `downloadExternalBlob` — `md-app-state` ("WhatsApp App State Keys").
pub async fn download_external_blob(blob: &wa::ExternalBlobReference) -> Result<Vec<u8>, AppStateError> {
    let media_key = blob.media_key.as_deref().filter(|k| !k.is_empty()).ok_or_else(|| invalid("external blob sem mediaKey"))?;
    let direct_path = blob.direct_path.as_deref().filter(|p| !p.is_empty()).ok_or_else(|| invalid("external blob sem directPath"))?;
    let expanded = baileys_crypto::hkdf(media_key, 112, None, "WhatsApp App State Keys").map_err(invalid)?;
    let iv = &expanded[0..16];
    let cipher_key = &expanded[16..48];

    let url = baileys_media::url_from_direct_path(direct_path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(invalid)?;
    let bytes = client
        .get(&url)
        .header("Origin", "https://web.whatsapp.com")
        .send()
        .await
        .map_err(invalid)?
        .bytes()
        .await
        .map_err(invalid)?;

    // `ciphertext || mac(10)`: decifra só os blocos inteiros de 16 (o MAC fica fora).
    let body = &bytes[..(bytes.len() / 16) * 16];
    baileys_crypto::aes_decrypt_cbc(body, cipher_key, iv).map_err(invalid)
}

/// `downloadExternalPatch`.
pub async fn download_external_patch(blob: &wa::ExternalBlobReference) -> Result<wa::SyncdMutations, AppStateError> {
    let buffer = download_external_blob(blob).await?;
    wa::SyncdMutations::decode(buffer.as_slice()).map_err(invalid)
}

/// JSON do `app-state-sync-key` (`proto.Message.AppStateSyncKeyData` em BufferJSON).
pub fn app_state_sync_key_json(data: &wa::message::AppStateSyncKeyData) -> String {
    let mut obj = serde_json::Map::new();
    if let Some(key_data) = &data.key_data {
        obj.insert("keyData".to_string(), serde_json::to_value(to_buffer(key_data)).unwrap_or_default());
    }
    if let Some(fp) = &data.fingerprint {
        obj.insert(
            "fingerprint".to_string(),
            serde_json::json!({
                "rawId": fp.raw_id,
                "currentIndex": fp.current_index,
                "deviceIndexes": fp.device_indexes,
            }),
        );
    }
    if let Some(ts) = data.timestamp {
        obj.insert("timestamp".to_string(), serde_json::Value::String(ts.to_string()));
    }
    serde_json::Value::Object(obj).to_string()
}

/// `keyData` de um `app-state-sync-key` gravado (BufferJSON ou base64 cru).
pub fn app_state_sync_key_data(json: &str) -> Option<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let key_data = value.get("keyData")?;
    match key_data {
        serde_json::Value::String(s) => base64::engine::general_purpose::STANDARD.decode(s).ok(),
        other => serde_json::from_value::<BufferValue>(other.clone()).ok().map(|b| from_buffer(&b)),
    }
    .filter(|k| !k.is_empty())
}

/// Id base64 de uma chave do `appStateSyncKeyShare`.
pub fn app_state_key_id_b64(key_id: &[u8]) -> String {
    b64(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lt_hash_add_then_remove_returns_initial() {
        let initial = vec![0u8; HASH_LEN];
        let mac = vec![7u8; 32];
        let added = lt_hash_subtract_then_add(&initial, &[mac.clone()], &[]).unwrap();
        assert_ne!(added, initial);
        let removed = lt_hash_subtract_then_add(&added, &[], &[mac]).unwrap();
        assert_eq!(removed, initial);
    }

    #[test]
    fn mutation_roundtrip_set_and_decode() {
        let key_data = vec![1u8; 32];
        let keys = mutation_keys(&key_data).unwrap();
        let key_id = vec![9u8, 9, 9];
        let index = br#"["setting_pushName"]"#.to_vec();
        let action = wa::SyncActionData {
            index: Some(index.clone()),
            value: Some(wa::SyncActionValue {
                push_name_setting: Some(wa::sync_action_value::PushNameSetting { name: Some("Joao".into()) }),
                ..Default::default()
            }),
            padding: Some(Vec::new()),
            version: Some(1),
        };
        let iv = [3u8; 16];
        let enc = baileys_crypto::aes_encrypt_cbc(&action.encode_to_vec(), &keys.value_encryption_key, &iv).unwrap();
        let mut enc_value = iv.to_vec();
        enc_value.extend(enc);
        let set = wa::syncd_mutation::SyncdOperation::Set as i32;
        let value_mac = generate_mac(set, &enc_value, &key_id, &keys.value_mac_key);
        let index_mac = baileys_crypto::hmac_sign(&index, &keys.index_key, baileys_crypto::HmacVariant::Sha256);
        let mut blob = enc_value;
        blob.extend(value_mac);
        let record = wa::SyncdRecord {
            index: Some(wa::SyncdIndex { blob: Some(index_mac) }),
            value: Some(wa::SyncdValue { blob: Some(blob) }),
            key_id: Some(wa::KeyId { id: Some(key_id.clone()) }),
        };
        let snapshot = wa::SyncdSnapshot {
            version: Some(wa::SyncdVersion { version: Some(3) }),
            records: vec![record],
            ..Default::default()
        };
        let getter = |id: &str| (id == b64(&key_id)).then(|| key_data.clone());
        let (state, map) = decode_syncd_snapshot("critical_block", &snapshot, &getter, None, false).unwrap();
        assert_eq!(state.version, 3);
        let mutations = map.into_mutations();
        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].index, vec!["setting_pushName".to_string()]);
    }
}
