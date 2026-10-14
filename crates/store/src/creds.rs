//! Tipos de credenciais — espelhando `Types/Auth.ts`.

use serde::{Deserialize, Serialize};

use baileys_crypto::KeyPair;

/// `KeyPair` serializado em BufferJSON (como o Node grava).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerializedKeyPair {
    pub public: BufferValue,
    pub private: BufferValue,
}

/// Valor que pode ser bytes (BufferJSON) ou string base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BufferValue {
    Buffer { #[serde(rename = "type")] type_: String, data: String },
    Raw(String),
}

/// `SignedKeyPair`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeyPair {
    pub key_pair: SerializedKeyPair,
    pub signature: BufferValue,
    pub key_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_s: Option<u64>,
}

/// `Contact` (subconjunto usado em creds).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<String>,
}

/// `AuthenticationCreds` — espelha `Types/Auth.ts`.
///
/// NOTA: o campo `account` é `proto.ADVSignedDeviceIdentity` e `signalIdentities`
/// é uma lista; aqui mantemos como JSON genérico para preservar compatibilidade
/// de leitura sem perder campos desconhecidos.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationCreds {
    pub noise_key: SerializedKeyPair,
    pub pairing_ephemeral_key_pair: SerializedKeyPair,
    pub signed_identity_key: SerializedKeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u32,
    pub adv_secret_key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub me: Option<Contact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_identities: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub my_app_state_key_id: Option<String>,
    pub first_unuploaded_pre_key_id: u32,
    pub next_pre_key_id: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_account_sync_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,

    #[serde(default)]
    pub processed_history_messages: serde_json::Value,
    pub account_sync_counter: u32,
    pub account_settings: serde_json::Value,
    pub registered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_prop_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_info: Option<BufferValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nct_salt: Option<BufferValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachout_time_lock: Option<serde_json::Value>,
}

impl AuthenticationCreds {
    /// Converte para o `KeyPair` do `baileys-crypto` (decodificando base64).
    pub fn noise_key_pair(&self) -> KeyPair {
        KeyPair {
            private: decode_buffer(&self.noise_key.private),
            public: decode_buffer(&self.noise_key.public),
        }
    }

    pub fn signed_identity_key_pair(&self) -> KeyPair {
        KeyPair {
            private: decode_buffer(&self.signed_identity_key.private),
            public: decode_buffer(&self.signed_identity_key.public),
        }
    }
}

/// `initAuthCreds` — espelha `Hineken/src/Utils/auth-utils.ts::initAuthCreds`.
pub fn init_auth_creds() -> AuthenticationCreds {
    use base64::Engine;
    use rand::RngCore;

    let noise_key = baileys_crypto::Curve::generate_key_pair();
    let pairing_ephemeral = baileys_crypto::Curve::generate_key_pair();
    let identity = baileys_crypto::Curve::generate_key_pair();
    let signed_pre_key = baileys_crypto::signed_key_pair(&identity, 1);

    let mut adv_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut adv_secret);

    AuthenticationCreds {
        noise_key: SerializedKeyPair {
            public: to_buffer(&noise_key.public),
            private: to_buffer(&noise_key.private),
        },
        pairing_ephemeral_key_pair: SerializedKeyPair {
            public: to_buffer(&pairing_ephemeral.public),
            private: to_buffer(&pairing_ephemeral.private),
        },
        signed_identity_key: SerializedKeyPair {
            public: to_buffer(&identity.public),
            private: to_buffer(&identity.private),
        },
        signed_pre_key: SignedKeyPair {
            key_pair: SerializedKeyPair {
                public: to_buffer(&signed_pre_key.key_pair.public),
                private: to_buffer(&signed_pre_key.key_pair.private),
            },
            signature: to_buffer(&signed_pre_key.signature),
            key_id: signed_pre_key.key_id,
            timestamp_s: signed_pre_key.timestamp_s,
        },
        registration_id: baileys_core::ids::generate_registration_id(),
        adv_secret_key: base64::engine::general_purpose::STANDARD.encode(adv_secret),
        me: None,
        account: None,
        signal_identities: None,
        my_app_state_key_id: None,
        first_unuploaded_pre_key_id: 1,
        next_pre_key_id: 1,
        last_account_sync_timestamp: None,
        platform: None,
        processed_history_messages: serde_json::json!([]),
        account_sync_counter: 0,
        account_settings: serde_json::json!({ "unarchiveChats": false }),
        registered: false,
        pairing_code: None,
        last_prop_hash: None,
        routing_info: None,
        nct_salt: None,
        reachout_time_lock: None,
    }
}

fn to_buffer(bytes: &[u8]) -> BufferValue {
    use base64::Engine;
    BufferValue::Buffer {
        type_: "Buffer".to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

fn decode_buffer(value: &BufferValue) -> Vec<u8> {
    use base64::Engine;
    match value {
        BufferValue::Buffer { data, .. } => base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap_or_default(),
        BufferValue::Raw(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap_or_default(),
    }
}
