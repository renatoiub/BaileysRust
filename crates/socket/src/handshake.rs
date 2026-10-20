//! Nós de handshake — port de `Hineken/src/Utils/validate-connection.ts`.

use baileys_core::ids::encode_big_endian;
use baileys_proto::proto as wa;
use baileys_store::creds::AuthenticationCreds;
use base64::Engine;
use prost::Message;

/// `generateLoginNode` — ClientPayload para login de dispositivo já registrado.
pub fn generate_login_node(user_jid: &str, config: &ClientConfig, wa_version: [u32; 3]) -> wa::ClientPayload {
    let decoded = baileys_core::jid_decode(user_jid);
    let (user, device) = match decoded {
        Some(d) => (d.user, d.device.unwrap_or(0)),
        None => (user_jid.trim_end_matches("@s.whatsapp.net").to_string(), 0),
    };

    let mut payload = base_client_payload(config, wa_version);
    payload.passive = Some(true);
    payload.pull = Some(true);
    payload.username = Some(user.parse::<u64>().unwrap_or(0));
    payload.device = Some(device);
    payload.lid_db_migrated = Some(false);
    payload
}

/// `generateRegistrationNode` — ClientPayload de registro (novo dispositivo).
pub fn generate_registration_node(
    creds: &AuthenticationCreds,
    config: &ClientConfig,
    wa_version: [u32; 3],
) -> wa::ClientPayload {
    let app_version_buf = baileys_crypto::md5(
        wa_version
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(".")
            .as_bytes(),
    );

    let device_props = wa::DeviceProps {
        os: Some(config.browser_os.clone()),
        platform_type: Some(platform_type(&config.browser_platform) as i32),
        require_full_sync: Some(config.sync_full_history),
        version: Some(wa::device_props::AppVersion {
            primary: Some(10),
            secondary: Some(15),
            tertiary: Some(7),
            quaternary: None,
            quinary: None,
        }),
        history_sync_config: Some(wa::device_props::HistorySyncConfig {
            full_sync_days_limit: None,
            full_sync_size_mb_limit: None,
            storage_quota_mb: Some(569150),
            inline_initial_payload_in_e2_ee_msg: Some(false),
            recent_sync_days_limit: None,
            support_call_log_history: Some(false),
            support_bot_user_agent_chat_history: Some(true),
            support_cag_reactions_and_polls: Some(true),
            support_biz_hosted_msg: Some(true),
            support_recent_sync_chunk_message_count_tuning: Some(true),
            support_hosted_group_msg: Some(true),
            support_fbid_bot_chat_history: Some(true),
            support_message_association: Some(true),
            support_add_on_history_sync_migration: None,
        }),
    };
    let device_props_bytes = device_props.encode_to_vec();

    let spk_pub = decode_buffer(&creds.signed_pre_key.key_pair.public);
    let spk_sig = decode_buffer(&creds.signed_pre_key.signature);
    let identity_pub = decode_buffer(&creds.signed_identity_key.public);

    let pairing_data = wa::client_payload::DevicePairingRegistrationData {
        e_regid: Some(encode_big_endian(creds.registration_id, 4)),
        e_keytype: Some(vec![5]),
        e_ident: Some(identity_pub),
        e_skey_id: Some(encode_big_endian(creds.signed_pre_key.key_id, 3)),
        e_skey_val: Some(spk_pub),
        e_skey_sig: Some(spk_sig),
        build_hash: Some(app_version_buf),
        device_props: Some(device_props_bytes),
    };

    let mut payload = base_client_payload(config, wa_version);
    payload.passive = Some(false);
    payload.pull = Some(false);
    payload.device_pairing_data = Some(pairing_data);
    payload
}

fn base_client_payload(config: &ClientConfig, wa_version: [u32; 3]) -> wa::ClientPayload {
    wa::ClientPayload {
        username: None,
        passive: None,
        user_agent: Some(wa::client_payload::UserAgent {
            platform: Some(wa::client_payload::user_agent::Platform::Web as i32),
            app_version: Some(wa::client_payload::user_agent::AppVersion {
                primary: Some(wa_version[0]),
                secondary: Some(wa_version[1]),
                tertiary: Some(wa_version[2]),
                quaternary: None,
                quinary: None,
            }),
            mcc: Some("000".to_string()),
            mnc: Some("000".to_string()),
            os_version: Some("0.1".to_string()),
            manufacturer: None,
            device: Some("Desktop".to_string()),
            os_build_number: Some("0.1".to_string()),
            phone_id: None,
            release_channel: Some(wa::client_payload::user_agent::ReleaseChannel::Release as i32),
            locale_language_iso6391: Some("en".to_string()),
            locale_country_iso31661_alpha2: Some(config.country_code.clone()),
            device_board: None,
            device_exp_id: None,
            device_type: None,
            device_model_type: None,
        }),
        web_info: Some(wa::client_payload::WebInfo {
            ref_token: None,
            version: None,
            webd_payload: None,
            web_sub_platform: Some(web_sub_platform(config) as i32),
        }),
        push_name: None,
        session_id: None,
        short_connect: None,
        connect_type: Some(wa::client_payload::ConnectType::WifiUnknown as i32),
        connect_reason: Some(wa::client_payload::ConnectReason::UserActivated as i32),
        shards: vec![],
        dns_source: None,
        connect_attempt_count: None,
        device: None,
        device_pairing_data: None,
        product: Some(wa::client_payload::Product::Whatsapp as i32),
        fb_cat: None,
        fb_user_agent: None,
        oc: None,
        lc: None,
        ios_app_extension: None,
        fb_app_id: None,
        fb_device_id: None,
        pull: None,
        padding_bytes: None,
        year_class: None,
        mem_class: None,
        interop_data: None,
        traffic_anonymization: None,
        lid_db_migrated: None,
        account_type: None,
    }
}

fn web_sub_platform(config: &ClientConfig) -> wa::client_payload::web_info::WebSubPlatform {
    if config.sync_full_history {
        match config.browser_os.as_str() {
            "Mac OS" => wa::client_payload::web_info::WebSubPlatform::Darwin,
            "Windows" => wa::client_payload::web_info::WebSubPlatform::Win32,
            _ => wa::client_payload::web_info::WebSubPlatform::WebBrowser,
        }
    } else {
        wa::client_payload::web_info::WebSubPlatform::WebBrowser
    }
}

fn platform_type(platform: &str) -> wa::device_props::PlatformType {
    match platform.to_ascii_uppercase().as_str() {
        "CHROME" => wa::device_props::PlatformType::Chrome,
        "FIREFOX" => wa::device_props::PlatformType::Firefox,
        "IE" => wa::device_props::PlatformType::Ie,
        "OPERA" => wa::device_props::PlatformType::Opera,
        "SAFARI" => wa::device_props::PlatformType::Safari,
        "EDGE" => wa::device_props::PlatformType::Edge,
        "DESKTOP" => wa::device_props::PlatformType::Desktop,
        "IPAD" => wa::device_props::PlatformType::Ipad,
        "ANDROID_TABLET" => wa::device_props::PlatformType::AndroidTablet,
        "OHANA" => wa::device_props::PlatformType::Ohana,
        "ALOHA" => wa::device_props::PlatformType::Aloha,
        "CATALINA" => wa::device_props::PlatformType::Catalina,
        "TCL_TV" => wa::device_props::PlatformType::TclTv,
        "IOS_PHONE" => wa::device_props::PlatformType::IosPhone,
        "IOS_CATALYST" => wa::device_props::PlatformType::IosCatalyst,
        "ANDROID_PHONE" => wa::device_props::PlatformType::AndroidPhone,
        _ => wa::device_props::PlatformType::Chrome,
    }
}

/// `configureSuccessfulPairing` — valida o HMAC/assinaturas e monta o reply.
///
/// Retorna as creds atualizadas (fragmento) e o nó de resposta
/// `pair-device-sign`.
pub fn configure_successful_pairing(
    stanza: &baileys_core::BinaryNode,
    creds: &AuthenticationCreds,
) -> Result<(AuthenticationCreds, baileys_core::BinaryNode), HandshakeError> {
    let msg_id = stanza.attr("id").unwrap_or_default().to_string();

    let pair_success = stanza
        .child("pair-success")
        .ok_or(HandshakeError::MissingNode("pair-success"))?;
    let device_identity = pair_success
        .child("device-identity")
        .ok_or(HandshakeError::MissingNode("device-identity"))?;
    let device = pair_success
        .child("device")
        .ok_or(HandshakeError::MissingNode("device"))?;
    let platform = pair_success.child("platform");
    let biz = pair_success.child("biz");

    let biz_name = biz.and_then(|b| b.attr("name")).map(String::from);
    let jid = device.attr("jid").unwrap_or_default().to_string();
    let lid = device.attr("lid").map(String::from);

    let identity_bytes = device_identity
        .content
        .as_ref()
        .and_then(|c| match c {
            baileys_core::BinaryContent::Bytes(b) => Some(b.clone()),
            _ => None,
        })
        .ok_or(HandshakeError::MissingNode("device-identity content"))?;

    let hmac_proto = wa::AdvSignedDeviceIdentityHmac::decode(identity_bytes.as_slice())
        .map_err(HandshakeError::Prost)?;
    let details = hmac_proto
        .details
        .ok_or(HandshakeError::MissingNode("details"))?;
    let hmac = hmac_proto
        .hmac
        .ok_or(HandshakeError::MissingNode("hmac"))?;
    let account_type = hmac_proto.account_type;

    let hmac_prefix: &[u8] = if account_type == Some(wa::AdvEncryptionType::Hosted as i32) {
        &baileys_core::constants::WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
    } else {
        &[]
    };

    let adv_secret = base64::engine::general_purpose::STANDARD
        .decode(&creds.adv_secret_key)
        .unwrap_or_default();
    let mut to_sign = Vec::with_capacity(hmac_prefix.len() + details.len());
    to_sign.extend_from_slice(hmac_prefix);
    to_sign.extend_from_slice(&details);
    let adv_sign = baileys_crypto::hmac_sign(&to_sign, &adv_secret, baileys_crypto::HmacVariant::Sha256);
    if adv_sign != hmac {
        return Err(HandshakeError::InvalidAccountSignature);
    }

    let mut account = wa::AdvSignedDeviceIdentity::decode(details.as_slice())
        .map_err(HandshakeError::Prost)?;

    let account_signature_key = account
        .account_signature_key
        .clone()
        .ok_or(HandshakeError::MissingNode("accountSignatureKey"))?;
    let account_signature = account
        .account_signature
        .clone()
        .ok_or(HandshakeError::MissingNode("accountSignature"))?;
    let device_details = account
        .details
        .clone()
        .ok_or(HandshakeError::MissingNode("device details"))?;

    let device_identity_proto = wa::AdvDeviceIdentity::decode(device_details.as_slice())
        .map_err(HandshakeError::Prost)?;

    let account_signature_prefix: &[u8] =
        if device_identity_proto.device_type == Some(wa::AdvEncryptionType::Hosted as i32) {
            &baileys_core::constants::WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
        } else {
            &baileys_core::constants::WA_ADV_ACCOUNT_SIG_PREFIX
        };

    let identity_pub = decode_buffer(&creds.signed_identity_key.public);
    let mut account_msg = Vec::with_capacity(account_signature_prefix.len() + device_details.len() + identity_pub.len());
    account_msg.extend_from_slice(account_signature_prefix);
    account_msg.extend_from_slice(&device_details);
    account_msg.extend_from_slice(&identity_pub);
    if !baileys_crypto::Curve::verify(&account_signature_key, &account_msg, &account_signature) {
        return Err(HandshakeError::InvalidAccountSignature);
    }

    // deviceSignature = sign(identityPrivate, DEVICE_SIG_PREFIX || deviceDetails || identityPub || accountSignatureKey)
    let identity_priv = decode_buffer(&creds.signed_identity_key.private);
    let mut device_msg = Vec::new();
    device_msg.extend_from_slice(&baileys_core::constants::WA_ADV_DEVICE_SIG_PREFIX);
    device_msg.extend_from_slice(&device_details);
    device_msg.extend_from_slice(&identity_pub);
    device_msg.extend_from_slice(&account_signature_key);
    account.device_signature = baileys_crypto::Curve::sign(&identity_priv, &device_msg).ok();

    // encodeSignedDeviceIdentity(account, false) — sem signature key.
    let mut encoded_account = account.clone();
    encoded_account.account_signature_key = None;
    let account_enc = encoded_account.encode_to_vec();

    let reply = baileys_core::BinaryNode::new("iq")
        .with_attr("to", baileys_core::jid::S_WHATSAPP_NET)
        .with_attr("type", "result")
        .with_attr("id", msg_id)
        .with_children(vec![baileys_core::BinaryNode::new("pair-device-sign").with_children(vec![
            baileys_core::BinaryNode::new("device-identity")
                .with_attr("key-index", device_identity_proto.key_index.unwrap_or(0).to_string())
                .with_bytes(account_enc),
        ])]);

    // Creds atualizadas.
    let mut updated = creds.clone();
    updated.account = Some(account_to_json(&account));
    updated.me = Some(baileys_store::creds::Contact {
        id: jid,
        name: biz_name,
        lid,
        notify: None,
    });
    updated.platform = platform.and_then(|p| p.attr("name")).map(String::from);
    updated.registered = true;

    Ok((updated, reply))
}

fn decode_buffer(value: &baileys_store::creds::BufferValue) -> Vec<u8> {
    match value {
        baileys_store::creds::BufferValue::Buffer { data, .. }
        | baileys_store::creds::BufferValue::Raw(data) => {
            base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default()
        }
    }
}

/// Serializa `AdvSignedDeviceIdentity` no formato do protobufjs (camelCase,
/// campos `bytes` como `{"type":"Buffer","data":"<base64>"}`), idêntico ao que
/// o Node grava em `authState.creds.account` via `BufferJSON.replacer`.
pub fn account_to_json(account: &wa::AdvSignedDeviceIdentity) -> serde_json::Value {
    let field = |v: &Option<Vec<u8>>| {
        v.as_ref().map(|b| {
            serde_json::json!({
                "type": "Buffer",
                "data": base64::engine::general_purpose::STANDARD.encode(b),
            })
        }).unwrap_or(serde_json::Value::Null)
    };
    serde_json::json!({
        "details": field(&account.details),
        "accountSignatureKey": field(&account.account_signature_key),
        "accountSignature": field(&account.account_signature),
        "deviceSignature": field(&account.device_signature),
    })
}

/// `encodeSignedDeviceIdentity(account, includeSignatureKey)` — port fiel de
/// `Utils/validate-connection.js`.
///
/// No envio de mensagens (`relayMessage`) o Node chama com
/// `includeSignatureKey = true` (mantém a `accountSignatureKey`); apenas o
/// `pair-device-sign` usa `false`. Sem a signature key no stanza, o device
/// primário rejeita o `pkmsg` e a mensagem fica "Aguardando mensagem".
pub fn encode_signed_device_identity(
    account_json: &serde_json::Value,
    include_signature_key: bool,
) -> Option<Vec<u8>> {
    let account = account_from_json(account_json)?;
    let mut account = account;
    if !include_signature_key || account.account_signature_key.as_ref().map(|k| k.is_empty()).unwrap_or(true) {
        account.account_signature_key = None;
    }
    Some(account.encode_to_vec())
}

/// Desserializa `AdvSignedDeviceIdentity` a partir do JSON do protobufjs
/// (camelCase + BufferJSON), tal como gravado em `creds.account`.
pub fn account_from_json(value: &serde_json::Value) -> Option<wa::AdvSignedDeviceIdentity> {
    let buf = |v: &serde_json::Value| -> Option<Vec<u8>> {
        match v {
            serde_json::Value::Null => None,
            serde_json::Value::Object(map) => {
                let data = map.get("data")?;
                base64::engine::general_purpose::STANDARD
                    .decode(data.as_str()?)
                    .ok()
            }
            serde_json::Value::Array(arr) => Some(
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u8))
                    .collect(),
            ),
            _ => None,
        }
    };
    let obj = value.as_object()?;
    Some(wa::AdvSignedDeviceIdentity {
        details: buf(obj.get("details")?),
        account_signature_key: buf(obj.get("accountSignatureKey")?),
        account_signature: buf(obj.get("accountSignature")?),
        device_signature: buf(obj.get("deviceSignature")?),
    })
}

/// Configuração de conexão (espelha os campos do `SocketConfig` usados no login).
#[derive(Clone)]
pub struct ClientConfig {
    pub browser_os: String,
    pub browser_platform: String,
    pub sync_full_history: bool,
    pub country_code: String,
    pub keep_alive_interval_ms: u64,
    pub default_query_timeout_ms: u64,
    pub qr_timeout_ms: u64,
    /// `maxMsgRetryCount` — vale para o pedido de retry e para o reenvio.
    pub max_msg_retry_count: u32,
    /// `retryRequestDelayMs` — espera após cada `sendRetryRequest`.
    pub retry_request_delay_ms: u64,
    /// `ignoreGroups` do container (`shouldIgnoreJid`: grupo/broadcast/newsletter).
    pub ignore_groups: bool,
    /// `cacheControl`: liga os caches compartilháveis (metadados de grupo,
    /// LID, onWhatsApp, foto de perfil e devices).
    pub cache_control: bool,
    /// Provider externo dos caches (ex.: Redis). `None` = só memória.
    /// Os compartilháveis usam `cache:global:*`, iguais para todas as conexões.
    pub cache_provider: Option<std::sync::Arc<dyn crate::cache::CacheStore>>,
    /// Prefixo dos caches por conexão no provider (`cache:instance:{key}:*`).
    pub cache_instance_key: Option<String>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("browser_os", &self.browser_os)
            .field("browser_platform", &self.browser_platform)
            .field("sync_full_history", &self.sync_full_history)
            .field("country_code", &self.country_code)
            .field("max_msg_retry_count", &self.max_msg_retry_count)
            .field("ignore_groups", &self.ignore_groups)
            .field("cache_control", &self.cache_control)
            .field("cache_provider", &self.cache_provider.is_some())
            .field("cache_instance_key", &self.cache_instance_key)
            .finish_non_exhaustive()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            browser_os: "Ubuntu".to_string(),
            browser_platform: "Chrome".to_string(),
            sync_full_history: false,
            country_code: "BR".to_string(),
            keep_alive_interval_ms: 10_000,
            default_query_timeout_ms: 40_000,
            qr_timeout_ms: 60_000,
            max_msg_retry_count: 5,
            retry_request_delay_ms: 250,
            ignore_groups: false,
            cache_control: true,
            cache_provider: None,
            cache_instance_key: None,
        }
    }
}

/// Erros do handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("missing node: {0}")]
    MissingNode(&'static str),
    #[error("invalid account signature")]
    InvalidAccountSignature,
    #[error("prost decode: {0}")]
    Prost(#[from] prost::DecodeError),
}
