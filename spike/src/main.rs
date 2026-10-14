//! `spike-connect` — Fase 0 (go/no-go).
//!
//! Conecta em `wss://web.whatsapp.com/ws/chat`, executa o handshake Noise
//! completo (ClientHello → ServerHello → ClientFinish) e reporta o primeiro
//! nó binário decodificado (Conn/Stream/error).
//!
//! Uso:
//! ```bash
//! cargo run -p baileys-spike -- <session-dir>
//! ```
//!
//! O store em `<session-dir>` usa o MESMO formato SQLite do container Node
//! (`auth_data (key, value)`). Credenciais novas são geradas e gravadas.

use std::sync::Arc;

use base64::Engine;

use baileys_core::constants::WA_VERSION;
use baileys_core::ids::{encode_big_endian, generate_registration_id};
use baileys_crypto::{signed_key_pair, Curve, KeyPair};
use baileys_proto::proto as wa;
use baileys_socket::{parse_server_hello, Frame, NoiseHandler};
use baileys_store::creds::{AuthenticationCreds, BufferValue, SerializedKeyPair, SignedKeyPair};
use baileys_store::sqlite::SQLiteAuthState;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Instala o provedor criptográfico do rustls (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let session_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./spike-session".to_string());

    let store = SQLiteAuthState::open(&session_dir)?;

    // Carrega creds existentes ou gera novas (formato idêntico ao Node).
    let creds = match store.read_creds()? {
        Some(c) => {
            tracing::info!("creds existentes carregadas (swap de sessão)");
            c
        }
        None => {
            let c = generate_creds();
            store.save_creds(&c)?;
            tracing::info!("creds novas geradas e gravadas");
            c
        }
    };

    // 1. Conecta WebSocket.
    let url = "wss://web.whatsapp.com/ws/chat";
    tracing::info!(url, "conectando ao WhatsApp...");
    let (ws_stream, _response) = connect_async(url).await?;
    let (mut sink, mut stream) = ws_stream.split();

    // 2. Par efêmero + noise handler.
    let ephemeral = Curve::generate_key_pair();
    let noise = Arc::new(Mutex::new(NoiseHandler::new(ephemeral.clone(), None)));

    // 3. Envia ClientHello.
    let hello = baileys_socket::client_hello(&ephemeral.public);
    {
        let mut n = noise.lock().await;
        let frame = n.encode_frame(&hello)?;
        sink.send(WsMessage::Binary(frame)).await?;
    }

    // 4. Recebe ServerHello e completa o handshake.
    let noise_key = creds.noise_key_pair();
    let identity_key = creds.signed_identity_key_pair();

    let mut handshake_done = false;
    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let WsMessage::Binary(data) = msg else { continue };

        let mut n = noise.lock().await;
        let mut server_hello_bytes: Option<Vec<u8>> = None;
        let mut got_node = false;

        n.decode_frame(&data, &mut |frame| {
            match frame {
                Frame::Raw(bytes) => {
                    if !handshake_done {
                        server_hello_bytes = Some(bytes);
                    }
                }
                Frame::Node(node) => {
                    tracing::info!(tag = %node.tag, attrs = ?node.attrs, "nó binário recebido");
                    got_node = true;
                }
            }
        })?;

        if let Some(bytes) = server_hello_bytes {
            let server_hello = parse_server_hello(&bytes)?;
            tracing::info!("ServerHello recebido — processando handshake");

            let key_enc = n.process_handshake(&server_hello, &noise_key).await?;

            // ClientPayload de registro (sem creds → registration node).
            let client_payload = build_registration_payload(&creds, &identity_key)?;

            let payload_enc = n.encrypt(&client_payload.encode_to_vec())?;
            let client_finish = wa::HandshakeMessage {
                client_hello: None,
                server_hello: None,
                client_finish: Some(wa::handshake_message::ClientFinish {
                    r#static: Some(key_enc),
                    payload: Some(payload_enc),
                }),
            };
            let finish_bytes = client_finish.encode_to_vec();
            let frame = n.encode_frame(&finish_bytes)?;
            sink.send(WsMessage::Binary(frame)).await?;
            n.finish_init().await?;

            handshake_done = true;
            tracing::info!("ClientFinish enviado — handshake Noise completo (GO)");
        }

        drop(n);
        if got_node {
            break;
        }
    }

    tracing::info!("spike concluído: handshake Noise OK, nós binários decodificados");
    Ok(())
}

/// Gera credenciais novas no formato exato do Node (`initAuthCreds`).
fn generate_creds() -> AuthenticationCreds {
    let noise_key = Curve::generate_key_pair();
    let pairing_ephemeral = Curve::generate_key_pair();
    let identity = Curve::generate_key_pair();
    let signed_pre_key = signed_key_pair(&identity, 1);

    AuthenticationCreds {
        noise_key: to_serialized(&noise_key),
        pairing_ephemeral_key_pair: to_serialized(&pairing_ephemeral),
        signed_identity_key: to_serialized(&identity),
        signed_pre_key: SignedKeyPair {
            key_pair: to_serialized(&signed_pre_key.key_pair),
            signature: to_buffer(&signed_pre_key.signature),
            key_id: signed_pre_key.key_id,
            timestamp_s: signed_pre_key.timestamp_s,
        },
        registration_id: generate_registration_id(),
        adv_secret_key: base64::engine::general_purpose::STANDARD.encode(rand_bytes(32)),
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
        account_settings: serde_json::json!({"unarchiveChats": false}),
        registered: false,
        pairing_code: None,
        last_prop_hash: None,
        routing_info: None,
        nct_salt: None,
        reachout_time_lock: None,
    }
}

fn to_serialized(kp: &KeyPair) -> SerializedKeyPair {
    SerializedKeyPair {
        public: to_buffer(&kp.public),
        private: to_buffer(&kp.private),
    }
}

fn to_buffer(bytes: &[u8]) -> BufferValue {
    BufferValue::Buffer {
        type_: "Buffer".to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut out = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// Constrói o ClientPayload de registro (`generateRegistrationNode`).
fn build_registration_payload(
    creds: &AuthenticationCreds,
    identity_key: &KeyPair,
) -> Result<wa::ClientPayload, Box<dyn std::error::Error>> {
    let app_version_buf = baileys_crypto::md5(WA_VERSION.map(|v| v.to_string()).join(".").as_bytes());

    let device_props = wa::DeviceProps {
        os: Some("Ubuntu".to_string()),
        platform_type: Some(wa::device_props::PlatformType::Chrome as i32),
        require_full_sync: Some(false),
        version: Some(wa::device_props::AppVersion {
            primary: Some(10),
            secondary: Some(15),
            tertiary: Some(7),
            quaternary: None,
            quinary: None,
        }),
        history_sync_config: None,
    };
    let device_props_bytes = device_props.encode_to_vec();

    let signed_pre = &creds.signed_pre_key;
    let spk_pub = decode_buffer(&signed_pre.key_pair.public)?;
    let spk_sig = decode_buffer(&signed_pre.signature)?;

    let pairing_data = wa::client_payload::DevicePairingRegistrationData {
        e_regid: Some(encode_big_endian(creds.registration_id, 4)),
        e_keytype: Some(vec![5]),
        e_ident: Some(identity_key.public.clone()),
        e_skey_id: Some(encode_big_endian(signed_pre.key_id, 3)),
        e_skey_val: Some(spk_pub),
        e_skey_sig: Some(spk_sig),
        build_hash: Some(app_version_buf),
        device_props: Some(device_props_bytes),
    };

    Ok(wa::ClientPayload {
        username: None,
        passive: Some(false),
        user_agent: Some(wa::client_payload::UserAgent {
            platform: Some(wa::client_payload::user_agent::Platform::Web as i32),
            app_version: Some(wa::client_payload::user_agent::AppVersion {
                primary: Some(WA_VERSION[0]),
                secondary: Some(WA_VERSION[1]),
                tertiary: Some(WA_VERSION[2]),
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
            locale_country_iso31661_alpha2: Some("US".to_string()),
            device_board: None,
            device_exp_id: None,
            device_type: None,
            device_model_type: None,
        }),
        web_info: Some(wa::client_payload::WebInfo {
            ref_token: None,
            version: None,
            webd_payload: None,
            web_sub_platform: Some(wa::client_payload::web_info::WebSubPlatform::WebBrowser as i32),
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
        device_pairing_data: Some(pairing_data),
        product: Some(wa::client_payload::Product::Whatsapp as i32),
        fb_cat: None,
        fb_user_agent: None,
        oc: None,
        lc: None,
        ios_app_extension: None,
        fb_app_id: None,
        fb_device_id: None,
        pull: Some(false),
        padding_bytes: None,
        year_class: None,
        mem_class: None,
        interop_data: None,
        traffic_anonymization: None,
        lid_db_migrated: Some(false),
        account_type: Some(wa::client_payload::AccountType::Default as i32),
    })
}

fn decode_buffer(value: &BufferValue) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use base64::Engine;
    match value {
        BufferValue::Buffer { data, .. } | BufferValue::Raw(data) => Ok(base64::engine::general_purpose::STANDARD
            .decode(data)?),
    }
}
