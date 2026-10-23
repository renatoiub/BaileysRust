//! `Client` — gerenciador de conexão do socket (port do `socket.ts`).
//!
//! Cobre o fluxo completo da Fase 1:
//! - Handshake Noise (ClientHello → ServerHello → ClientFinish).
//! - Emissão de QR (`connection.update { qr }`) e pareamento (`pair-device`).
//! - Login (`CB:success`) e upload de pre-keys.
//! - Keep-alive (`w:p` ping).
//! - Envio e recebimento de mensagens E2E (texto), com `<ack>`/`<receipt>`.
//! - Envio de mídia por conveniência: `send_image`, `send_video`, `send_audio`
//!   (PTT/MP3 via FFmpeg) e `send_document` — upload + E2E num só passo.
//!   O pipeline de baixo nível (`upload_media` + `send_media_message`) também
//!   é público para mídia/lista/contato/localização arbitrária.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use baileys_codec::encode_binary_node;
use baileys_core::constants::{
    INITIAL_PREKEY_COUNT, MIN_PREKEY_COUNT,
};
use baileys_core::ids::{generate_md_tag_prefix, generate_message_id_v2};
use baileys_core::{BinaryContent, BinaryNode, S_WHATSAPP_NET};
use baileys_crypto::Curve;
use baileys_proto::proto as wa;
use baileys_repository::{InjectPreKey, InjectSession, InjectSignedPreKey, SignalRepository, SignalStoreExtension, SqliteSignalStore};
use baileys_signal::protocol::SignalStore;
use baileys_store::creds::AuthenticationCreds;
use baileys_store::sqlite::SQLiteAuthState;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::handshake::{
    configure_successful_pairing, generate_login_node, generate_registration_node, ClientConfig,
};
use crate::noise::NoiseHandler;

/// Presença de um contato (espelha `presence.update` do Baileys).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PresenceData {
    /// JID normalizado do participante.
    pub participant: String,
    /// `available` | `unavailable` | `composing` | `paused` | `recording`.
    pub last_known_presence: String,
    /// Timestamp de último visto (segundos), se o servidor informou.
    pub last_seen: Option<i64>,
}

/// Atualização de um chat (espelha `chats.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ChatUpdate {
    pub id: String,
    pub archived: Option<bool>,
    pub unread_count: Option<i32>,
    /// Timestamp (ms) do pin no app-state; `None` = não fixado.
    pub pinned: Option<i64>,
    /// `muteEndTime` do app-state; `None` = sem mute.
    pub mute_end_time: Option<i64>,
    pub name: Option<String>,
    pub read_only: Option<bool>,
    pub ephemeral_expiration: Option<u32>,
    pub tc_token: Option<Vec<u8>>,
}

/// Contato (espelha `contacts.upsert`/`contacts.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ContactUpsert {
    pub id: String,
    pub name: Option<String>,
    pub lid: Option<String>,
    pub jid: Option<String>,
    pub notify: Option<String>,
    pub verified_name: Option<String>,
    pub img_url: Option<String>,
}

/// Atualização de grupo (espelha `groups.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupUpdate {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrict: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_add_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_approval_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_reason: Option<String>,
}

/// Participante do `group-participants.update` (`{ jid, phone_number }`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GroupParticipantInfo {
    pub jid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
}

/// Atualização de participantes de grupo (espelha `group-participants.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GroupParticipantsUpdate {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub participants: Vec<GroupParticipantInfo>,
    pub action: String,
}

/// `key` de uma atualização (espelha `proto.IMessageKey` serializado).
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageUpdateKey {
    pub remote_jid: String,
    pub id: String,
    pub from_me: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant: Option<String>,
    /// Extras do `WAMessageKey` do Hineken (`...message.key`), em snake_case como no Node.
    #[serde(rename = "sender_lid", skip_serializing_if = "Option::is_none")]
    pub sender_lid: Option<String>,
    #[serde(rename = "participant_pn", skip_serializing_if = "Option::is_none")]
    pub participant_pn: Option<String>,
    #[serde(rename = "participant_lid", skip_serializing_if = "Option::is_none")]
    pub participant_lid: Option<String>,
    #[serde(rename = "sender_pn", skip_serializing_if = "Option::is_none")]
    pub sender_pn: Option<String>,
    #[serde(rename = "peer_recipient_pn", skip_serializing_if = "Option::is_none")]
    pub peer_recipient_pn: Option<String>,
    #[serde(rename = "peer_recipient_lid", skip_serializing_if = "Option::is_none")]
    pub peer_recipient_lid: Option<String>,
}

impl MessageUpdateKey {
    /// `{ ...message.key, id }` — key do envelope (já limpa) com outro id.
    fn from_envelope(key: &wa::MessageKey, extras: &MessageKeyExtras, id: String) -> Self {
        Self {
            remote_jid: key.remote_jid.clone().unwrap_or_default(),
            id,
            from_me: key.from_me.unwrap_or(false),
            participant: key.participant.clone(),
            sender_lid: extras.sender_lid.clone(),
            participant_pn: extras.participant_pn.clone(),
            participant_lid: extras.participant_lid.clone(),
            sender_pn: extras.sender_pn.clone(),
            peer_recipient_pn: extras.peer_recipient_pn.clone(),
            peer_recipient_lid: extras.peer_recipient_lid.clone(),
        }
    }
}

/// `update` do `messages.update` (espelha `WAMessageUpdate.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageUpdateData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_stub_type: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub message_stub_parameters: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_timestamp: Option<u64>,
    /// `update.key` do REVOKE (`key: message.key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<MessageUpdateKey>,
    /// `starAction` do app-state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starred: Option<bool>,
}

/// Atualização de status de mensagem (espelha `messages.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MessageStatusUpdate {
    pub key: MessageUpdateKey,
    pub update: MessageUpdateData,
}

/// Receipt de usuário (espelha `proto.IUserReceipt` serializado).
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserReceipt {
    pub user_jid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_timestamp: Option<i64>,
}

/// Receipt de entrega/leitura (espelha `message-receipt.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MessageReceiptUpdate {
    pub key: MessageUpdateKey,
    pub receipt: UserReceipt,
}

/// Reação a mensagem (espelha `messages.reaction`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MessageReaction {
    pub remote_jid: String,
    pub id: String,
    pub from_me: bool,
    pub text: Option<String>,
    pub sender_timestamp_ms: Option<i64>,
}

/// Histórico sincronizado (espelha `messaging-history.set`).
///
/// `chats` foi removido do payload: as mesmas mensagens já vêm em `messages`
/// (o consumidor só usa `messages`), e carregar `Conversation` duplicava toda
/// a memória do history sync.
#[derive(Debug, Clone, Default)]
pub struct MessagingHistorySet {
    pub contacts: Vec<serde_json::Value>,
    pub messages: Vec<wa::WebMessageInfo>,
    pub is_latest: bool,
    pub progress: u32,
    pub sync_type: i32,
}

/// Chamada (espelha `call` do Baileys).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CallInfo {
    pub chat_id: String,
    pub from: String,
    pub id: String,
    pub caller_pn: Option<String>,
    pub date: Option<i64>,
    pub offline: bool,
    pub status: String,
    pub is_video: bool,
    pub is_group: bool,
    pub group_jid: Option<String>,
}

/// `NO_MESSAGE_FOUND_ERROR_TEXT` do Hineken.
const NO_MESSAGE_FOUND_ERROR_TEXT: &str = "Message absent from node";

/// Retorno do `decodeMessageNode`: `fullMessage` (key crua), `author`,
/// `sender` (`author` em chat 1:1, `chatId` nos demais) e `category`.
struct DecodedMessageNode {
    full: wa::WebMessageInfo,
    author: String,
    sender: String,
    key_extras: MessageKeyExtras,
    category: Option<String>,
}

/// Campos extras do `key` que não existem no proto `MessageKey`
/// (espelha o `WAMessageKey` do Hineken: `sender_lid`, `participant_lid`,
/// `participant_pn`, `sender_pn`, `peer_recipient_pn`, `peer_recipient_lid`).
#[derive(Debug, Clone, Default)]
pub struct MessageKeyExtras {
    pub sender_lid: Option<String>,
    pub participant_lid: Option<String>,
    pub participant_pn: Option<String>,
    pub sender_pn: Option<String>,
    pub peer_recipient_pn: Option<String>,
    pub peer_recipient_lid: Option<String>,
}

/// Eventos emitidos pelo client (espelho do `ev` do Baileys).
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// `connection.update` — estado de conexão.
    ConnectionUpdate(ConnectionUpdate),
    /// `creds.update` — creds alteradas (deve ser persistido).
    CredsUpdate(AuthenticationCreds),
    /// Mensagem recebida e descriptografada (WebMessageInfo + nós brutos).
    Message {
        info: wa::WebMessageInfo,
        raw: BinaryNode,
        key_extras: MessageKeyExtras,
    },
    /// Mensagem que falhou ao descriptografar (nó bruto + motivo). O retry
    /// agora é MANUAL (via manager): não enviamos receipt/PDO automático.
    MessageFailed {
        info: wa::WebMessageInfo,
        raw: BinaryNode,
        reason: String,
    },
    /// QR code disponível para pareamento.
    Qr(String),
    /// `presence.update` / `chatstate` — presença de contatos.
    PresenceUpdate {
        id: String,
        presences: Vec<PresenceData>,
    },
    /// `chats.update` — mudanças em chats (arquivar/ler/pin).
    ChatsUpdate { chats: Vec<ChatUpdate> },
    /// `chats.delete` — chats apagados.
    ChatsDelete { jids: Vec<String> },
    /// `contacts.update` — atualização de contatos.
    ContactsUpdate { contacts: Vec<ContactUpsert> },
    /// `contacts.upsert` — contatos novos/atualizados.
    ContactsUpsert { contacts: Vec<ContactUpsert> },
    /// `groups.upsert` — grupos novos.
    GroupsUpsert { groups: Vec<serde_json::Value> },
    /// `groups.update` — mudanças em grupos.
    GroupsUpdate { updates: Vec<GroupUpdate> },
    /// `group-participants.update` — participantes de grupo.
    GroupParticipantsUpdate { update: GroupParticipantsUpdate },
    /// `messages.update` — atualizações de status/revoque de mensagens.
    MessagesUpdate { updates: Vec<MessageStatusUpdate> },
    /// `message-receipt.update` — receipts em grupos/broadcast.
    MessageReceiptUpdate { updates: Vec<MessageReceiptUpdate> },
    /// `messages.reaction` — reações a mensagens.
    MessagesReaction { reactions: Vec<MessageReaction> },
    /// `messaging-history.set` — histórico sincronizado (history sync).
    MessagingHistorySet { data: MessagingHistorySet },
    /// `call` — eventos de chamada (parsed para webhook + nós brutos para
    /// o CallManager/player bridge).
    Call { calls: Vec<CallInfo>, raw_nodes: Vec<BinaryNode> },
    /// `CB:receipt` com `type=retry` (nó bruto) — o app pode montar o
    /// `retryRelay` como o container Node.
    RetryReceipt { node: BinaryNode },
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionUpdate {
    pub connection: String,
    pub qr: Option<String>,
    pub is_new_login: bool,
    pub received_pending_notifications: bool,
    /// Código de desconexão (espelha `lastDisconnect.error.output.statusCode`).
    pub status_code: Option<i32>,
    /// Motivo textual (espelha `reason` do stream error / failure).
    pub reason: Option<String>,
}

/// Resultado do envio de mensagem.
#[derive(Debug, Clone)]
pub struct SendMessageResult {
    pub message_id: String,
}

/// Participante-alvo de um relay (retry) — port do `{ jid, count }` do Node
/// (`MessageRelayOptions.participant`).
#[derive(Debug, Clone)]
pub struct RelayParticipant {
    pub jid: String,
    pub count: u32,
}

/// Parâmetros configuráveis do retry manual (`/manager/retry`).
///
/// Espelha o `sendRetryRequest` do Hineken, mas com todos os campos do nó
/// editáveis pelo operador:
/// - `to`            → `receipt.attrs.to` (destino do receipt; ex: o `from` do
///   nó original, ou o participant LID para status/group).
/// - `participant`   → `receipt.attrs.participant` (opcional).
/// - `recipient`     → `receipt.attrs.recipient` (opcional).
/// - `retry_count`   → `retry.count`.
/// - `force_include_keys` → inclui o bundle `<keys>` (type 05 + identity +
///   pre-key + skey + device-identity).
/// - `assert_session`     → roda `assert_sessions(force=true)` antes de enviar.
#[derive(Debug, Clone, Default)]
pub struct DebugRetryParams {
    pub msg_id: String,
    pub to: String,
    pub participant: Option<String>,
    pub recipient: Option<String>,
    pub retry_count: u32,
    pub retry_id: Option<String>,
    pub retry_t: Option<String>,
    pub force_include_keys: bool,
    pub assert_session: bool,
}

/// Resultado do upload de mídia.
#[derive(Debug, Clone)]
pub struct MediaUpload {
    pub media_key: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
    pub media_url: String,
    pub direct_path: String,
}

type PendingQuery = tokio::sync::oneshot::Sender<BinaryNode>;

use crate::cache::TtlCache;

/// Sink de escrita do WebSocket (compartilhado entre `run` e as operações).
pub type WsSink = Arc<
    Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
            WsMessage,
        >,
    >,
>;

/// Callback de persistência de mensagem enviada (port do `saveMessage` que o
/// app fornece ao Hineken). `(msg_id, destino, Message codificado)`.
pub type SaveMessageFn = Arc<
    dyn Fn(String, String, Vec<u8>) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync,
>;

/// Callback de recuperação de mensagem enviada (port do `getMessage` do
/// Hineken). `(msg_id, remote_jid)` → `Message` codificado (ou `None`).
pub type LoadMessageFn = Arc<
    dyn Fn(String, String) -> futures_util::future::BoxFuture<'static, Option<Vec<u8>>> + Send + Sync,
>;

/// `patchMessageBeforeSending` do `SocketConfig` (default: identidade).
pub type PatchMessageFn = Arc<dyn Fn(wa::Message) -> wa::Message + Send + Sync>;

/// Cliente do socket WhatsApp.
pub struct Client {
    store: Arc<SqliteSignalStore>,
    config: ClientConfig,

    epoch: AtomicU32,
    tag_prefix: String,
    pending_queries: Mutex<HashMap<String, PendingQuery>>,
    events: tokio::sync::broadcast::Sender<ClientEvent>,
    /// Sink do WebSocket ativo (definido após `run` conectar).
    sink: Mutex<Option<WsSink>>,
    /// NoiseHandler compartilhado (definido após `run` conectar). Usado para
    /// criptografar todos os envios (igual ao `sendRawMessage` do Node).
    noise: Mutex<Option<Arc<Mutex<NoiseHandler>>>>,
    /// Último código de desconexão (para o loop de reconnect do container).
    last_close_code: AtomicI32,
    /// `true` entre o `connection: "open"` e o `connection: "close"`.
    open: std::sync::atomic::AtomicBool,
    /// Versão do WhatsApp Web do handshake (`version` do `makeWASocket`);
    /// vale a partir da próxima conexão.
    wa_version: std::sync::RwLock<[u32; 3]>,
    /// Handle da task de rotação de QR (para cancelar ao parear).
    qr_rotation: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// A rotação esgotou os refs e fechou o socket (`QR refs attempts ended`).
    qr_refs_ended: Arc<std::sync::atomic::AtomicBool>,
    /// Acorda o loop de leitura quando os refs de QR acabam.
    qr_close: Arc<tokio::sync::Notify>,
    /// JIDs cuja sessão E2E já foi forçada uma vez (port de `caches.forceSession`).
    force_session_cache: TtlCache<()>,
    /// Mutex de retry (port de `retryMutex` do Node) — serializa o
    /// processamento de `<receipt type="retry">` concorrentes.
    retry_mutex: Mutex<()>,
    /// Contador de retries por mensagem (port de `caches.msgRetryCache`).
    msg_retry_cache: TtlCache<u32>,
    /// `placeholderResendCache` — evita PDOs duplicados para o mesmo msg id.
    placeholder_resend_cache: TtlCache<()>,
    /// `lidCache` — mapeia `@s.whatsapp.net` → `@lid` (evita USync repetido).
    lid_cache: TtlCache<String>,
    /// `devicesCache` — fanout de devices por JID (evita USync repetido).
    devices_cache: TtlCache<Vec<(String, u32, String)>>,
    /// `onWhatsapp` — existência no WhatsApp por JID.
    on_whatsapp_cache: TtlCache<bool>,
    /// `sender-key-memory` — mapa `senderId → true` por grupo, port do
    /// `authState.keys.set({ 'sender-key-memory': { [jid]: senderKeyMap } })`
    /// do Node (memória da distribuição de sender key por grupo).
    sender_key_memory: TtlCache<HashMap<String, bool>>,
    /// `profilePicture` — URLs de foto de perfil por JID.
    profile_picture_cache: TtlCache<String>,
    /// `groupMetaCache` — metadados de grupo por JID.
    group_meta_cache: TtlCache<crate::groups::GroupMetadata>,
    /// Callback de persistência de mensagem enviada (fornecido pelo app).
    save_message_fn: Mutex<Option<SaveMessageFn>>,
    /// Callback de recuperação de mensagem enviada (fornecido pelo app).
    load_message_fn: Mutex<Option<LoadMessageFn>>,
    /// `patchMessageBeforeSending` (fornecido pelo app).
    patch_message_fn: std::sync::Mutex<Option<PatchMessageFn>>,
    /// `sendActiveReceipts` — segue o `isOnline` do `sendPresenceUpdate`.
    send_active_receipts: std::sync::atomic::AtomicBool,
    /// Cache do `fetchPrivacySettings`.
    privacy_settings: Mutex<Option<HashMap<String, String>>>,
    /// `pendingAppStateSync` do `upsertMessage` (history sync sem `myAppStateKeyId`).
    pending_app_state_sync: std::sync::atomic::AtomicBool,
    /// Serializa o `resyncAppState` (o Node roda dentro de `keys.transaction`).
    app_state_mutex: Mutex<()>,
}

impl Client {
    /// Abre (ou cria) uma sessão no diretório `db/{key}` e prepara o client.
    pub fn new(session_folder: impl AsRef<std::path::Path>, config: ClientConfig) -> Result<Self, ClientError> {
        let sqlite = Arc::new(SQLiteAuthState::open(session_folder)?);
        if sqlite.read_creds()?.is_none() {
            let creds = baileys_store::creds::init_auth_creds();
            sqlite.save_creds(&creds)?;
        }
        let store = Arc::new(SqliteSignalStore::new(sqlite.clone())?);
        // Folga para a rajada de mensagens offline no reconnect: um receiver
        // que fica para trás perde eventos (`Lagged`).
        let (events, _) = tokio::sync::broadcast::channel(4096);

        let client = Self {
            store,
            config,
            epoch: AtomicU32::new(1),
            tag_prefix: generate_md_tag_prefix(),
            pending_queries: Mutex::new(HashMap::new()),
            events,
            sink: Mutex::new(None),
            noise: Mutex::new(None),
            last_close_code: AtomicI32::new(0),
            open: std::sync::atomic::AtomicBool::new(false),
            wa_version: std::sync::RwLock::new(baileys_core::constants::WA_VERSION),
            qr_rotation: Mutex::new(None),
            qr_refs_ended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            qr_close: Arc::new(tokio::sync::Notify::new()),
            force_session_cache: TtlCache::new(Duration::from_secs(600), 2000),
            retry_mutex: Mutex::new(()),
            msg_retry_cache: TtlCache::new(Duration::from_secs(3600), 2000).with_flush_tracking(),
            placeholder_resend_cache: TtlCache::new(Duration::from_secs(3600), 2000),
            lid_cache: TtlCache::new(Duration::from_secs(3600), 2000),
            devices_cache: TtlCache::new(Duration::from_secs(1000), 2000),
            on_whatsapp_cache: TtlCache::new(Duration::from_secs(7200), 1000),
            sender_key_memory: TtlCache::new(Duration::from_secs(86400), 2000),
            profile_picture_cache: TtlCache::new(Duration::from_secs(7200), 1000),
            group_meta_cache: TtlCache::new(Duration::from_secs(3600), 1000),
            save_message_fn: Mutex::new(None),
            load_message_fn: Mutex::new(None),
            patch_message_fn: std::sync::Mutex::new(None),
            send_active_receipts: std::sync::atomic::AtomicBool::new(false),
            privacy_settings: Mutex::new(None),
            pending_app_state_sync: std::sync::atomic::AtomicBool::new(false),
            app_state_mutex: Mutex::new(()),
        };
        client.apply_cache_config();
        Ok(client)
    }

    /// Aplica `cache_control`/`cache_provider` do `ClientConfig`.
    ///
    /// - Compartilháveis (`cache:global:*`, mesmos dados para qualquer
    ///   conexão): metadados de grupo, LID, onWhatsApp, foto e devices.
    ///   Seguem o `cache_control`.
    /// - Por conexão (`cache:instance:{key}:*`): sender-key-memory, retry e
    ///   placeholder — estado do protocolo, sempre ligados.
    /// - `forceSession` fica só em memória (`NodeCache` do Node), como antes.
    fn apply_cache_config(&self) {
        let enabled = self.config.cache_control;
        self.lid_cache.set_enabled(enabled);
        self.devices_cache.set_enabled(enabled);
        self.on_whatsapp_cache.set_enabled(enabled);
        self.profile_picture_cache.set_enabled(enabled);
        self.group_meta_cache.set_enabled(enabled);

        let Some(provider) = self.config.cache_provider.clone() else {
            return;
        };
        self.lid_cache.set_backend("cache:global:lid", Some(provider.clone()));
        self.devices_cache.set_backend("cache:global:devices", Some(provider.clone()));
        self.on_whatsapp_cache.set_backend("cache:global:onwhatsapp", Some(provider.clone()));
        self.profile_picture_cache.set_backend("cache:global:profilepic", Some(provider.clone()));
        self.group_meta_cache.set_backend("cache:global:groupmeta", Some(provider.clone()));

        if let Some(instance_key) = self.config.cache_instance_key.as_deref().filter(|k| !k.is_empty()) {
            self.sender_key_memory
                .set_backend(&format!("cache:instance:{instance_key}:senderkey"), Some(provider.clone()));
            self.msg_retry_cache
                .set_backend(&format!("cache:instance:{instance_key}:msgretry"), Some(provider.clone()));
            self.placeholder_resend_cache
                .set_backend(&format!("cache:instance:{instance_key}:placeholder"), Some(provider));
        }
    }

    /// Último código de desconexão (0 = nunca desconectou).
    pub fn last_close_code(&self) -> i32 {
        self.last_close_code.load(Ordering::SeqCst)
    }

    /// Versão do WhatsApp Web usada no próximo handshake.
    pub fn wa_version(&self) -> [u32; 3] {
        *self.wa_version.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Troca a versão do WhatsApp Web; vale a partir da próxima conexão.
    pub fn set_wa_version(&self, version: [u32; 3]) {
        *self.wa_version.write().unwrap_or_else(|e| e.into_inner()) = version;
    }

    /// Conexão logada e aberta (`connection: "open"` sem `close` depois).
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    /// Assina o fluxo de eventos.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ClientEvent> {
        self.events.subscribe()
    }

    /// Credenciais atuais.
    pub fn creds(&self) -> AuthenticationCreds {
        self.store.creds()
    }

    /// O repositório Signal (para uso avançado).
    pub fn signal_store(&self) -> Arc<SqliteSignalStore> {
        self.store.clone()
    }

    /// Sink de escrita ativo (para o container dirigir envios). `None` se
    /// `run` ainda não conectou.
    pub async fn sink(&self) -> Option<WsSink> {
        self.sink.lock().await.clone()
    }

    /// JID do `me` (normalizado) — vazio se ainda não pareou.
    pub fn me_id(&self) -> String {
        self.store.creds().me.map(|m| m.id).unwrap_or_default()
    }

    /// LID do `me` — vazio se ainda não pareou.
    pub fn me_lid(&self) -> String {
        self.store
            .creds()
            .me
            .and_then(|m| m.lid)
            .unwrap_or_default()
    }

    /// Registra os callbacks de store de mensagens (port do `getMessage`/
    /// `saveMessage` que o app fornece ao Hineken). Chamado pelo container
    /// ao criar a instância.
    pub async fn set_message_store(&self, save: SaveMessageFn, load: LoadMessageFn) {
        *self.save_message_fn.lock().await = Some(save);
        *self.load_message_fn.lock().await = Some(load);
    }

    /// Define o `patchMessageBeforeSending` (aplicado como no `relayMessage`).
    pub fn set_patch_message(&self, patch: PatchMessageFn) {
        *self.patch_message_fn.lock().unwrap() = Some(patch);
    }

    fn patch_message(&self, message: &wa::Message) -> wa::Message {
        match self.patch_message_fn.lock().unwrap().clone() {
            Some(patch) => patch(message.clone()),
            None => message.clone(),
        }
    }

    /// Registra uma extensão de armazenamento de chaves de sinal (ex. Redis
    /// do app). Encaminha para o `SqliteSignalStore` (session/sender-key/
    /// pre-key via `load`/`store`/`remove`).
    pub fn set_store_extension(&self, ext: Arc<dyn SignalStoreExtension>) {
        self.store.set_extension(ext);
    }

    /// Criptografa uma mensagem E2E para um JID (usado pelo CallManager).
    pub fn encrypt_for(&self, jid: &str, data: &[u8]) -> Result<(String, Vec<u8>), ClientError> {
        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
        let me_id = self.me_id();
        let me_lid = if self.me_lid().is_empty() { me_id.clone() } else { self.me_lid() };
        let dest = convert_lid_device(jid, None, &me_id, &me_lid);
        let enc = repo.encrypt_message(&dest, data)?;
        Ok((enc.r#type, enc.ciphertext))
    }

    /// Descriptografa uma mensagem E2E de um JID (usado pelo CallManager).
    pub fn decrypt_for(&self, jid: &str, enc_type: &str, data: &[u8]) -> Result<Vec<u8>, ClientError> {
        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
        Ok(repo.decrypt_message(jid, enc_type, data)?)
    }

    /// Conecta e processa o fluxo até o socket fechar (retorna o erro ou `Ok`).
    ///
    /// Ao sair (por erro ou fim do stream), grava `last_close_code` e emite
    /// `ConnectionUpdate { connection: "close", status_code, reason }` — igual
    /// ao `connection.update { connection: 'close', lastDisconnect }` do Node.
    pub async fn run(self: Arc<Self>) -> Result<(), ClientError> {
        self.qr_refs_ended.store(false, Ordering::SeqCst);
        let result = self.clone().run_inner().await;
        self.cancel_qr_rotation().await;
        let (status_code, reason) = if self.qr_refs_ended.load(Ordering::SeqCst) {
            // `end(new Boom('QR refs attempts ended', { statusCode: timedOut }))`.
            (Self::WS_CONNECTION_LOST, "qrRefsEnded".to_string())
        } else {
            match &result {
                Ok(()) => (Self::WS_CONNECTION_CLOSED, "connectionClosed".to_string()),
                Err(e) => self.error_to_close(e),
            }
        };
        self.last_close_code.store(status_code, Ordering::SeqCst);
        self.open.store(false, Ordering::SeqCst);
        *self.sink.lock().await = None;
        let _ = self.events.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
            connection: "close".to_string(),
            status_code: Some(status_code),
            reason: Some(reason),
            ..Default::default()
        }));
        result
    }

    async fn run_inner(self: Arc<Self>) -> Result<(), ClientError> {
        let url = format!(
            "wss://web.whatsapp.com/ws/chat{}",
            self.routing_query().await
        );
        tracing::debug!(url, "conectando ao WhatsApp");

        let (ws_stream, _) = connect_async(&url).await.map_err(ClientError::WebSocket)?;
        let (sink, stream) = ws_stream.split();
        let sink: WsSink = Arc::new(Mutex::new(sink));
        *self.sink.lock().await = Some(sink.clone());
        let mut stream = stream;

        let ephemeral = Curve::generate_key_pair();
        let noise = Arc::new(Mutex::new(NoiseHandler::new(ephemeral.clone(), self.routing_info())));
        *self.noise.lock().await = Some(noise.clone());

        // 1. ClientHello.
        let hello = crate::noise::client_hello(&ephemeral.public);
        {
            let mut n = noise.lock().await;
            let frame = n.encode_frame(&hello)?;
            let mut sink = sink.lock().await;
            sink.send(WsMessage::Binary(frame)).await.map_err(ClientError::WebSocket)?;
        }

        let noise_key = self.store.creds().noise_key_pair();
        let mut handshake_done = false;
        let mut connected = false;

        // Keep-alive: a cada `keep_alive_interval_ms`, envia um ping `w:p`
        // (igual ao Node). Sem isso, o servidor derruba com `stream:error { ping }`
        // após ~30s de inatividade. O envio passa pelo Noise (encode_frame).
        let keepalive_sink = sink.clone();
        let keepalive_noise = noise.clone();
        let keepalive_interval = self.config.keep_alive_interval_ms;
        let keepalive_guard = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(keepalive_interval)).await;
                let ping = BinaryNode::new("iq")
                    .with_attr("id", baileys_core::ids::generate_message_id_v2(None))
                    .with_attr("to", S_WHATSAPP_NET)
                    .with_attr("type", "get")
                    .with_attr("xmlns", "w:p")
                    .with_children(vec![BinaryNode::new("ping")]);
                let bytes = encode_binary_node(&ping);
                let frame = match keepalive_noise.lock().await.encode_frame(&bytes) {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let mut sink = keepalive_sink.lock().await;
                if sink.send(WsMessage::Binary(frame)).await.is_err() {
                    break;
                }
            }
        });

        loop {
            // O fim dos refs de QR fecha o sink; não depende do servidor
            // responder ao close para sair do loop.
            let next = tokio::select! {
                m = stream.next() => m,
                _ = self.qr_close.notified() => None,
            };
            let Some(msg) = next else {
                break;
            };
            let msg = msg.map_err(ClientError::WebSocket)?;
            let WsMessage::Binary(data) = msg else {
                continue;
            };

            let mut pending_frames: Vec<BinaryNode> = Vec::new();
            {
                let mut n = noise.lock().await;
                let mut server_hello: Option<Vec<u8>> = None;

                n.decode_frame(&data, &mut |frame| match frame {
                    crate::noise::Frame::Raw(bytes) => {
                        if !handshake_done {
                            server_hello = Some(bytes);
                        }
                    }
                    crate::noise::Frame::Node(node) => pending_frames.push(node),
                })?;

                if let Some(bytes) = server_hello {
                    let server_hello = crate::noise::parse_server_hello(&bytes)?;
                    let key_enc = n.process_handshake(&server_hello, &noise_key).await?;

                    let creds = self.store.creds();
                    let wa_version = self.wa_version();
                    let payload = match &creds.me {
                        Some(me) => generate_login_node(&me.id, &self.config, wa_version),
                        None => generate_registration_node(&creds, &self.config, wa_version),
                    };
                    let payload_enc = n.encrypt(&payload.encode_to_vec())?;

                    let finish = wa::HandshakeMessage {
                        client_hello: None,
                        server_hello: None,
                        client_finish: Some(wa::handshake_message::ClientFinish {
                            r#static: Some(key_enc),
                            payload: Some(payload_enc),
                        }),
                    };
                    let frame = n.encode_frame(&finish.encode_to_vec())?;
                    let mut sink = sink.lock().await;
                    sink.send(WsMessage::Binary(frame))
                        .await
                        .map_err(ClientError::WebSocket)?;
                    n.finish_init().await?;
                    handshake_done = true;
                    tracing::debug!("handshake Noise completo");
                }
            }

            for node in pending_frames {
                self.handle_node(&node, &sink, &noise, &mut connected).await?;
            }

            if connected {
                // Continua processando; o `run` só termina quando o stream acaba.
            }
        }

        keepalive_guard.abort();
        Ok(())
    }

    /// Códigos de desconexão (espelha `DisconnectReason` do Baileys).
    pub const WS_CONNECTION_CLOSED: i32 = 428;
    const WS_CONNECTION_LOST: i32 = 408;

    /// Converte um erro do `run` em `(status_code, reason)`.
    fn error_to_close(&self, e: &ClientError) -> (i32, String) {
        match e {
            ClientError::StreamError { code, .. } => (*code, "streamError".to_string()),
            ClientError::Failure { code } => (*code, "failure".to_string()),
            ClientError::ConnectionClosed => (Self::WS_CONNECTION_CLOSED, "connectionClosed".to_string()),
            ClientError::MultiDeviceMismatch => (411, "multideviceMismatch".to_string()),
            ClientError::WebSocket(e) => {
                let text = e.to_string();
                if text.contains("timed out") || text.contains("ETIMEDOUT") || text.contains("ENOTFOUND") {
                    (Self::WS_CONNECTION_LOST, "connectionLost".to_string())
                } else {
                    (Self::WS_CONNECTION_CLOSED, "connectionClosed".to_string())
                }
            }
            _ => (Self::WS_CONNECTION_CLOSED, "connectionClosed".to_string()),
        }
    }

    fn routing_info(&self) -> Option<Vec<u8>> {
        let creds = self.store.creds();
        creds.routing_info.as_ref().map(|v| match v {
            baileys_store::creds::BufferValue::Buffer { data, .. }
            | baileys_store::creds::BufferValue::Raw(data) => {
                base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default()
            }
        })
    }

    async fn routing_query(&self) -> String {
        match self.routing_info() {
            Some(bytes) => {
                let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
                format!("?ED={b64url}")
            }
            None => String::new(),
        }
    }

    /// Processa um nó binário de entrada.
    async fn handle_node(
        self: &Arc<Self>,
        node: &BinaryNode,
        sink: &WsSink,
        noise: &Arc<Mutex<NoiseHandler>>,
        connected: &mut bool,
    ) -> Result<(), ClientError> {
        let tag = node.tag.clone();

        // Resposta a uma query pendente (qualquer id registrado em pending_queries).
        if let Some(id) = node.attr("id") {
            if self.pending_queries.lock().await.contains_key(id) {
                if let Some(tx) = self.pending_queries.lock().await.remove(id) {
                    let _ = tx.send(node.clone());
                    return Ok(());
                }
            }
        }

        let l2 = match &node.content {
            Some(BinaryContent::Children(children)) => children.first().map(|c| c.tag.clone()).unwrap_or_default(),
            _ => String::new(),
        };

        tracing::debug!(tag = %tag, l2 = %l2, type_ = ?node.attr("type"), xmlns = ?node.attr("xmlns"), from = ?node.attr("from"), id = ?node.attr("id"), "nó recebido");

        // Keep-alive: responder a pings `w:p` (com filho `ping`) e
        // `urn:xmpp:ping` (XMPP padrão, sem filho). Sem resposta, o servidor
        // derruba a conexão com `stream:error { ping }` em ~30s.
        if tag == "iq"
            && node.attr("type") == Some("get")
            && (node.attr("xmlns") == Some("w:p") || node.attr("xmlns") == Some("urn:xmpp:ping"))
        {
            let pong = BinaryNode::new("iq")
                .with_attr("to", S_WHATSAPP_NET)
                .with_attr("type", "result")
                .with_attr("id", node.attr("id").unwrap_or_default());
            self.send_node(&pong, sink).await?;
            return Ok(());
        }

        // `CB:iq,type:set,pair-device` → QR.
        if tag == "iq"
            && node.attr("type") == Some("set")
            && node.child("pair-device").is_some()
        {
            self.handle_pair_device(node, sink).await?;
            return Ok(());
        }

        // `CB:iq,,pair-success`.
        if tag == "iq" && node.child("pair-success").is_some() {
            self.handle_pair_success(node, sink).await?;
            return Ok(());
        }

        // `CB:success`.
        if tag == "success" {
            // Roda o login em task separada: `handle_success` faz upload de
            // pre-keys via `query_node`, que aguarda a resposta do servidor.
            // Se rodasse aqui (no loop de leitura), o loop ficaria bloqueado
            // esperando a resposta que só é lida pelo próprio loop — deadlock
            // que deixava o aparelho "conectando..." para sempre.
            let client = self.clone();
            let node = node.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                if let Err(e) = client.handle_success(&node, &sink).await {
                    tracing::warn!(error = %e, "falha ao concluir login (success)");
                }
            });
            *connected = true; // o estado ONLINE vem do evento `connection.open`
            return Ok(());
        }

        // `CB:stream:error`.
        if tag == "stream:error" {
            let code = node
                .attr("code")
                .and_then(|c| c.parse::<i32>().ok())
                .unwrap_or_else(|| {
                    // Mapeia filho `conflict` → 440; senão badSession.
                    if node.child("conflict").is_some() {
                        440
                    } else {
                        500
                    }
                });
            return Err(ClientError::StreamError {
                code,
                detail: format!("{node:?}"),
            });
        }

        // `CB:failure` — pode ser logout/falha de login.
        if tag == "failure" {
            let code = node.attr("reason").and_then(|r| r.parse::<i32>().ok()).unwrap_or(500);
            return Err(ClientError::Failure { code });
        }

        // `CB:ib,,downgrade_webclient`.
        if tag == "ib" && l2 == "downgrade_webclient" {
            return Err(ClientError::MultiDeviceMismatch);
        }

        // `CB:ib,,edge_routing` → routingInfo.
        if tag == "ib" && l2 == "edge_routing" {
            self.handle_edge_routing(node).await;
            return Ok(());
        }

        // `CB:ib,,offline_preview` → responde pedindo o lote offline. Sem isso,
        // o servidor NÃO entrega mensagens acumuladas enquanto a sessão estava
        // offline (e em alguns casos para de entregar mensagens novas também).
        if tag == "ib" && l2 == "offline_preview" {
            let batch = BinaryNode::new("ib").with_children(vec![
                BinaryNode::new("offline_batch").with_attr("count", "100"),
            ]);
            self.send_node(&batch, sink).await?;
            tracing::debug!("offline_preview recebido; pedi lote offline (count=100)");
            return Ok(());
        }

        // `CB:ib,,offline` → servidor terminou de entregar as notificações
        // pendentes (offline). Apenas registra; as mensagens chegam como
        // stanzas `message` comuns logo em seguida.
        if tag == "ib" && l2 == "offline" {
            let count = node
                .child("offline")
                .and_then(|c| c.attr("count"))
                .unwrap_or("0");
            tracing::debug!(count, "offline: servidor entregou notificações pendentes");
            return Ok(());
        }

        // `CB:ib,,dirty` → sincronização pendente (account_sync/groups). O
        // payload em si não bloqueia a entrega de mensagens; registramos para
        // diagnóstico e seguimos.
        if tag == "ib" && l2 == "dirty" {
            let dtype = node
                .child("dirty")
                .and_then(|c| c.attr("type"))
                .unwrap_or("unknown");
            tracing::debug!(r#type = dtype, "dirty: sincronização pendente recebida");
            return Ok(());
        }

        // `CB:xmlstreamend`.
        if tag == "xmlstreamend" {
            return Err(ClientError::ConnectionClosed);
        }

        // Call offer (tag `call`, filho `offer`) — sem ack, o servidor
        // derruba a conexão com `stream:error 500` carregando
        // `<ack class="call" type="offer" ...>`.
        if tag == "call" && l2 == "offer" {
            let ack = BinaryNode::new("ack")
                .with_attr("id", node.attr("id").unwrap_or_default())
                .with_attr("to", node.attr("from").unwrap_or_default())
                .with_attr("class", "call")
                .with_attr("type", "offer");
            self.send_node(&ack, sink).await?;
            tracing::debug!(from = ?node.attr("from"), "call offer acked");
            return Ok(());
        }

        // Receipt (delivery/read/retry).
        if tag == "receipt" {
            // Node: `handleReceipt` roda em try/catch — erros de query (ex:
            // `query timed out` no assertSessions do retry do device 0) NÃO
            // derrubam a conexão.
            if node.attr("type") == Some("retry") {
                // Retry faz query (`<iq encrypt>` no assert_sessions) e deve
                // rodar em task separada: se rodasse inline, o loop de
                // leitura ficaria bloqueado esperando a resposta que só ele
                // mesmo poderia entregar (mesmo deadlock do handle_success).
                let client = self.clone();
                let node = node.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    if let Err(e) = client.handle_receipt(&node, &sink).await {
                        tracing::warn!(error = %e, "erro ao processar receipt (não fatal)");
                    }
                });
            } else if let Err(e) = self.handle_receipt(node, sink).await {
                tracing::warn!(error = %e, "erro ao processar receipt (não fatal)");
            }
            return Ok(());
        }

        // `CB:ack,class:message` → `handleBadAck`.
        if tag == "ack" && node.attr("class") == Some("message") {
            self.handle_bad_ack(node, sink).await?;
            return Ok(());
        }

        // Mensagem de entrada.
        if tag == "message" {
            if let Err(e) = self.handle_message(node, sink).await {
                tracing::warn!(error = %e, "erro ao processar mensagem (não fatal)");
            }
            return Ok(());
        }

        // Notificação de pre-keys baixas.
        if tag == "notification" || (tag == "iq" && node.attr("xmlns") == Some("encrypt")) {
            // Se for a notificação `count` (pre-keys baixas), o upload roda em
            // task separada: `upload_pre_keys` faz `query_node` (aguarda a
            // resposta do servidor). Inline no loop de leitura = deadlock que
            // fechava o socket com `query timed out` após 40s (mesmo bug do
            // handle_success/retry).
            let from = node.attr("from").unwrap_or_default();
            let needs_upload = from == S_WHATSAPP_NET
                && node
                    .child("count")
                    .and_then(|c| c.attr("value"))
                    .and_then(|v| v.parse::<i64>().ok())
                    .map(|count| count < MIN_PREKEY_COUNT as i64)
                    .unwrap_or(false);
            if needs_upload {
                let client = self.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    if let Err(e) = client.upload_pre_keys(INITIAL_PREKEY_COUNT, &sink).await {
                        tracing::warn!(error = %e, "falha ao fazer upload de pre-keys (não fatal)");
                    }
                });
            }
            // `processNotification` por `type` (o ack sai no `finally`).
            if tag == "notification" {
                match node.attr("type") {
                    Some("w:gp2") => self.handle_group_notification(node).await,
                    Some("devices") => self.handle_devices_notification(node, sink).await,
                    Some("privacy_token") => self.handle_privacy_token_notification(node),
                    Some("server_sync") => {
                        // `resyncAppState([name], false)` — fora do loop de leitura (faz query).
                        if let Some(name) = node.child("collection").and_then(|c| c.attr("name")) {
                            let name = name.to_string();
                            let client = self.clone();
                            let sink = sink.clone();
                            tokio::spawn(async move {
                                if let Err(e) = client.resync_app_state(&[name.as_str()], false, &sink).await {
                                    tracing::warn!(error = %e, name, "server_sync resync falhou");
                                }
                            });
                        }
                    }
                    _ => {}
                }
            }
            self.handle_encrypt_notification(node, sink, noise).await?;
            return Ok(());
        }

        // Presence (`CB:presence`) e chatstate (`CB:chatstate`).
        if tag == "presence" {
            self.handle_presence(node);
            return Ok(());
        }
        if tag == "chatstate" {
            self.handle_chatstate(node);
            return Ok(());
        }

        // Chats (`chats.update`/`chats.delete`) — nós `<chat>`.
        if tag == "chat" {
            self.handle_chat_node(node);
            return Ok(());
        }

        // Contatos (`contacts.update`/`contacts.upsert`) — nós `<contact>`.
        if tag == "contact" {
            self.handle_contact_node(node);
            return Ok(());
        }

        // Call (`call` com `<offer>`) — além do ack acima, emite o evento
        // `ClientEvent::Call` para o webhook e o call-player.
        if tag == "call" {
            self.handle_call_node(node);
            return Ok(());
        }

        tracing::debug!(tag, l2, "nó não tratado");
        Ok(())
    }

    /// Port de `presence.update` (CB:presence) — `<presence type="...">`.
    fn handle_presence(&self, node: &BinaryNode) {
        let from = node.attr("from").unwrap_or_default().to_string();
        let last_known_presence = node.attr("type").unwrap_or("unavailable").to_string();
        let last_seen = node.attr("last").and_then(|v| v.parse::<i64>().ok());
        // O Node usa o `participant` do próprio attrs ou o `from`.
        let participant = node.attr("participant").map(String::from).unwrap_or_else(|| from.clone());
        let presence = PresenceData {
            participant,
            last_known_presence,
            last_seen,
        };
        let _ = self.events.send(ClientEvent::PresenceUpdate {
            id: from,
            presences: vec![presence],
        });
    }

    /// Port de `presence.update` para `CB:chatstate` (composing/paused/recording).
    fn handle_chatstate(&self, node: &BinaryNode) {
        let from = node.attr("from").unwrap_or_default().to_string();
        // chatstate: o filho `<composing>|<paused>|<recording>` define o estado.
        let state = if node.child("composing").is_some() {
            "composing"
        } else if node.child("paused").is_some() {
            "paused"
        } else if node.child("recording").is_some() {
            "recording"
        } else {
            "available"
        };
        let presence = PresenceData {
            participant: from.clone(),
            last_known_presence: state.to_string(),
            last_seen: None,
        };
        let _ = self.events.send(ClientEvent::PresenceUpdate {
            id: from,
            presences: vec![presence],
        });
    }

    /// Port de `chats.update`/`chats.delete` a partir de nós `<chat>`.
    fn handle_chat_node(&self, node: &BinaryNode) {
        let from = node.attr("from").unwrap_or_default().to_string();
        let chat_type = node.attr("type").unwrap_or_default().to_string();

        // `chats.delete` (type="delete") ou `<chat jid>` marcado para remoção.
        if chat_type == "delete" {
            let jids = match &node.content {
                Some(baileys_core::BinaryContent::Children(children)) => children
                    .iter()
                    .filter_map(|c| c.attr("jid").map(String::from))
                    .collect(),
                _ => Vec::new(),
            };
            if !jids.is_empty() {
                let _ = self.events.send(ClientEvent::ChatsDelete { jids });
            }
            return;
        }

        let update = ChatUpdate {
            id: from,
            archived: node.attr("archive").and_then(|v| v.parse::<bool>().ok()),
            unread_count: node.attr("count").and_then(|v| v.parse::<i32>().ok()),
            pinned: node.attr("pin").and_then(|v| v.parse::<i64>().ok()),
            mute_end_time: None,
            name: node.attr("name").map(String::from),
            read_only: node.attr("read_only").and_then(|v| v.parse::<bool>().ok()),
            ephemeral_expiration: node
                .attr("ephemeral")
                .and_then(|v| v.parse::<u32>().ok()),
            tc_token: node.child_bytes("tc_token").map(|b| b.to_vec()),
        };
        let _ = self.events.send(ClientEvent::ChatsUpdate {
            chats: vec![update],
        });
    }

    /// Port de `contacts.update`/`contacts.upsert` a partir de nós `<contact>`.
    fn handle_contact_node(&self, node: &BinaryNode) {
        let id = node.attr("jid").unwrap_or_default().to_string();
        if id.is_empty() {
            return;
        }
        let contact = ContactUpsert {
            id: id.clone(),
            name: node.attr("name").map(String::from),
            lid: node.attr("lid").map(String::from),
            jid: Some(id),
            notify: node.attr("notify").map(String::from),
            verified_name: node.attr("verify").map(String::from),
            img_url: node.attr("img_url").map(String::from),
        };
        // `contacts.update` (update="true") vs `contacts.upsert` (padrão).
        if node.attr("update").and_then(|v| v.parse::<bool>().ok()).unwrap_or(false) {
            let _ = self.events.send(ClientEvent::ContactsUpdate {
                contacts: vec![contact],
            });
        } else {
            let _ = self.events.send(ClientEvent::ContactsUpsert {
                contacts: vec![contact],
            });
        }
    }

    /// Port de `call` (evento `call` do Baileys) — emite `CallInfo`.
    fn handle_call_node(&self, node: &BinaryNode) {
        let from = node.attr("from").unwrap_or_default().to_string();
        let id = node.attr("id").unwrap_or_default().to_string();
        let status = node.attr("type").unwrap_or("offer").to_string();
        let call_type = node.attr("call_type").unwrap_or_default().to_string();
        let is_video = call_type == "video";
        let is_group = baileys_core::is_jid_group(&from);

        let call = CallInfo {
            chat_id: from.clone(),
            from: from.clone(),
            id,
            caller_pn: node.attr("caller_pn").map(String::from),
            date: node.attr("t").and_then(|t| t.parse::<i64>().ok()),
            offline: node.attr("offline").and_then(|v| v.parse::<bool>().ok()).unwrap_or(false),
            status,
            is_video,
            is_group,
            group_jid: if is_group { Some(from) } else { None },
        };
        let _ = self.events.send(ClientEvent::Call {
            calls: vec![call],
            raw_nodes: vec![node.clone()],
        });
    }

    /// Port de `groups.upsert`/`groups.update`/`group-participants.update`
    /// a partir de notificações `w:gp2`.
    /// `handleGroupNotification` + ramo `messageStubType` do `processMessage`
    /// (Hineken): eventos de grupo e manutenção do `groupMetaCache`.
    async fn handle_group_notification(&self, node: &BinaryNode) {
        let jid = baileys_core::jid_normalized_user(node.attr("from").unwrap_or_default());
        let participant = node.attr("participant").map(String::from);
        let Some(child) = (match &node.content {
            Some(BinaryContent::Children(children)) => children.first(),
            _ => None,
        }) else {
            return;
        };
        let participant_jid = child
            .child("participant")
            .and_then(|p| p.attr("jid"))
            .map(String::from)
            .or_else(|| participant.clone());
        let participant_info = || -> Vec<GroupParticipantInfo> {
            child
                .children("participant")
                .iter()
                .map(|p| GroupParticipantInfo {
                    jid: p.attr("jid").unwrap_or_default().to_string(),
                    phone_number: p.attr("phone_number").map(String::from),
                })
                .collect()
        };
        let emit_group_update = |update: GroupUpdate| {
            let _ = self.events.send(ClientEvent::GroupsUpdate {
                updates: vec![GroupUpdate { id: jid.clone(), author: participant.clone(), ..update }],
            });
        };
        let emit_participants = |participants: Vec<GroupParticipantInfo>, action: &str| {
            let _ = self.events.send(ClientEvent::GroupParticipantsUpdate {
                update: GroupParticipantsUpdate {
                    id: jid.clone(),
                    author: participant.clone(),
                    participants,
                    action: action.to_string(),
                },
            });
        };
        let on_off = |tag: &str, on: &str| tag == on;

        match child.tag.as_str() {
            "create" => {
                if let Some(metadata) = crate::groups::extract_group_metadata(child) {
                    let mut group = serde_json::to_value(&metadata).unwrap_or_default();
                    if let (Some(obj), Some(author)) = (group.as_object_mut(), participant.clone()) {
                        obj.insert("author".to_string(), serde_json::Value::String(author));
                    }
                    let _ = self.events.send(ClientEvent::GroupsUpsert { groups: vec![group] });
                }
            }
            "modify" => {
                // `participantInfo` não é preenchido no `modify` do Node.
                emit_participants(Vec::new(), "modify");
                self.group_meta_cache.remove(&jid).await;
            }
            "promote" | "demote" | "remove" | "add" | "leave" => {
                let participants = participant_info();
                let action = match child.tag.as_str() {
                    "leave" => "remove",
                    tag => tag,
                };
                emit_participants(participants.clone(), action);
                match action {
                    "remove" => {
                        if let Some(mut metadata) = self.group_meta_cache.get(&jid).await {
                            for p in &participants {
                                if let Some(index) = metadata
                                    .participants
                                    .iter()
                                    .position(|m| m.lid.as_deref() == Some(p.jid.as_str()))
                                {
                                    metadata.participants.remove(index);
                                }
                            }
                            metadata.size = metadata.participants.len();
                            self.group_meta_cache.set(jid.clone(), metadata).await;
                        }
                    }
                    "add" => {
                        if let Some(mut metadata) = self.group_meta_cache.get(&jid).await {
                            for p in &participants {
                                let exists = metadata
                                    .participants
                                    .iter()
                                    .any(|m| m.lid.as_deref() == Some(p.jid.as_str()) || m.id == p.jid);
                                if !exists {
                                    metadata.participants.push(crate::groups::GroupParticipant {
                                        id: p.jid.clone(),
                                        lid: Some(p.jid.clone()),
                                        jid: p.phone_number.clone().unwrap_or_default(),
                                        admin: None,
                                    });
                                }
                            }
                            metadata.size = metadata.participants.len();
                            self.group_meta_cache.set(jid.clone(), metadata).await;
                        }
                    }
                    _ => self.group_meta_cache.remove(&jid).await,
                }
            }
            "subject" => {
                emit_group_update(GroupUpdate {
                    subject: child.attr("subject").map(String::from),
                    ..Default::default()
                });
                self.group_meta_cache.remove(&jid).await;
            }
            "description" => {
                let desc = child.child("body").map(|b| b.content_text()).filter(|d| !d.is_empty());
                emit_group_update(GroupUpdate { desc, ..Default::default() });
                self.group_meta_cache.remove(&jid).await;
            }
            "announcement" | "not_announcement" => {
                emit_group_update(GroupUpdate {
                    announce: Some(on_off(&child.tag, "announcement")),
                    ..Default::default()
                });
                self.group_meta_cache.remove(&jid).await;
            }
            "locked" | "unlocked" => {
                emit_group_update(GroupUpdate {
                    restrict: Some(on_off(&child.tag, "locked")),
                    ..Default::default()
                });
                self.group_meta_cache.remove(&jid).await;
            }
            "invite" => {
                emit_group_update(GroupUpdate {
                    invite_code: child.attr("code").map(String::from),
                    ..Default::default()
                });
                self.group_meta_cache.remove(&jid).await;
            }
            "member_add_mode" => {
                let mode = child.content_text();
                if !mode.is_empty() {
                    emit_group_update(GroupUpdate {
                        member_add_mode: Some(mode == "all_member_add"),
                        ..Default::default()
                    });
                    self.group_meta_cache.remove(&jid).await;
                }
            }
            "membership_approval_mode" => {
                if let Some(group_join) = child.child("group_join") {
                    emit_group_update(GroupUpdate {
                        join_approval_mode: Some(group_join.attr("state") == Some("on")),
                        ..Default::default()
                    });
                    self.group_meta_cache.remove(&jid).await;
                }
            }
            "created_membership_requests" | "revoked_membership_requests" => {
                tracing::debug!(jid, participant = ?participant_jid, tag = %child.tag, "group join request");
                self.group_meta_cache.remove(&jid).await;
            }
            "suspended" | "unsuspended" => {
                emit_group_update(GroupUpdate {
                    suspended: Some(child.tag == "suspended"),
                    ..Default::default()
                });
                self.group_meta_cache.remove(&jid).await;
            }
            "delete" => {
                emit_group_update(GroupUpdate {
                    deleted: Some(true),
                    delete_reason: child.attr("reason").map(String::from),
                    ..Default::default()
                });
                self.group_meta_cache.remove(&jid).await;
            }
            _ => {}
        }
    }

    /// `case 'devices'` do `processNotification`: apaga sessões de devices
    /// removidos e invalida o `devicesCache` (1:1 e `group-`).
    async fn handle_devices_notification(&self, node: &BinaryNode, sink: &WsSink) {
        let Some(child) = (match &node.content {
            Some(BinaryContent::Children(children)) => children.first(),
            _ => None,
        }) else {
            return;
        };
        let devices = child.children("device");
        let invalidate = |normalized: String| async move {
            self.devices_cache.remove(&normalized).await;
            self.devices_cache.remove(&format!("group-{normalized}")).await;
        };
        match child.tag.as_str() {
            "remove" => {
                let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
                for device in &devices {
                    for attr in ["jid", "lid"] {
                        let Some(value) = device.attr(attr) else { continue };
                        if let Ok(addr) = repo.jid_to_signal_protocol_address(value) {
                            self.store.remove_generic("session", &addr);
                        }
                        invalidate(baileys_core::jid_normalized_user(value)).await;
                    }
                }
            }
            "update" => {
                let me_lid = self.store.creds().me.and_then(|m| m.lid).unwrap_or_default();
                let normalized = baileys_core::jid_normalized_user(&me_lid);
                let lids = if baileys_core::is_lid_user(&normalized) {
                    None
                } else {
                    self.get_lid(&normalized, sink).await.ok().flatten()
                };
                invalidate(normalized).await;
                if let Some(lids) = lids {
                    invalidate(lids).await;
                }
            }
            "add" => {
                for device in &devices {
                    for attr in ["jid", "lid"] {
                        let Some(value) = device.attr(attr) else { continue };
                        invalidate(baileys_core::jid_normalized_user(value)).await;
                    }
                }
            }
            _ => {}
        }
    }

    // --- handlers de pareamento / login ---

    async fn handle_pair_device(
        &self,
        stanza: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        // Responde o iq.
        let iq = BinaryNode::new("iq")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "result")
            .with_attr("id", stanza.attr("id").unwrap_or_default());
        self.send_node(&iq, sink).await?;

        let pair_device = stanza.child("pair-device");
        let ref_nodes: Vec<&BinaryNode> = pair_device.map(|p| p.children("ref")).unwrap_or_default();

        if ref_nodes.is_empty() {
            tracing::debug!("pair-device passkey request — uso manual");
            return Ok(());
        }

        let creds = self.store.creds();
        // Formato exato do Node Baileys (`genPairQR` em socket.js):
        //   qr = [ref, noiseKeyB64, identityKeyB64, advB64].join(',')
        let noise_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(decode_buffer(&creds.noise_key.public));
        let identity_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(decode_buffer(&creds.signed_identity_key.public));
        let adv_b64 = creds.adv_secret_key.clone();

        // Coleta todos os refs para o ciclo do QR (o Node usa 60s no primeiro,
        // 20s nos seguintes).
        let refs: Vec<String> = ref_nodes
            .iter()
            .filter_map(|ref_node| match &ref_node.content {
                Some(BinaryContent::Bytes(b)) => Some(String::from_utf8_lossy(b).to_string()),
                Some(BinaryContent::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();
        if refs.is_empty() {
            return Ok(());
        }

        // Emite o primeiro QR já (refs[0]) e agenda a rotação dos demais.
        let qr = gen_qr(&refs[0], &noise_key_b64, &identity_key_b64, &adv_b64);
        tracing::debug!("QR disponível");
        let _ = self.events.send(ClientEvent::Qr(qr.clone()));
        let _ = self.events.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
            connection: "connecting".to_string(),
            qr: Some(qr),
            ..Default::default()
        }));

        // Rotação: a cada `qr_timeout_ms` (padrão 60s), emite o próximo ref.
        // Assim o QR nunca expira enquanto a conexão estiver viva.
        let refs_rest = refs[1..].to_vec();
        let noise_key_b64_rot = noise_key_b64.clone();
        let identity_key_b64_rot = identity_key_b64.clone();
        let adv_b64_rot = adv_b64.clone();
        let events_rot = self.events.clone();
        let mut qr_interval = self.config.qr_timeout_ms.max(1000);
        let sink_rot = sink.clone();
        let refs_ended = self.qr_refs_ended.clone();
        let qr_close = self.qr_close.clone();

        // Cancela qualquer rotação anterior (o Node tem um único `qrTimer`).
        self.cancel_qr_rotation().await;

        let handle = tokio::spawn(async move {
            for r in refs_rest {
                tokio::time::sleep(std::time::Duration::from_millis(qr_interval)).await;
                let qr = gen_qr(&r, &noise_key_b64_rot, &identity_key_b64_rot, &adv_b64_rot);
                tracing::debug!("QR rotacionado");
                let _ = events_rot.send(ClientEvent::Qr(qr.clone()));
                let _ = events_rot.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
                    connection: "connecting".to_string(),
                    qr: Some(qr),
                    ..Default::default()
                }));
                qr_interval = 20_000; // refs seguintes: 20s
            }
            // Refs esgotados: o Node encerra a conexão (408) e o app reconecta
            // com QR novo.
            tokio::time::sleep(std::time::Duration::from_millis(qr_interval)).await;
            tracing::debug!("refs de QR esgotados; encerrando a conexão");
            refs_ended.store(true, Ordering::SeqCst);
            let _ = sink_rot.lock().await.close().await;
            qr_close.notify_waiters();
        });
        *self.qr_rotation.lock().await = Some(handle);

        Ok(())
    }

    /// Aborta a rotação de QR pendente (espelha `clearTimeout(qrTimer)` do Node).
    pub async fn cancel_qr_rotation(&self) {
        if let Some(handle) = self.qr_rotation.lock().await.take() {
            handle.abort();
        }
    }

    async fn handle_pair_success(
        &self,
        stanza: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        // Pareado: para a rotação do QR (o Node faz clearTimeout(qrTimer)).
        self.cancel_qr_rotation().await;

        let creds = self.store.creds();
        let (updated, reply) = configure_successful_pairing(stanza, &creds)?;
        self.store.update_creds(updated.clone())?;
        let _ = self.events.send(ClientEvent::CredsUpdate(updated));
        let _ = self.events.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
            connection: "connecting".to_string(),
            is_new_login: true,
            qr: None,
            ..Default::default()
        }));
        self.send_node(&reply, sink).await?;
        Ok(())
    }

    async fn handle_success(
        &self,
        node: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        tracing::debug!(lid = ?node.attr("lid"), "handle_success: iniciando login pós-success");
        // Login completo: para a rotação do QR (clearTimeout(qrTimer) do Node).
        self.cancel_qr_rotation().await;

        // Node (`socket.ts` CB:success): atualiza `me.lid` ANTES de enviar
        // `active`/emitir `open`. O `handle_receipt` (retry do phone) depende
        // do `me.lid` imediatamente após a conexão abrir.
        if let Some(lid) = node.attr("lid") {
            let mut creds = self.store.creds();
            if let Some(me) = &mut creds.me {
                me.lid = Some(lid.to_string());
                self.store.update_creds(creds.clone())?;
                let _ = self.events.send(ClientEvent::CredsUpdate(creds));
            }
        }

        self.upload_pre_keys_if_required(sink).await?;

        // sendPassiveIq('active') — via query para registrar a resposta e
        // manter a conexão estável (igual ao Node).
        let active = BinaryNode::new("iq")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("xmlns", "passive")
            .with_attr("type", "set")
            .with_attr("id", self.next_tag())
            .with_children(vec![BinaryNode::new("active")]);
        self.query_node(active, sink).await?;

        self.open.store(true, Ordering::SeqCst);
        let _ = self.events.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
            connection: "open".to_string(),
            ..Default::default()
        }));
        tracing::debug!("conexão aberta com o WhatsApp");
        Ok(())
    }

    async fn handle_edge_routing(&self, node: &BinaryNode) {
        if let Some(edge) = node.child("edge_routing") {
            if let Some(routing) = edge.child("routing_info") {
                if let Some(BinaryContent::Bytes(bytes)) = &routing.content {
                    let mut creds = self.store.creds();
                    creds.routing_info = Some(baileys_store::creds::BufferValue::Buffer {
                        type_: "Buffer".to_string(),
                        data: base64::engine::general_purpose::STANDARD.encode(bytes),
                    });
                    if self.store.update_creds(creds.clone()).is_ok() {
                        let _ = self.events.send(ClientEvent::CredsUpdate(creds));
                    }
                }
            }
        }
    }

    // --- pre-keys ---

    async fn upload_pre_keys_if_required(
        &self,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        tracing::debug!("upload_pre_keys_if_required: consultando pre-keys no servidor");
        let count = self.get_available_pre_keys_on_server(sink).await?;
        tracing::debug!("{count} pre-keys no servidor");
        if count <= MIN_PREKEY_COUNT as i64 {
            self.upload_pre_keys(INITIAL_PREKEY_COUNT, sink).await?;
        }
        Ok(())
    }

    async fn get_available_pre_keys_on_server(
        &self,
        sink: &WsSink,
    ) -> Result<i64, ClientError> {
        tracing::debug!("get_available_pre_keys_on_server: montando query count");
        let query = BinaryNode::new("iq")
            .with_attr("id", self.next_tag())
            .with_attr("xmlns", "encrypt")
            .with_attr("type", "get")
            .with_attr("to", S_WHATSAPP_NET)
            .with_children(vec![BinaryNode::new("count")]);
        tracing::debug!("get_available_pre_keys_on_server: enviando query_node");
        let result = self.query_node(query, sink).await?;
        let count = result
            .child("count")
            .and_then(|c| c.attr("value"))
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        Ok(count)
    }

    async fn upload_pre_keys(
        &self,
        count: u32,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        tracing::debug!(count, "fazendo upload de pre-keys");

        let mut creds = self.store.creds();
        let available = creds.next_pre_key_id.saturating_sub(creds.first_unuploaded_pre_key_id);
        let remaining = count as i64 - available as i64;
        let last_pre_key_id = creds.next_pre_key_id as i64 + remaining - 1;

        let mut new_pre_keys: Vec<(u32, Vec<u8>, Vec<u8>)> = Vec::new();
        if remaining > 0 {
            for i in creds.next_pre_key_id..=last_pre_key_id as u32 {
                let kp = Curve::generate_key_pair();
                let serialized = baileys_store::creds::SerializedKeyPair {
                    public: to_buffer(&kp.public),
                    private: to_buffer(&kp.private),
                };
                self.store.store_pre_key(i, &serialized)?;
                new_pre_keys.push((i, kp.public.clone(), kp.private.clone()));
            }
        }

        // Pre-keys existentes para upload: range [firstUnuploaded, firstUnuploaded+count).
        let mut upload_keys: Vec<(u32, Vec<u8>)> = Vec::new();
        let range_start = creds.first_unuploaded_pre_key_id;
        let range_end = range_start.saturating_add(count);
        for id in range_start..range_end {
            let mut found: Option<Vec<u8>> = None;
            if let Some((pubk, _)) = self.store.load_pre_key(id)? {
                // Pre-key gravada por versão antiga/bugada com prefixo `05` (33
                // bytes): o servidor rejeita silenciosamente e o upload estoura
                // timeout. Regenera como 32 bytes.
                if pubk.len() == 32 {
                    found = Some(pubk);
                } else {
                    let kp = Curve::generate_key_pair();
                    let serialized = baileys_store::creds::SerializedKeyPair {
                        public: to_buffer(&kp.public),
                        private: to_buffer(&kp.private),
                    };
                    self.store.store_pre_key(id, &serialized)?;
                    found = Some(kp.public);
                }
            } else if let Some((_, pubk, _)) = new_pre_keys.iter().find(|(i, _, _)| *i == id) {
                found = Some(pubk.clone());
            }
            if let Some(pubk) = found {
                upload_keys.push((id, pubk));
            }
        }

        let identity_pub = decode_buffer(&creds.signed_identity_key.public);
        let spk_pub = decode_buffer(&creds.signed_pre_key.key_pair.public);
        let spk_sig = decode_buffer(&creds.signed_pre_key.signature);

        let mut list_children = Vec::with_capacity(upload_keys.len());
        for (id, public) in &upload_keys {
            list_children.push(
                BinaryNode::new("key")
                    .with_children(vec![
                        BinaryNode::new("id").with_bytes(baileys_core::ids::encode_big_endian(*id, 3)),
                        BinaryNode::new("value").with_bytes(public.clone()),
                    ]),
            );
        }

        let skey = BinaryNode::new("skey").with_children(vec![
            BinaryNode::new("id").with_bytes(baileys_core::ids::encode_big_endian(creds.signed_pre_key.key_id, 3)),
            BinaryNode::new("value").with_bytes(spk_pub),
            BinaryNode::new("signature").with_bytes(spk_sig),
        ]);

        let node = BinaryNode::new("iq")
            .with_attr("xmlns", "encrypt")
            .with_attr("type", "set")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("id", self.next_tag())
            .with_children(vec![
                BinaryNode::new("registration").with_bytes(baileys_core::ids::encode_big_endian(creds.registration_id, 4)),
                BinaryNode::new("type").with_bytes(vec![5]),
                BinaryNode::new("identity").with_bytes(identity_pub),
                BinaryNode::new("list").with_children(list_children),
                skey,
            ]);

        let _ = self.query_node(node, sink).await?;

        creds.next_pre_key_id = (last_pre_key_id + 1).max(creds.next_pre_key_id as i64) as u32;
        creds.first_unuploaded_pre_key_id = (last_pre_key_id + 1).max(creds.first_unuploaded_pre_key_id as i64) as u32;
        self.store.update_creds(creds.clone())?;
        let _ = self.events.send(ClientEvent::CredsUpdate(creds));
        tracing::debug!(count, "pre-keys enviadas");
        Ok(())
    }

    async fn handle_encrypt_notification(
        &self,
        node: &BinaryNode,
        sink: &WsSink,
        noise: &Arc<Mutex<NoiseHandler>>,
    ) -> Result<(), ClientError> {
        // O upload de pre-keys em si é disparado pelo `handle_node` em task
        // separada (ver branch `notification`/`iq encrypt`), para não bloquear
        // o loop de leitura com o `query_node` do upload.
        let _ = noise;

        // Ack da notificação — CRÍTICO. O Node (`handleNotification`) SEMPRE
        // envia `sendMessageAck` no `finally`. Sem ack, o servidor acumula
        // notificações pendentes e derruba a conexão com `stream:error 500`
        // (payload `<ack class="notification" ...>` — foi exatamente o que
        // derrubou a sessão).
        self.send_message_ack(node, sink).await?;

        Ok(())
    }

    // --- mensagens ---

    async fn handle_message(
        self: &Arc<Self>,
        node: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let from = node.attr("from").unwrap_or_default().to_string();

        // `shouldIgnoreJid` (ack e sai).
        if self.should_ignore_jid(&from) && from != "@s.whatsapp.net" {
            tracing::debug!(from = %from, "ignored message");
            return self.send_message_ack(node, sink).await;
        }

        // `<unavailable type="view_once">`: upsert (`append`) + ack, sem decrypt.
        if node.child("unavailable").and_then(|u| u.attr("type")) == Some("view_once") {
            if let Some(decoded) = self.decode_message_node(node) {
                let mut info = decoded.full;
                clean_message(&mut info, &self.me_id());
                let _ = self.events.send(ClientEvent::Message {
                    info,
                    raw: node.clone(),
                    key_extras: decoded.key_extras,
                });
            }
            return self.send_message_ack(node, sink).await;
        }

        // `msmsg` (Meta AI): só ack.
        if node.child("enc").and_then(|e| e.attr("type")) == Some("msmsg") {
            return self.send_message_ack(node, sink).await;
        }

        // `decodeMessageNode` lança em envelope inválido (o Node não faz ack).
        let Some(decoded) = self.decode_message_node(node) else {
            tracing::warn!(from = %from, "decodeMessageNode: envelope inválido, mensagem ignorada");
            return Ok(());
        };
        let DecodedMessageNode { full: mut info, author, sender, key_extras, category } = decoded;
        tracing::debug!(from = %from, author = %author, sender = %sender, "mensagem decodificada");

        // `lidCache` a partir de `sender_lid` + `sender_pn` (só chat 1:1).
        if is_jid_user(&from) || is_lid_user(&from) {
            if let (Some(sender_lid), Some(sender_pn)) = (&key_extras.sender_lid, &key_extras.sender_pn) {
                let pn = baileys_core::jid_normalized_user(sender_pn);
                if self.lid_cache.get(&pn).await.is_none() {
                    self.lid_cache.set(pn, baileys_core::jid_normalized_user(sender_lid)).await;
                }
            }
        }

        self.decrypt_message_node(node, &mut info, &author, &sender);

        let msg_id = info.key.as_ref().and_then(|k| k.id.clone()).unwrap_or_default();
        if info.message_stub_type == Some(wa::web_message_info::StubType::Ciphertext as i32) {
            let stub = info.message_stub_parameters.first().cloned().unwrap_or_default();
            if stub == NO_MESSAGE_FOUND_ERROR_TEXT {
                // Sem ciphertext no nó (fanout/ads): só PDO.
                let unavailable_type = node
                    .child("unavailable")
                    .and_then(|u| u.attr("type").map(String::from));
                let skip = matches!(
                    unavailable_type.as_deref(),
                    Some("bot_unavailable_fanout")
                        | Some("hosted_unavailable_fanout")
                        | Some("view_once_unavailable_fanout")
                );
                self.send_message_ack(node, sink).await?;
                if skip {
                    tracing::debug!(msg_id = %msg_id, unavailable_type = ?unavailable_type, "skipping placeholder resend for excluded unavailable type");
                } else if self.sink().await.is_some() {
                    if let Some(key) = info.key.clone() {
                        let client = self.clone();
                        let sink = sink.clone();
                        let msg_id = msg_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = client.request_placeholder_resend(key, &sink).await {
                                tracing::warn!(error = %e, msg_id, "failed to request placeholder resend");
                            }
                        });
                    }
                }
            } else {
                self.send_message_ack(node, sink).await?;
                let client = self.clone();
                let sink = sink.clone();
                let retry_node = node.clone();
                let msg_id = msg_id.clone();
                tokio::spawn(async move {
                    let _guard = client.retry_mutex.lock().await;
                    if client.sink().await.is_some() {
                        if let Err(e) = client.send_retry_request(&retry_node, &sink).await {
                            tracing::warn!(error = %e, msg_id, "falha ao enviar retry request");
                        }
                        let delay = client.config.retry_request_delay_ms;
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                    } else {
                        tracing::debug!(msg_id, "connection closed, ignoring retry req");
                    }
                });
            }
            // Monitor do manager (retry manual / marcador de "recuperada").
            let mut failed = info.clone();
            clean_message(&mut failed, &self.me_id());
            let _ = self.events.send(ClientEvent::MessageFailed {
                reason: failed.message_stub_parameters.join(", "),
                info: failed,
                raw: node.clone(),
            });
        } else {
            // Receipt: `peer_msg` (category=peer), `sender` (outro device
            // meu; em 1:1 o participant é o author), `inactive` sem presença.
            let key = info.key.clone().unwrap_or_default();
            let remote_jid = key.remote_jid.clone().unwrap_or_default();
            let mut participant = key.participant.clone();
            let receipt_type = if category.as_deref() == Some("peer") {
                Some("peer_msg")
            } else if key.from_me.unwrap_or(false) {
                if is_jid_user(&remote_jid) {
                    participant = Some(author.clone());
                }
                Some("sender")
            } else if !self.send_active_receipts.load(Ordering::Relaxed) {
                Some("inactive")
            } else {
                None
            };
            self.send_receipt(&remote_jid, participant.as_deref(), &[msg_id.clone()], receipt_type, sink)
                .await?;

            let is_history = info
                .message
                .as_ref()
                .map(normalize_message_content)
                .and_then(|m| m.protocol_message.as_ref())
                .and_then(|p| p.history_sync_notification.as_ref())
                .is_some();
            if is_history {
                let jid = baileys_core::jid_normalized_user(&remote_jid);
                self.send_receipt(&jid, None, &[msg_id.clone()], Some("hist_sync"), sink).await?;
            }

            self.send_message_ack(node, sink).await?;
        }

        // `cleanMessage` + `upsertMessage` (→ `processMessage`).
        clean_message(&mut info, &self.me_id());
        let _ = self.events.send(ClientEvent::Message {
            info: info.clone(),
            raw: node.clone(),
            key_extras: key_extras.clone(),
        });
        self.update_push_name_from_message(&info, sink).await;
        tracing::debug!(from = %from, msg_id = %msg_id, "evento Message emitido");

        self.process_message(&info, &key_extras, sink).await;
        self.maybe_sync_app_state(&info, sink);
        Ok(())
    }

    /// Gatilhos do `upsertMessage`: history sync com `myAppStateKeyId` →
    /// `doAppStateSync`; sem chave → `pendingAppStateSync`; e o
    /// `appStateSyncKeyShare` libera o sync pendente.
    fn maybe_sync_app_state(self: &Arc<Self>, info: &wa::WebMessageInfo, sink: &WsSink) {
        let Some(message) = info.message.as_ref() else {
            return;
        };
        let is_history = normalize_message_content(message)
            .protocol_message
            .as_ref()
            .and_then(|p| p.history_sync_notification.as_ref())
            .is_some();
        let has_key = self.store.creds().my_app_state_key_id.is_some();

        let mut should_sync = false;
        if is_history && !has_key {
            tracing::warn!("skipping app state sync, as myAppStateKeyId is not set");
            self.pending_app_state_sync.store(true, Ordering::Relaxed);
        }
        if is_history && has_key {
            self.pending_app_state_sync.store(false, Ordering::Relaxed);
            should_sync = true;
        }
        let is_key_share = message
            .protocol_message
            .as_ref()
            .and_then(|p| p.app_state_sync_key_share.as_ref())
            .is_some();
        if is_key_share && self.pending_app_state_sync.swap(false, Ordering::Relaxed) {
            should_sync = true;
        }

        if should_sync {
            let client = self.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                client.do_app_state_sync(&sink).await;
            });
        }
    }

    /// `doAppStateSync`: sync inicial de todas as coleções (só uma vez,
    /// controlado pelo `accountSyncCounter`).
    async fn do_app_state_sync(self: &Arc<Self>, sink: &WsSink) {
        if self.store.creds().account_sync_counter != 0 {
            return;
        }
        tracing::debug!("doing initial app state sync");
        match self.resync_app_state(&crate::app_state::ALL_WA_PATCH_NAMES, true, sink).await {
            Ok(()) => {
                let mut creds = self.store.creds();
                creds.account_sync_counter += 1;
                if self.store.update_creds(creds.clone()).is_ok() {
                    let _ = self.events.send(ClientEvent::CredsUpdate(creds));
                }
            }
            Err(e) => tracing::warn!(error = %e, "initial app state sync falhou"),
        }
    }

    /// `getAppStateSyncKey` — `keyData` gravado em `app-state-sync-key`.
    fn app_state_sync_key(&self, key_id: &str) -> Option<Vec<u8>> {
        let raw = self.store.load_generic("app-state-sync-key", key_id)?;
        crate::app_state::app_state_sync_key_data(&raw)
    }

    fn load_app_state_version(&self, name: &str) -> Option<crate::app_state::LtHashState> {
        let raw = self.store.load_generic("app-state-sync-version", name)?;
        serde_json::from_str(&raw).ok()
    }

    fn save_app_state_version(&self, name: &str, state: &crate::app_state::LtHashState) {
        if let Ok(json) = serde_json::to_string(state) {
            self.store.store_generic("app-state-sync-version", name, &json);
        }
    }

    /// `resyncAppState` (Hineken `chats.ts`): busca snapshot/patches de cada
    /// coleção até não haver mais, decodifica e aplica as mutações.
    pub async fn resync_app_state(
        self: &Arc<Self>,
        collections: &[&str],
        is_initial_sync: bool,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        use crate::app_state::{self as app_state, MutationMap};
        let _guard = self.app_state_mutex.lock().await;

        let mut initial_version_map: HashMap<String, u64> = HashMap::new();
        let mut global_mutation_map = MutationMap::default();
        let mut collections_to_handle: Vec<String> = Vec::new();
        for name in collections {
            if !collections_to_handle.iter().any(|c| c == name) {
                collections_to_handle.push(name.to_string());
            }
        }
        let mut attempts_map: HashMap<String, u32> = HashMap::new();

        while !collections_to_handle.is_empty() {
            let mut states: HashMap<String, app_state::LtHashState> = HashMap::new();
            let mut nodes = Vec::new();
            for name in &collections_to_handle {
                let state = match self.load_app_state_version(name) {
                    Some(state) => {
                        initial_version_map.entry(name.clone()).or_insert(state.version);
                        state
                    }
                    None => app_state::LtHashState::new(),
                };
                tracing::debug!("resyncing {name} from v{}", state.version);
                nodes.push(
                    BinaryNode::new("collection")
                        .with_attr("name", name.as_str())
                        .with_attr("version", state.version.to_string())
                        .with_attr("return_snapshot", (state.version == 0).to_string()),
                );
                states.insert(name.clone(), state);
            }

            let query = BinaryNode::new("iq")
                .with_attr("to", S_WHATSAPP_NET)
                .with_attr("xmlns", "w:sync:app:state")
                .with_attr("type", "set")
                .with_attr("id", self.next_tag())
                .with_children(vec![BinaryNode::new("sync").with_children(nodes)]);
            let result = self.query_node(query, sink).await?;

            let decoded = app_state::parse_syncd_collections(&result)
                .map_err(|e| ClientError::InvalidParams(e.to_string()))?;
            if decoded.is_empty() {
                break;
            }

            let get_key = |id: &str| self.app_state_sync_key(id);
            for collection in decoded {
                let name = collection.name.clone();
                let has_more_patches = collection.has_more_patches;
                let outcome: Result<(), app_state::AppStateError> = async {
                    if let Some(snapshot_ref) = &collection.snapshot_ref {
                        let data = app_state::download_external_blob(snapshot_ref).await?;
                        let snapshot = wa::SyncdSnapshot::decode(data.as_slice())
                            .map_err(|e| app_state::AppStateError::Invalid(e.to_string()))?;
                        let (new_state, mutation_map) = app_state::decode_syncd_snapshot(
                            &name,
                            &snapshot,
                            &get_key,
                            initial_version_map.get(&name).copied(),
                            app_state::VALIDATE_SNAPSHOT_MACS,
                        )?;
                        tracing::debug!("restored state of {name} from snapshot to v{} with mutations", new_state.version);
                        self.save_app_state_version(&name, &new_state);
                        states.insert(name.clone(), new_state);
                        global_mutation_map.extend(mutation_map);
                    }

                    if !collection.patches.is_empty() {
                        let mut patches = collection.patches.clone();
                        for patch in patches.iter_mut() {
                            if let Some(external) = patch.external_mutations.clone() {
                                let downloaded = app_state::download_external_patch(&external).await?;
                                patch.mutations.extend(downloaded.mutations);
                            }
                        }
                        let current = states.get(&name).cloned().unwrap_or_default();
                        let (new_state, mutation_map) = app_state::decode_patches(
                            &name,
                            &patches,
                            &current,
                            &get_key,
                            initial_version_map.get(&name).copied(),
                            app_state::VALIDATE_PATCH_SNAPSHOT_MACS,
                        )?;
                        self.save_app_state_version(&name, &new_state);
                        tracing::debug!("synced {name} to v{}", new_state.version);
                        initial_version_map.insert(name.clone(), new_state.version);
                        states.insert(name.clone(), new_state);
                        global_mutation_map.extend(mutation_map);
                    }
                    Ok(())
                }
                .await;

                match outcome {
                    Ok(()) => {
                        if has_more_patches {
                            tracing::debug!("{name} has more patches...");
                        } else {
                            collections_to_handle.retain(|c| c != &name);
                        }
                    }
                    Err(error) => {
                        let attempts = attempts_map.get(&name).copied().unwrap_or(0);
                        let irrecoverable = attempts >= app_state::MAX_SYNC_ATTEMPTS || error.is_key_not_found();
                        tracing::debug!(
                            name,
                            error = %error,
                            "failed to sync state from version{}",
                            if irrecoverable { "" } else { ", removing and trying from scratch" }
                        );
                        self.store.remove_generic("app-state-sync-version", &name);
                        attempts_map.insert(name.clone(), attempts + 1);
                        if irrecoverable {
                            collections_to_handle.retain(|c| c != &name);
                        }
                    }
                }
            }
        }

        for mutation in global_mutation_map.into_mutations() {
            self.process_sync_action(&mutation, is_initial_sync, sink).await;
        }
        Ok(())
    }

    /// `processSyncAction` (Hineken `chat-utils.ts`).
    async fn process_sync_action(
        &self,
        mutation: &crate::app_state::ChatMutation,
        is_initial_sync: bool,
        sink: &WsSink,
    ) {
        let Some(action) = mutation.sync_action.value.as_ref() else {
            tracing::debug!(index = ?mutation.index, "unprocessable update");
            return;
        };
        let index_at = |i: usize| mutation.index.get(i).cloned().unwrap_or_default();
        let (r#type, id, msg_id, from_me) = (index_at(0), index_at(1), index_at(2), index_at(3));

        if let Some(mute) = &action.mute_action {
            let _ = self.events.send(ClientEvent::ChatsUpdate {
                chats: vec![ChatUpdate {
                    id,
                    mute_end_time: if mute.muted.unwrap_or(false) { mute.mute_end_timestamp } else { None },
                    ..Default::default()
                }],
            });
        } else if action.archive_chat_action.is_some() || r#type == "archive" || r#type == "unarchive" {
            let archived = match &action.archive_chat_action {
                Some(a) => a.archived.unwrap_or(false),
                None => r#type == "archive",
            };
            let _ = self.events.send(ClientEvent::ChatsUpdate {
                chats: vec![ChatUpdate { id, archived: Some(archived), ..Default::default() }],
            });
        } else if let Some(mark_read) = &action.mark_chat_as_read_action {
            let read = mark_read.read.unwrap_or(false);
            // No sync inicial, "lido" é o padrão: não emite unreadCount.
            let unread_count = if is_initial_sync && read {
                None
            } else if read {
                Some(0)
            } else {
                Some(-1)
            };
            let _ = self.events.send(ClientEvent::ChatsUpdate {
                chats: vec![ChatUpdate { id, unread_count, ..Default::default() }],
            });
        } else if action.delete_message_for_me_action.is_some() || r#type == "deleteMessageForMe" {
            tracing::debug!(id, msg_id, from_me, "messages.delete (app-state)");
        } else if let Some(contact) = &action.contact_action {
            let _ = self.events.send(ClientEvent::ContactsUpsert {
                contacts: vec![ContactUpsert {
                    id: id.clone(),
                    name: contact.full_name.clone(),
                    lid: contact.lid_jid.clone().filter(|l| !l.is_empty()),
                    jid: is_jid_user(&id).then(|| id.clone()),
                    ..Default::default()
                }],
            });
        } else if let Some(push_name) = &action.push_name_setting {
            if let Some(name) = push_name.name.as_deref().filter(|n| !n.is_empty()) {
                self.set_me_name(name, sink).await;
            }
        } else if let Some(pin) = &action.pin_action {
            let _ = self.events.send(ClientEvent::ChatsUpdate {
                chats: vec![ChatUpdate {
                    id,
                    pinned: if pin.pinned.unwrap_or(false) { mutation.sync_action.value.as_ref().and_then(|v| v.timestamp) } else { None },
                    ..Default::default()
                }],
            });
        } else if let Some(setting) = &action.unarchive_chats_setting {
            let unarchive_chats = setting.unarchive_chats.unwrap_or(false);
            let mut creds = self.store.creds();
            if !creds.account_settings.is_object() {
                creds.account_settings = serde_json::json!({});
            }
            if let Some(obj) = creds.account_settings.as_object_mut() {
                obj.insert("unarchiveChats".to_string(), serde_json::Value::Bool(unarchive_chats));
            }
            if self.store.update_creds(creds.clone()).is_ok() {
                let _ = self.events.send(ClientEvent::CredsUpdate(creds));
            }
            tracing::debug!("archive setting updated => '{unarchive_chats}'");
        } else if action.star_action.is_some() || r#type == "star" {
            let starred = action
                .star_action
                .as_ref()
                .and_then(|s| s.starred)
                .unwrap_or_else(|| mutation.index.last().map(String::as_str) == Some("1"));
            let _ = self.events.send(ClientEvent::MessagesUpdate {
                updates: vec![MessageStatusUpdate {
                    key: MessageUpdateKey { remote_jid: id, id: msg_id, from_me: from_me == "1", ..Default::default() },
                    update: MessageUpdateData { starred: Some(starred), ..Default::default() },
                }],
            });
        } else if action.delete_chat_action.is_some() || r#type == "deleteChat" {
            if !is_initial_sync {
                let _ = self.events.send(ClientEvent::ChatsDelete { jids: vec![id] });
            }
        } else {
            tracing::debug!(id, index = ?mutation.index, "unprocessable update");
        }
    }

    /// `upsertMessage` ("update our pushname too") + hook `creds.update` do
    /// socket: mensagem minha com `pushName` diferente do `me.name` grava o
    /// nome e reenvia `<presence name>` (sem `type`).
    async fn update_push_name_from_message(&self, info: &wa::WebMessageInfo, sink: &WsSink) {
        let from_me = info.key.as_ref().and_then(|k| k.from_me).unwrap_or(false);
        let Some(push_name) = info.push_name.as_deref().filter(|n| !n.is_empty()) else {
            return;
        };
        if !from_me {
            return;
        }
        self.set_me_name(push_name, sink).await;
    }

    /// `creds.update({ me: { ...me, name } })` + hook do socket: grava o nome
    /// e, se mudou, envia `<presence name>`.
    async fn set_me_name(&self, name: &str, sink: &WsSink) {
        let mut creds = self.store.creds();
        let Some(me) = creds.me.as_mut() else {
            return;
        };
        if me.name.as_deref() == Some(name) {
            return;
        }
        me.name = Some(name.to_string());
        if let Err(e) = self.store.update_creds(creds.clone()) {
            tracing::warn!(error = %e, "falha ao gravar pushName no creds");
            return;
        }
        let _ = self.events.send(ClientEvent::CredsUpdate(creds));
        tracing::debug!(name, "updated pushName");
        let presence = BinaryNode::new("presence").with_attr("name", name);
        if let Err(e) = self.send_node(&presence, sink).await {
            tracing::warn!(error = %e, "error in sending presence update on name change");
        }
    }

    /// `handleBadAck`: ack de mensagem enviada com `error` vira
    /// `messages.update { status: ERROR, messageStubParameters: [error] }`.
    async fn handle_bad_ack(&self, node: &BinaryNode, sink: &WsSink) -> Result<(), ClientError> {
        if let Some(error) = node.attr("error") {
            let key = MessageUpdateKey {
                remote_jid: node.attr("from").unwrap_or_default().to_string(),
                id: node.attr("id").unwrap_or_default().to_string(),
                from_me: true,
                ..Default::default()
            };
            let error_update = |parameters: Vec<String>| MessageStatusUpdate {
                key: key.clone(),
                update: MessageUpdateData {
                    status: Some(wa::web_message_info::Status::Error as i32),
                    message_stub_parameters: parameters,
                    ..Default::default()
                },
            };
            match error {
                // `MissingTcToken`: o Node também consulta o reachout timelock.
                "463" => {
                    let _ = self.events.send(ClientEvent::MessagesUpdate {
                        updates: vec![error_update(vec![
                            error.to_string(),
                            "Your account has been restricted".to_string(),
                        ])],
                    });
                }
                "479" => tracing::warn!(
                    msg_id = %key.id,
                    from = %key.remote_jid,
                    "smax-invalid (479): stanza rejected by server — likely stale device session or malformed addressing"
                ),
                _ => tracing::warn!(?node.attrs, "received error in ack"),
            }
            let _ = self.events.send(ClientEvent::MessagesUpdate {
                updates: vec![error_update(vec![error.to_string()])],
            });
        }
        self.send_message_ack(node, sink).await
    }

    /// `shouldIgnoreJid` do container (`ignoreGroups`).
    fn should_ignore_jid(&self, jid: &str) -> bool {
        if !self.config.ignore_groups || jid.is_empty() {
            return false;
        }
        is_jid_group(jid) || jid.ends_with("@broadcast") || jid.contains("newsletter")
    }

    /// `decryptMessageNode().decrypt()` (Hineken `decode-wa-message.ts`).
    fn decrypt_message_node(
        &self,
        stanza: &BinaryNode,
        info: &mut wa::WebMessageInfo,
        author: &str,
        sender: &str,
    ) {
        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
        let mut decryptables = 0usize;
        if let Some(BinaryContent::Children(children)) = &stanza.content {
            for child in children {
                if child.tag == "verified_name" {
                    if let Some(BinaryContent::Bytes(bytes)) = &child.content {
                        let details = wa::VerifiedNameCertificate::decode(bytes.as_slice())
                            .ok()
                            .and_then(|cert| cert.details)
                            .and_then(|d| wa::verified_name_certificate::Details::decode(d.as_slice()).ok());
                        if let Some(details) = details {
                            info.verified_biz_name = details.verified_name;
                        }
                    }
                }
                if child.tag != "enc" && child.tag != "plaintext" {
                    continue;
                }
                let Some(BinaryContent::Bytes(content)) = &child.content else {
                    continue;
                };
                decryptables += 1;

                let e2e_type = if child.tag == "plaintext" {
                    "plaintext".to_string()
                } else {
                    child.attr("type").unwrap_or_default().to_string()
                };
                let decoded: Result<wa::Message, String> = (|| {
                    let buf = match e2e_type.as_str() {
                        "skmsg" => repo
                            .decrypt_group_message(sender, author, content)
                            .map_err(|e| e.to_string())?,
                        "pkmsg" | "msg" => {
                            let user = if is_jid_user(sender) { sender } else { author };
                            repo.decrypt_message(user, &e2e_type, content).map_err(|e| e.to_string())?
                        }
                        "plaintext" => content.clone(),
                        other => return Err(format!("Unknown e2e type: {other}")),
                    };
                    let bytes = if e2e_type != "plaintext" {
                        baileys_core::ids::unpad_random_max16(&buf).map_err(|e| e.to_string())?
                    } else {
                        buf
                    };
                    wa::Message::decode(bytes.as_slice()).map_err(|e| e.to_string())
                })();

                match decoded {
                    Ok(decoded) => {
                        // `deviceSentMessage`: preserva o `messageContextInfo`
                        // externo (`{ ...outer, ...inner }`) — é onde vem o
                        // `messageSecret` das mensagens enviadas pelo celular.
                        let inner = decoded.device_sent_message.as_ref().and_then(|d| d.message.clone());
                        let msg = match inner {
                            Some(inner) => {
                                let mut inner = *inner;
                                if let Some(mut merged) = decoded.message_context_info.clone() {
                                    if let Some(inner_ctx) = inner.message_context_info.take() {
                                        let _ = merged.merge(inner_ctx.encode_to_vec().as_slice());
                                    }
                                    inner.message_context_info = Some(merged);
                                }
                                inner
                            }
                            None => decoded,
                        };

                        if let Some(skdm) = &msg.sender_key_distribution_message {
                            if let (Some(axolotl), Some(group_id)) =
                                (&skdm.axolotl_sender_key_distribution_message, &skdm.group_id)
                            {
                                if let Err(e) = repo.process_sender_key_distribution_message(group_id, author, axolotl) {
                                    tracing::error!(error = %e, "failed to decrypt message");
                                }
                            }
                        }

                        // `Object.assign(fullMessage.message, msg)`.
                        match info.message.as_mut() {
                            Some(existing) => {
                                let _ = existing.merge(msg.encode_to_vec().as_slice());
                            }
                            None => info.message = Some(msg),
                        }
                    }
                    Err(err) => {
                        tracing::error!(error = %err, e2e_type = %e2e_type, "failed to decrypt message");
                        info.message_stub_type = Some(wa::web_message_info::StubType::Ciphertext as i32);
                        info.message_stub_parameters = vec![err];
                    }
                }
            }
        }

        if decryptables == 0 {
            info.message_stub_type = Some(wa::web_message_info::StubType::Ciphertext as i32);
            info.message_stub_parameters = vec![NO_MESSAGE_FOUND_ERROR_TEXT.to_string()];
        }
    }

    /// Port de `decodeMessageNode` (parse do envelope, sem descriptografar).
    fn decode_message_node(&self, stanza: &BinaryNode) -> Option<DecodedMessageNode> {
        let msg_id = stanza.attr("id").unwrap_or_default().to_string();
        let from = stanza.attr("from").unwrap_or_default().to_string();
        let participant = stanza.attr("participant").map(String::from);
        let recipient = stanza.attr("recipient").map(String::from);
        let sender_lid = stanza.attr("sender_lid").map(String::from);
        let participant_lid = stanza.attr("participant_lid").map(String::from);
        let participant_pn = stanza.attr("participant_pn").map(String::from);
        let sender_pn = stanza.attr("sender_pn").map(String::from);
        let peer_recipient_pn = stanza.attr("peer_recipient_pn").map(String::from);
        let peer_recipient_lid = stanza.attr("peer_recipient_lid").map(String::from);

        let me = self.store.creds().me.clone();
        let me_id = me.as_ref().map(|m| m.id.clone()).unwrap_or_default();
        let me_lid = me.as_ref().and_then(|m| m.lid.clone()).unwrap_or_default();
        let is_me = |jid: &str| !me_id.is_empty() && are_jids_same_user(jid, &me_id);
        let is_me_lid = |jid: &str| !me_lid.is_empty() && are_jids_same_user(jid, &me_lid);

        // `(isLidUser(from) || isLidUser(participant) ? isMeLid : isMe)(participant || from)`.
        let from_or_participant = participant.clone().unwrap_or_else(|| from.clone());
        let from_me = if is_lid_user(&from) || participant.as_deref().is_some_and(is_lid_user) {
            is_me_lid(&from_or_participant)
        } else {
            is_me(&from_or_participant)
        };

        // `${lidUser}:${device}@lid` (sem `:0` quando o device é 0/ausente).
        let lid_author = |lid_source: &str, device_source: &str| -> String {
            let user = jid_user(&baileys_core::jid_normalized_user(lid_source)).unwrap_or_default();
            match jid_device(device_source) {
                Some(d) if d != 0 => format!("{user}:{d}@lid"),
                _ => format!("{user}@lid"),
            }
        };

        let (is_chat, chat_id, author) = if is_jid_user(&from) || is_lid_user(&from) {
            let chat_id = match &recipient {
                Some(r) if !r.ends_with("@bot") => {
                    if !is_me(&from) && !is_me_lid(&from) {
                        tracing::warn!(from = %from, "recipient present, but msg not from me");
                        return None;
                    }
                    r.clone()
                }
                _ if from.is_empty() => sender_lid.clone().unwrap_or_default(),
                _ => from.clone(),
            };
            let author = if from_me {
                lid_author(&me_lid, &from)
            } else if let Some(sl) = &sender_lid {
                lid_author(sl, &from)
            } else {
                from.clone()
            };
            (true, chat_id, author)
        } else if is_jid_group(&from) {
            let Some(p) = participant.clone() else {
                tracing::warn!(from = %from, "No participant in group message");
                return None;
            };
            let author = if from_me {
                lid_author(&me_lid, &p)
            } else if let Some(pl) = &participant_lid {
                lid_author(pl, &p)
            } else {
                p.clone()
            };
            (false, from.clone(), author)
        } else if from.ends_with("@broadcast") {
            if participant.is_none() && participant_lid.is_some() {
                tracing::warn!(from = %from, "No participant in group message");
                return None;
            }
            let author = participant_lid.clone().or_else(|| participant.clone()).unwrap_or_default();
            (false, from.clone(), author)
        } else if from.ends_with("@newsletter") {
            (false, from.clone(), from.clone())
        } else {
            tracing::warn!(from = %from, "Unknown message type");
            return None;
        };

        // Key crua (o `cleanMessage` normaliza depois do receipt).
        let key = wa::MessageKey {
            remote_jid: Some(chat_id.clone()),
            from_me: Some(from_me),
            id: Some(msg_id),
            participant: participant.clone(),
        };

        let full = wa::WebMessageInfo {
            key: Some(key),
            message: None,
            message_timestamp: stanza.attr("t").and_then(|t| t.parse().ok()),
            status: if from_me {
                Some(wa::web_message_info::Status::ServerAck as i32)
            } else {
                None
            },
            push_name: stanza.attr("notify").map(String::from),
            broadcast: Some(from.ends_with("@broadcast")),
            ..Default::default()
        };

        let key_extras = MessageKeyExtras {
            sender_lid,
            participant_lid,
            participant_pn,
            sender_pn,
            peer_recipient_pn,
            peer_recipient_lid,
        };

        Some(DecodedMessageNode {
            full,
            sender: if is_chat { author.clone() } else { chat_id },
            author,
            key_extras,
            category: stanza.attr("category").map(String::from),
        })
    }

    /// `processMessage` (Hineken `process-message.ts`) sobre a mensagem já
    /// limpa: protocolo, `secretEncryptedMessage` e reação.
    async fn process_message(
        self: &Arc<Self>,
        info: &wa::WebMessageInfo,
        key_extras: &MessageKeyExtras,
        _sink: &WsSink,
    ) {
        let (Some(message), Some(key)) = (info.message.as_ref(), info.key.as_ref()) else {
            return;
        };
        let content = normalize_message_content(message);
        if let Some(protocol) = content.protocol_message.as_deref() {
            self.handle_protocol_message(protocol, info, key, key_extras).await;
        } else if let Some(secret) = content.secret_encrypted_message.as_ref() {
            self.handle_secret_encrypted_message(secret, content, info, key, key_extras).await;
        } else if let Some(reaction) = content.reaction_message.as_ref() {
            // `messages.reaction` com a key da mensagem reagida (já normalizada).
            let reacted = reaction.key.clone().unwrap_or_default();
            let _ = self.events.send(ClientEvent::MessagesReaction {
                reactions: vec![MessageReaction {
                    remote_jid: reacted.remote_jid.unwrap_or_default(),
                    id: reacted.id.unwrap_or_default(),
                    from_me: reacted.from_me.unwrap_or(false),
                    text: reaction.text.clone(),
                    sender_timestamp_ms: reaction.sender_timestamp_ms,
                }],
            });
        }
    }

    /// `case protocolMsg.type` do `processMessage`.
    async fn handle_protocol_message(
        self: &Arc<Self>,
        protocol: &wa::message::ProtocolMessage,
        info: &wa::WebMessageInfo,
        key: &wa::MessageKey,
        key_extras: &MessageKeyExtras,
    ) {
        use wa::message::protocol_message::Type;
        let r#type = protocol.r#type.unwrap_or(-1);
        let target_id = protocol.key.as_ref().and_then(|k| k.id.clone()).unwrap_or_default();

        if r#type == Type::HistorySyncNotification as i32 {
            // Download HTTP fora do loop de leitura.
            if let Some(notification) = protocol.history_sync_notification.clone() {
                let client = self.clone();
                tokio::spawn(async move {
                    client.process_history_sync_notification(&notification).await;
                });
            }
        } else if r#type == Type::AppStateSyncKeyShare as i32 {
            let keys = protocol
                .app_state_sync_key_share
                .as_ref()
                .map(|s| s.keys.as_slice())
                .unwrap_or_default();
            if keys.is_empty() {
                tracing::debug!("recv app state sync with 0 keys");
                return;
            }
            let mut new_key_id = String::new();
            let mut new_keys = Vec::new();
            for app_key in keys {
                let Some(key_id) = app_key.key_id.as_ref().and_then(|k| k.key_id.as_deref()) else {
                    continue;
                };
                let str_key_id = crate::app_state::app_state_key_id_b64(key_id);
                let data = app_key.key_data.clone().unwrap_or_default();
                self.store.store_generic(
                    "app-state-sync-key",
                    &str_key_id,
                    &crate::app_state::app_state_sync_key_json(&data),
                );
                new_keys.push(str_key_id.clone());
                new_key_id = str_key_id;
            }
            tracing::debug!(new_app_state_sync_key_id = %new_key_id, ?new_keys, "injecting new app state sync keys");
            if !new_key_id.is_empty() {
                let mut creds = self.store.creds();
                creds.my_app_state_key_id = Some(new_key_id);
                if self.store.update_creds(creds.clone()).is_ok() {
                    let _ = self.events.send(ClientEvent::CredsUpdate(creds));
                }
            }
        } else if r#type == Type::Revoke as i32 {
            let envelope = MessageUpdateKey::from_envelope(key, key_extras, key.id.clone().unwrap_or_default());
            let _ = self.events.send(ClientEvent::MessagesUpdate {
                updates: vec![MessageStatusUpdate {
                    key: MessageUpdateKey::from_envelope(key, key_extras, target_id),
                    update: MessageUpdateData {
                        message: Some(serde_json::Value::Null),
                        message_stub_type: Some(wa::web_message_info::StubType::Revoke as i32),
                        key: Some(envelope),
                        ..Default::default()
                    },
                }],
            });
        } else if r#type == Type::PeerDataOperationRequestResponseMessage as i32 {
            let Some(response) = protocol.peer_data_operation_request_response_message.as_ref() else {
                return;
            };
            if let Some(stanza_id) = &response.stanza_id {
                self.placeholder_resend_cache.remove(stanza_id).await;
            }
            for result in &response.peer_data_operation_result {
                let Some(bytes) = result
                    .placeholder_message_resend_response
                    .as_ref()
                    .and_then(|r| r.web_message_info_bytes.clone())
                else {
                    continue;
                };
                let Ok(web_message_info) = wa::WebMessageInfo::decode(bytes.as_slice()) else {
                    continue;
                };
                // `setTimeout(() => ev.emit('messages.upsert', ...), 500)`.
                let client = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let _ = client.events.send(ClientEvent::Message {
                        info: web_message_info,
                        raw: BinaryNode::new("message"),
                        key_extras: MessageKeyExtras::default(),
                    });
                });
            }
        } else if r#type == Type::MessageEdit as i32 {
            self.emit_message_edit(
                key,
                key_extras,
                target_id,
                protocol.edited_message.as_deref(),
                protocol.timestamp_ms,
                info.message_timestamp,
            );
        }
    }

    /// `messages.update` de edição: `{ key: {...message.key, id}, update:
    /// { message: { editedMessage: { message } }, messageTimestamp } }`.
    fn emit_message_edit(
        &self,
        key: &wa::MessageKey,
        key_extras: &MessageKeyExtras,
        target_id: String,
        edited: Option<&wa::Message>,
        timestamp_ms: Option<i64>,
        fallback_timestamp: Option<u64>,
    ) {
        let edited_message = match edited {
            Some(m) => serde_json::json!({ "message": baileys_proto::proto_to_json_value(m) }),
            None => serde_json::json!({}),
        };
        let message_timestamp = timestamp_ms
            .filter(|ms| *ms != 0)
            .map(|ms| (ms / 1000) as u64)
            .or(fallback_timestamp);
        let _ = self.events.send(ClientEvent::MessagesUpdate {
            updates: vec![MessageStatusUpdate {
                key: MessageUpdateKey::from_envelope(key, key_extras, target_id),
                update: MessageUpdateData {
                    message: Some(serde_json::json!({ "editedMessage": edited_message })),
                    message_timestamp,
                    ..Default::default()
                },
            }],
        });
    }

    /// `secretEncryptedMessage` (`MESSAGE_EDIT`): decifra com o
    /// `messageSecret` da própria edição ou, na falta, da mensagem original.
    async fn handle_secret_encrypted_message(
        &self,
        secret: &wa::message::SecretEncryptedMessage,
        content: &wa::Message,
        info: &wa::WebMessageInfo,
        key: &wa::MessageKey,
        key_extras: &MessageKeyExtras,
    ) {
        use wa::message::secret_encrypted_message::SecretEncType;
        if secret.secret_enc_type != Some(SecretEncType::MessageEdit as i32) {
            return;
        }
        let Some(target_key) = secret.target_message_key.as_ref() else {
            return;
        };
        let Some(target_id) = target_key.id.clone().filter(|id| !id.is_empty()) else {
            return;
        };

        let chat_jid = if key.from_me.unwrap_or(false) {
            let me_lid = self.store.creds().me.and_then(|m| m.lid).unwrap_or_default();
            baileys_core::jid_normalized_user(&me_lid)
        } else {
            let source = key_extras
                .sender_lid
                .clone()
                .or_else(|| key_extras.participant_lid.clone())
                .or_else(|| key.remote_jid.clone())
                .unwrap_or_default();
            baileys_core::jid_normalized_user(&source)
        };

        let mut message_secret = content
            .message_context_info
            .as_ref()
            .and_then(|c| c.message_secret.clone())
            .filter(|s| !s.is_empty());
        if message_secret.is_none() {
            // `getMessage(targetKey)`.
            let load = self.load_message_fn.lock().await.clone();
            if let Some(load) = load {
                let remote = target_key.remote_jid.clone().unwrap_or_default();
                if let Some(bytes) = load(target_id.clone(), remote).await {
                    message_secret = wa::Message::decode(bytes.as_slice())
                        .ok()
                        .and_then(|m| m.message_context_info)
                        .and_then(|c| c.message_secret)
                        .filter(|s| !s.is_empty());
                }
            }
            tracing::debug!(
                target_id,
                has_fallback_secret = message_secret.is_some(),
                "secretEncryptedMessage: messageSecret missing on edit, tried original message fallback"
            );
        }
        let Some(message_secret) = message_secret else {
            return;
        };

        match decrypt_secret_encrypted_edit(secret, &message_secret, &target_id, &chat_jid) {
            Ok(decrypted) => {
                if let Some(edit) = decrypted.protocol_message.as_deref() {
                    if edit.edited_message.is_some() {
                        self.emit_message_edit(
                            key,
                            key_extras,
                            target_id,
                            edit.edited_message.as_deref(),
                            edit.timestamp_ms,
                            info.message_timestamp,
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, target_id, "failed to decrypt secretEncryptedMessage edit");
            }
        }
    }

    /// `HISTORY_SYNC_NOTIFICATION` → `messaging-history.set`.
    async fn process_history_sync_notification(&self, notification: &wa::message::HistorySyncNotification) {
        let sync_type = notification.sync_type.unwrap_or(0);
        let progress = notification.progress.unwrap_or(0);
        let is_latest = progress >= 100;

        // Inline bootstrap payload (initialHistBootstrapInlinePayload)
        // ou download via directPath (mediaKey + fileEncSha256).
        let mut history: Option<wa::HistorySync> = None;
        if let Some(inline) = &notification.initial_hist_bootstrap_inline_payload {
            if let Ok(decoded) = wa::HistorySync::decode(inline.as_slice()) {
                history = Some(decoded);
            }
        } else if let Some(decoded) = self.download_history_sync(notification).await {
            history = Some(decoded);
        }

        if let Some(h) = history {
            // `processHistoryMessage`: tcToken das conversas → `contacts-tc-token`
            // (chave `lidJid || id`).
            for chat in &h.conversations {
                let Some(token) = chat.tc_token.as_deref().filter(|t| !t.is_empty()) else {
                    continue;
                };
                let label = chat
                    .lid_jid
                    .as_deref()
                    .filter(|l| !l.is_empty())
                    .or(chat.id.as_deref())
                    .unwrap_or_default();
                self.store_tc_token(
                    label,
                    token,
                    chat.tc_token_timestamp.map(|t| t.to_string()),
                    chat.tc_token_sender_timestamp.map(|t| t as i64),
                );
            }

            // `messages` extraído direto (sem reter `Conversation`
            // completo: o consumidor só usa `data.messages`).
            let messages: Vec<wa::WebMessageInfo> = h
                .conversations
                .into_iter()
                .flat_map(|c| c.messages)
                .filter_map(|m| m.message)
                .collect();
            let contacts: Vec<serde_json::Value> = h
                .pushnames
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "pushName": p.pushname,
                    })
                })
                .collect();
            let _ = self.events.send(ClientEvent::MessagingHistorySet {
                data: MessagingHistorySet {
                    contacts,
                    messages,
                    is_latest,
                    progress,
                    sync_type,
                },
            });
        }
    }

    /// Baixa e decodifica um `HistorySync` do CDN (port de
    /// `downloadAndProcessHistorySyncNotification`).
    async fn download_history_sync(
        &self,
        notification: &wa::message::HistorySyncNotification,
    ) -> Option<wa::HistorySync> {
        let direct_path = notification.direct_path.as_ref()?;
        let media_key = notification.media_key.as_ref()?;
        if direct_path.is_empty() || media_key.is_empty() {
            return None;
        }

        let url = baileys_media::url_from_direct_path(direct_path);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .ok()?;
        let bytes = client.get(&url).send().await.ok()?.bytes().await.ok()?;

        // Keys: HKDF "WhatsApp History Keys" (mesma derivação do Baileys).
        let expanded = baileys_crypto::hkdf(
            media_key,
            80,
            None,
            "WhatsApp History Keys",
        )
        .ok()?;
        let iv = &expanded[0..16];
        let cipher_key = &expanded[16..48];
        let _mac_key = &expanded[48..80];

        // ciphertext || mac(32) — remove o tail de MAC e alinha a 16 bytes.
        let body = &bytes[..(bytes.len() / 16) * 16];
        // `aes_decrypt_cbc` já remove o PKCS7 (como o `aes.final()` do Node).
        let data = baileys_crypto::aes_decrypt_cbc(body, cipher_key, iv).ok()?;

        // `inflatePromise(buffer)` do Node (zlib); gzip mantido por compatibilidade.
        let decoded: Vec<u8> = {
            use std::io::Read;
            let mut out = Vec::new();
            if data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b {
                flate2::read::GzDecoder::new(data.as_slice()).read_to_end(&mut out).ok()?;
            } else {
                flate2::read::ZlibDecoder::new(data.as_slice()).read_to_end(&mut out).ok()?;
            }
            out
        };

        wa::HistorySync::decode(decoded.as_slice()).ok()
    }

    async fn send_message_ack(
        &self,
        node: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let mut ack = BinaryNode::new("ack")
            .with_attr("id", node.attr("id").unwrap_or_default())
            .with_attr("to", node.attr("from").unwrap_or_default())
            .with_attr("class", &node.tag);
        if let Some(participant) = node.attr("participant") {
            ack = ack.with_attr("participant", participant);
        }
        if let Some(recipient) = node.attr("recipient") {
            ack = ack.with_attr("recipient", recipient);
        }
        // Hineken: `!!attrs.type && (tag !== 'message' || unavailable ||
        // errorCode !== 0)` — sem `errorCode` (undefined) a condição é sempre
        // verdadeira, então o `type` entra sempre. Para `unavailable`, o
        // `from` do ack vira o próprio `me.id`.
        let has_unavailable = node.child("unavailable").is_some();
        if let Some(r#type) = node.attr("type") {
            ack = ack.with_attr("type", r#type);
        }
        if node.tag == "message" && has_unavailable {
            let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
            ack = ack.with_attr("from", me_id);
        }
        self.send_node(&ack, sink).await
    }

    /// `sendReceipt`.
    async fn send_receipt(
        &self,
        jid: &str,
        participant: Option<&str>,
        message_ids: &[String],
        r#type: Option<&str>,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        if message_ids.is_empty() {
            return Ok(());
        }
        let mut node = BinaryNode::new("receipt").with_attr("id", &message_ids[0]);
        if matches!(r#type, Some("read") | Some("read-self")) {
            node = node.with_attr("t", chrono_now_secs().to_string());
        }
        if r#type == Some("sender") && is_jid_user(jid) {
            node = node
                .with_attr("recipient", jid)
                .with_attr("to", participant.unwrap_or_default());
        } else {
            node = node.with_attr("to", jid);
            if let Some(p) = participant {
                node = node.with_attr("participant", p);
            }
        }
        if let Some(t) = r#type {
            node = node.with_attr("type", t);
        }

        if message_ids.len() > 1 {
            let list = BinaryNode::new("list").with_children(
                message_ids[1..]
                    .iter()
                    .map(|id| BinaryNode::new("item").with_attr("id", id))
                    .collect(),
            );
            node = node.with_children(vec![list]);
        }
        self.send_node(&node, sink).await
    }

    /// `sendRetryRequest` (Node) — pede re-entrega de uma mensagem que não
    /// conseguiu descriptografar (sender key ausente, sessão ausente etc.).
    ///
    /// Port fiel do Hineken (2 estágios):
    /// - 1ª tentativa: envia `<receipt type="retry">` para o remetente com o
    ///   `<retry count="1">`, `<registration>` e o bundle `<keys>` (type 05,
    ///   identity, pre-key, skey, device-identity).
    /// - 2ª tentativa em diante: pede a mesma mensagem ao celular (device 0)
    ///   via PDO `PLACEHOLDER_MESSAGE_RESEND`.
    async fn send_retry_request(
        self: &Arc<Self>,
        node: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let msg_id = node.attr("id").unwrap_or_default().to_string();
        if msg_id.is_empty() {
            return Ok(());
        }

        // `decodeMessageNode(node).fullMessage.key` (key crua).
        let Some(msg_key) = self.decode_message_node(node).and_then(|d| d.full.key) else {
            return Ok(());
        };
        let remote_jid = msg_key.remote_jid.clone().unwrap_or_default();
        let cache_key = format!("{msg_id}:{remote_jid}");

        let mut retry_count = self.msg_retry_cache.get(&cache_key).await.unwrap_or(0);
        if retry_count >= self.config.max_msg_retry_count {
            tracing::debug!(retry_count, msg_id, "reached retry limit, clearing");
            return Ok(());
        }
        retry_count += 1;
        self.msg_retry_cache.set(cache_key.clone(), retry_count).await;

        // Segunda tentativa: o receipt com keys já foi. Pede a mesma mensagem
        // ao celular e para.
        if retry_count > 1 {
            tracing::debug!(msg_id, retry_count, "requesting phone resend after key retry");
            if self.sink().await.is_some() {
                if let Err(e) = self.request_placeholder_resend(msg_key, sink).await {
                    tracing::warn!(error = %e, msg_id, "failed to request placeholder resend");
                }
            }
            return Ok(());
        }

        let creds = self.store.creds();
        let registration = baileys_core::ids::encode_big_endian(creds.registration_id, 4);

        let retry = BinaryNode::new("retry")
            .with_attr("count", retry_count.to_string())
            .with_attr("id", node.attr("id").unwrap_or_default())
            .with_attr("t", node.attr("t").unwrap_or_default())
            .with_attr("v", "1");
        let registration_node = BinaryNode::new("registration").with_bytes(registration);

        let mut receipt = BinaryNode::new("receipt")
            .with_attr("id", &msg_id)
            .with_attr("type", "retry")
            .with_attr("to", node.attr("from").unwrap_or_default());

        if let Some(recipient) = node.attr("recipient") {
            receipt = receipt.with_attr("recipient", recipient);
        }
        if let Some(participant) = node.attr("participant") {
            receipt = receipt.with_attr("participant", participant);
        }

        // Sempre inclui o bundle `<keys>` na primeira tentativa (como o Node
        // faz com `forceIncludeKeys || retryCount >= 1`). O bundle permite que
        // o remetente injete nossa sessão e re-criptografe a resposta.
        let identity_pub = decode_buffer(&creds.signed_identity_key.public);
        let spk_pub = decode_buffer(&creds.signed_pre_key.key_pair.public);
        let spk_sig = decode_buffer(&creds.signed_pre_key.signature);

        let device_identity = creds
            .account
            .as_ref()
            .and_then(|a| crate::handshake::encode_signed_device_identity(a, true));

        // Uma pre-key fresca (primeira não usada) para o bundle.
        let pre_key_node = self.next_pre_key_node().await?;

        let mut keys_children = vec![
            BinaryNode::new("type").with_bytes(vec![baileys_core::constants::KEY_BUNDLE_TYPE[0]]),
            BinaryNode::new("identity").with_bytes(identity_pub),
            pre_key_node,
            BinaryNode::new("skey").with_children(vec![
                BinaryNode::new("id")
                    .with_bytes(baileys_core::ids::encode_big_endian(creds.signed_pre_key.key_id, 3)),
                BinaryNode::new("value").with_bytes(spk_pub),
                BinaryNode::new("signature").with_bytes(spk_sig),
            ]),
        ];
        if let Some(di) = device_identity {
            keys_children.push(BinaryNode::new("device-identity").with_bytes(di));
        }
        receipt = receipt.with_children(vec![
            retry,
            registration_node,
            BinaryNode::new("keys").with_children(keys_children),
        ]);

        self.send_node(&receipt, sink).await?;
        tracing::debug!(msg_id, retry_count, "receipt de retry com keys enviado");
        Ok(())
    }

    /// Busca (ou gera) uma pre-key fresca para incluir no bundle de retry —
    /// espelha `getNextPreKeys(state, 1)` do Node.
    async fn next_pre_key_node(&self) -> Result<BinaryNode, ClientError> {
        let mut creds = self.store.creds();

        // Garante pelo menos uma pre-key não usada (gera se preciso).
        let available = creds
            .next_pre_key_id
            .saturating_sub(creds.first_unuploaded_pre_key_id);
        if available == 0 {
            let id = creds.next_pre_key_id;
            let kp = baileys_crypto::Curve::generate_key_pair();
            let serialized = baileys_store::creds::SerializedKeyPair {
                public: to_buffer(&kp.public),
                private: to_buffer(&kp.private),
            };
            self.store.store_pre_key(id, &serialized)?;
            creds.next_pre_key_id = id + 1;
        }

        // Lê a primeira pre-key não usada.
        let id = creds.first_unuploaded_pre_key_id;
        let public = if let Some((pubk, _)) = self.store.load_pre_key(id)? {
            pubk
        } else {
            // Fallback: a pre-key `first_unuploaded` não existe no store
            // (foi consumida por `remove_pre_key` após uso, mas o cursor não
            // avançou). Gera E PERSISTE — a private key precisa existir para
            // decriptar quando o remetente usar essa pre-key do bundle. O
            // fallback antigo só gerava a pública, e o `load_pre_key(id)`
            // retornava None → `invalid pre-key ID` na retransmissão.
            let kp = baileys_crypto::Curve::generate_key_pair();
            let serialized = baileys_store::creds::SerializedKeyPair {
                public: to_buffer(&kp.public),
                private: to_buffer(&kp.private),
            };
            self.store.store_pre_key(id, &serialized)?;
            kp.public
        };

        // Avança o cursor de pre-keys não usadas e persiste — port de
        // `firstUnuploadedPreKeyId = Math.max(firstUnuploaded, lastPreKeyId + 1)`
        // do `getNextPreKeys`. Sem isso, o mesmo ID vai em todo bundle de
        // retry e o remetente rejeita com `invalid pre-key ID`.
        creds.first_unuploaded_pre_key_id = creds.first_unuploaded_pre_key_id.max(id + 1);
        self.store.update_creds(creds.clone())?;
        let _ = self.events.send(ClientEvent::CredsUpdate(creds));

        Ok(BinaryNode::new("key").with_children(vec![
            BinaryNode::new("id").with_bytes(baileys_core::ids::encode_big_endian(id, 3)),
            BinaryNode::new("value").with_bytes(public),
        ]))
    }

    /// Retry MANUAL com payload dinâmico (usado pelo `/manager/retry`).
    ///
    /// Monta o `<receipt type="retry">` igual ao `sendRetryRequest` do Hineken,
    /// mas com `to`, `participant`, `recipient`, `retry_count`, `force_include_keys`
    /// e `assert_session` definidos pelo operador. Retorna o nó enviado para
    /// que o manager salve o payload (e o operador compare com o que retornou).
    pub async fn debug_send_retry(
        &self,
        params: DebugRetryParams,
        sink: &WsSink,
    ) -> Result<BinaryNode, ClientError> {
        let msg_id = params.msg_id.clone();
        if msg_id.is_empty() || params.to.is_empty() {
            return Err(ClientError::InvalidParams(
                "msgId e to são obrigatórios".to_string(),
            ));
        }

        // assertSessions opcional (forçado) antes do receipt — o operador
        // testa com/sem para ver qual combinação faz o peer re-cifrar.
        if params.assert_session {
            self.assert_sessions(&[params.to.clone()], true, None, sink)
                .await?;
        }

        let creds = self.store.creds();
        let registration = baileys_core::ids::encode_big_endian(creds.registration_id, 4);

        let retry_count = params.retry_count.max(1);
        let retry = BinaryNode::new("retry")
            .with_attr("count", retry_count.to_string())
            .with_attr("id", params.retry_id.clone().unwrap_or_else(|| msg_id.clone()))
            .with_attr("t", params.retry_t.clone().unwrap_or_default())
            .with_attr("v", "1");
        let registration_node = BinaryNode::new("registration").with_bytes(registration);

        let mut receipt = BinaryNode::new("receipt")
            .with_attr("id", &msg_id)
            .with_attr("type", "retry")
            .with_attr("to", &params.to);

        if let Some(r) = &params.recipient {
            receipt = receipt.with_attr("recipient", r);
        }
        if let Some(p) = &params.participant {
            receipt = receipt.with_attr("participant", p);
        }

        let mut children = vec![retry, registration_node];
        if params.force_include_keys {
            let identity_pub = decode_buffer(&creds.signed_identity_key.public);
            let spk_pub = decode_buffer(&creds.signed_pre_key.key_pair.public);
            let spk_sig = decode_buffer(&creds.signed_pre_key.signature);

            let device_identity = creds
                .account
                .as_ref()
                .and_then(|a| crate::handshake::encode_signed_device_identity(a, true));

            // Uma pre-key fresca (primeira não usada) para o bundle.
            let pre_key_node = self.next_pre_key_node().await?;

            let mut keys_children = vec![
                BinaryNode::new("type").with_bytes(vec![baileys_core::constants::KEY_BUNDLE_TYPE[0]]),
                BinaryNode::new("identity").with_bytes(identity_pub),
                pre_key_node,
                BinaryNode::new("skey").with_children(vec![
                    BinaryNode::new("id")
                        .with_bytes(baileys_core::ids::encode_big_endian(creds.signed_pre_key.key_id, 3)),
                    BinaryNode::new("value").with_bytes(spk_pub),
                    BinaryNode::new("signature").with_bytes(spk_sig),
                ]),
            ];
            if let Some(di) = device_identity {
                keys_children.push(BinaryNode::new("device-identity").with_bytes(di));
            }
            children.push(BinaryNode::new("keys").with_children(keys_children));
        }

        let receipt = receipt.with_children(children);
        self.send_node(&receipt, sink).await?;
        tracing::debug!(
            msg_id = %msg_id,
            to = %params.to,
            retry_count,
            force_include_keys = params.force_include_keys,
            assert_session = params.assert_session,
            "retry manual enviado"
        );
        Ok(receipt)
    }

    /// `requestPlaceholderResend` — pede a re-entrega de uma mensagem ao
    /// celular (device 0) via PDO `PLACEHOLDER_MESSAGE_RESEND`.
    async fn request_placeholder_resend(
        &self,
        msg_key: wa::MessageKey,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let msg_id = msg_key.id.clone().unwrap_or_default();
        if msg_id.is_empty() {
            return Ok(());
        }
        if self.placeholder_resend_cache.contains(&msg_id).await {
            tracing::debug!(msg_id, "placeholder resend já solicitado");
            return Ok(());
        }
        self.placeholder_resend_cache.set(msg_id.clone(), ()).await;

        let pdo = wa::message::PeerDataOperationRequestMessage {
            peer_data_operation_request_type: Some(
                wa::message::PeerDataOperationRequestType::PlaceholderMessageResend as i32,
            ),
            placeholder_message_resend_request: vec![
                wa::message::peer_data_operation_request_message::PlaceholderMessageResendRequest {
                    message_key: Some(msg_key),
                },
            ],
            ..Default::default()
        };
        self.send_peer_data_operation_message(pdo, sink).await
    }

    /// `sendPeerDataOperationMessage` — envia um `ProtocolMessage` PDO para o
    /// próprio `me.id` (peer), com `category: peer` e
    /// `push_priority: high_force`.
    async fn send_peer_data_operation_message(
        &self,
        pdo_message: wa::message::PeerDataOperationRequestMessage,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        if me_id.is_empty() {
            return Err(ClientError::NotAuthenticated);
        }

        let protocol = wa::message::ProtocolMessage {
            peer_data_operation_request_message: Some(pdo_message),
            r#type: Some(
                wa::message::protocol_message::Type::PeerDataOperationRequestMessage as i32,
            ),
            ..Default::default()
        };
        let message = wa::Message {
            protocol_message: Some(Box::new(protocol)),
            ..Default::default()
        };

        // Node: `relayMessage(meJid, protocolMessage, ...)` com
        // `meJid = jidNormalizedUser(creds.me.id)` — sem device, ou seja, o
        // device 0 (celular), que é quem processa o PDO e reenvia a mensagem.
        // Enviar para `me.id` cru (ex: `:28`) mandaria o PDO para nós mesmos.
        let me_jid = baileys_core::jid_normalized_user(&me_id);
        self.send_peer_message(&me_jid, message, sink).await
    }

    /// `relayMessage` para peer messages (PDO) — envia 1:1 para `me.id` com
    /// os atributos extras `category=peer` e `push_priority=high_force`, e
    /// empurra o `<enc>` direto (sem `<participants>`), além do nó `<meta
    /// appdata="default">`.
    async fn send_peer_message(
        &self,
        jid: &str,
        message: wa::Message,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        let msg_id = generate_message_id_v2(Some(&me_id));

        // Destino da sessão E2E: o device 0 do celular, derivado do meJid
        // normalizado (`jid`). `me_lid` é o device deste companion (ex: :28);
        // usar `me_lid` direto endereçaria a sessão para nós mesmos, e o PDO
        // não chegaria ao celular que processa o PLACEHOLDER_MESSAGE_RESEND.
        let dest = convert_lid_device(jid, None, &me_id, &me_lid);

        // Garante a sessão E2E com o device de destino ANTES de criptografar.
        // Sem isso, o `encrypt_message` falha com `no session record` e o PDO
        // (PLACEHOLDER_MESSAGE_RESEND) nunca sai — quebrava a recuperação de
        // status/retry na 2ª tentativa. O Node faz isso no `relayMessage`
        // (assertSessions antes de createParticipantNodes).
        self.assert_sessions(&[dest.clone()], false, None, sink).await?;

        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
        let enc = repo.encrypt_message(&dest, &write_random_pad_max16(&message.encode_to_vec()))?;

        let enc_node = BinaryNode::new("enc")
            .with_attr("v", "2")
            .with_attr("type", &enc.r#type)
            .with_bytes(enc.ciphertext);

        let mut children = vec![enc_node, BinaryNode::new("meta").with_attr("appdata", "default")];
        if enc.r#type == "pkmsg" {
            if let Some(account) = self.store.creds().account {
                if let Some(encoded) = crate::handshake::encode_signed_device_identity(&account, true) {
                    children.push(BinaryNode::new("device-identity").with_bytes(encoded));
                }
            }
        }

        let stanza = BinaryNode::new("message")
            .with_attr("id", &msg_id)
            .with_attr("type", "text")
            .with_attr("to", jid)
            .with_attr("category", "peer")
            .with_attr("push_priority", "high_force")
            .with_children(children);

        self.send_node(&stanza, sink).await?;
        tracing::debug!(msg_id, jid, "peer data operation enviada");
        Ok(())
    }

    /// `handleReceipt` — responde ao `<receipt>` de entrada.
    ///
    /// Para `type="retry"`, reenvia a mensagem (port de `sendMessagesAgain` +
    /// `relayMessage` do Node): re-garante sessão com o participante (forçada)
    /// e re-cifra o conteúdo lido do store (`getMessage`), respeitando grupo
    /// (sender-key) vs PV (deviceSentMessage).
    async fn handle_receipt(
        &self,
        node: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let receipt_type = node.attr("type").unwrap_or_default().to_string();
        let from = node.attr("from").unwrap_or_default().to_string();
        let participant = node.attr("participant").map(String::from);
        let recipient = node.attr("recipient").map(String::from);
        let msg_id = node.attr("id").unwrap_or_default().to_string();

        tracing::debug!(
            receipt_type,
            from,
            participant,
            msg_id,
            "receipt recebido"
        );

        // `shouldIgnoreJid(remoteJid)` sem `<retry>`: só ack.
        if self.should_ignore_jid(&from) && node.child("retry").is_none() {
            tracing::debug!(from, "ignoring receipt from jid");
            return self.send_message_ack(node, sink).await;
        }

        // `message-receipt.update` / `messages.update` — port exato do
        // `handleReceipt` do Hineken (messages-recv.ts). Só emite para
        // `type != "retry"` (retry é processado abaixo).
        if receipt_type != "retry" && !msg_id.is_empty() {
            // `ids = [attrs.id]` + ids dos filhos `<item>` de `content[0]`.
            let mut ids: Vec<String> = vec![msg_id.clone()];
            if let Some(baileys_core::BinaryContent::Children(children)) = &node.content {
                if let Some(first) = children.first() {
                    for item in first.children("item") {
                        if let Some(id) = item.attr("id") {
                            ids.push(id.to_string());
                        }
                    }
                }
            }

            // `isLid` + `isNodeFromMe` (Node usa me.lid ou me.id conforme o from).
            let me = self.store.creds().me.clone();
            let me_id = me.as_ref().map(|m| m.id.clone()).unwrap_or_default();
            let me_lid = me.and_then(|m| m.lid).unwrap_or_else(|| me_id.clone());
            let is_lid = from.ends_with("@lid");
            let p_or_from = participant.clone().unwrap_or_else(|| from.clone());
            let is_node_from_me = if is_lid {
                are_jids_same_user(&p_or_from, &me_lid)
            } else {
                are_jids_same_user(&p_or_from, &me_id)
            };

            // `remoteJid` e `fromMe` do Node.
            let remote = if !is_node_from_me || baileys_core::is_jid_group(&from) {
                from.clone()
            } else {
                recipient.clone().unwrap_or_else(|| from.clone())
            };
            let from_me = recipient.is_none()
                || ((receipt_type == "retry" || receipt_type == "sender") && is_node_from_me);
            // O `from` do receipt traz o device de quem leu/recebeu
            // (`user:77@lid`); o webhook espera o chat sem device.
            let remote = Some(baileys_core::jid_normalized_user(&remote))
                .filter(|r| !r.is_empty())
                .unwrap_or(remote);

            let status = get_status_from_receipt_type(node.attr("type"));

            // `status >= PENDING || !isNodeFromMe`.
            let status_ok = status.map(|s| s >= wa::web_message_info::Status::Pending as i32).unwrap_or(false);
            if status_ok || !is_node_from_me {
                let t = node.attr("t").and_then(|v| v.parse::<i64>().ok());

                if baileys_core::is_jid_group(&remote) || baileys_core::is_jid_status_broadcast(&remote) {
                    // Grupo/broadcast: `message-receipt.update` quando há participant.
                    if let Some(ref participant_jid) = participant {
                        let update_key = if status == Some(wa::web_message_info::Status::DeliveryAck as i32) {
                            "receiptTimestamp"
                        } else {
                            "readTimestamp"
                        };
                        let user_jid = baileys_core::jid_normalized_user(participant_jid);
                        let receipts: Vec<MessageReceiptUpdate> = ids
                            .iter()
                            .map(|id| MessageReceiptUpdate {
                                key: MessageUpdateKey {
                                    remote_jid: remote.clone(),
                                    id: id.clone(),
                                    from_me,
                                    participant: Some(participant_jid.clone()),
                                    ..Default::default()
                                },
                                receipt: UserReceipt {
                                    user_jid: user_jid.clone(),
                                    receipt_timestamp: if update_key == "receiptTimestamp" { t } else { None },
                                    read_timestamp: if update_key == "readTimestamp" { t } else { None },
                                },
                            })
                            .collect();
                        let _ = self.events.send(ClientEvent::MessageReceiptUpdate { updates: receipts });
                    }
                } else {
                    // 1:1: `messages.update` com `update: { status }`.
                    let updates: Vec<MessageStatusUpdate> = ids
                        .iter()
                        .map(|id| MessageStatusUpdate {
                            key: MessageUpdateKey {
                                remote_jid: remote.clone(),
                                id: id.clone(),
                                from_me,
                                participant: participant.clone(),
                                ..Default::default()
                            },
                            update: MessageUpdateData {
                                status,
                                ..Default::default()
                            },
                        })
                        .collect();
                    let _ = self.events.send(ClientEvent::MessagesUpdate { updates });
                }
            }
        }

        if receipt_type == "retry" {
            let _ = self.events.send(ClientEvent::RetryReceipt { node: node.clone() });
        }

        if receipt_type != "retry" {
            // Node manda o ack no `finally` — para não-retry, sem retry
            // abaixo, o ack sai aqui (mesmo efeito do `finally` do Node).
            self.send_message_ack(node, sink).await?;
            return Ok(());
        }
        if msg_id.is_empty() {
            // Sem id não há retry a processar — ack e sai.
            self.send_message_ack(node, sink).await?;
            return Ok(());
        }

        // Node manda o ack no `finally` (depois do processamento do retry, ou
        // mesmo quando o retry falha/no-op). Processa o retry e garante o ack
        // ao final de qualquer caminho.
        if let Err(e) = self.process_retry(node, sink).await {
            tracing::warn!(error = %e, msg_id, "retry: processamento falhou (ack enviado mesmo assim)");
        }
        self.send_message_ack(node, sink).await?;
        Ok(())
    }

    /// Port de `sendMessagesAgain` + `relayMessage` do Node para `type=retry`.
    async fn process_retry(&self, node: &BinaryNode, sink: &WsSink) -> Result<(), ClientError> {
        let receipt_type = node.attr("type").unwrap_or_default().to_string();
        let from = node.attr("from").unwrap_or_default().to_string();
        let participant = node.attr("participant").map(String::from);
        let recipient = node.attr("recipient").map(String::from);
        let msg_id = node.attr("id").unwrap_or_default().to_string();
        let _ = receipt_type;

        // Serializa o processamento de retry (port do `retryMutex` do Node).
        let _retry_guard = self.retry_mutex.lock().await;

        tracing::debug!(msg_id, participant, "retry: processando em task separada");

        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        // Port EXATO do bloco retry de `handleReceipt` (Node,
        // messages-recv.js:690-693):
        //   const isLid = attrs.from.includes('lid');
        //   const isNodeFromMe = areJidsSameUser(attrs.participant || attrs.from,
        //       isLid ? me.lid : me.id);
        //   const remoteJid = !isNodeFromMe || isJidGroup(attrs.from) ||
        //       !attrs.recipient ? attrs.from : attrs.recipient;
        let is_lid = from.contains("lid");
        let p_or_from = participant.clone().unwrap_or_else(|| from.clone());
        let is_node_from_me = if is_lid {
            are_jids_same_user(&p_or_from, &me_lid)
        } else {
            are_jids_same_user(&p_or_from, &me_id)
        };
        let remote = if !is_node_from_me || baileys_core::is_jid_group(&from) || recipient.is_none() {
            from.clone()
        } else {
            recipient.clone().unwrap_or_default()
        };

        // `retryParticipantJid = attrs.participant || (!isJidGroup(attrs.from) ?
        // attrs.from : undefined)` (Node `handleReceipt`, messages-recv.js:693).
        //
        // IMPORTANTE: para grupo SEM `attrs.participant`, o Node deixa
        // `retryParticipantJid` como `undefined` (NÃO usa o jid do grupo). Isso
        // faz `relayMessage` cair no branch `isGroup && !participant` com
        // `isretry` — reenvia SÓ o `skmsg`, sem fanout e sem distribuir sender
        // key. O `sendMessagesAgain` (com `sendToAll`) é código MORTO no Node;
        // o fluxo real não decide por device.
        let retry_participant: Option<String> = participant.clone().or_else(|| {
            if !baileys_core::is_jid_group(&from) {
                Some(from.clone())
            } else {
                None
            }
        });

        // `key.participant = key.participant || attrs.from` +
        // `willSendMessageAgain(ids[0], key.participant)`.
        let will_key = format!("{msg_id}:{}", participant.clone().unwrap_or_else(|| from.clone()));
        if self.msg_retry_cache.get(&will_key).await.unwrap_or(0) >= self.config.max_msg_retry_count {
            tracing::debug!(msg_id, "will not send message again, as sent too many times");
            return Ok(());
        }
        // `key.fromMe` do `handleReceipt` (`!attrs.recipient || isNodeFromMe` em retry).
        if !(recipient.is_none() || is_node_from_me) {
            tracing::debug!(msg_id, "recv retry for not fromMe message");
            return Ok(());
        }

        // `catch` do Node: `msgRetryCache.flushAll()`.
        let result = self
            .resend_retry(node, sink, &msg_id, &remote, retry_participant)
            .await;
        if let Err(e) = &result {
            tracing::error!(msg_id, error = %e, "error in sending message again");
            self.msg_retry_cache.clear().await;
        }
        result
    }

    /// Corpo do `try` do retry no `handleReceipt` (Hineken `messages-recv.ts` 885–951).
    async fn resend_retry(
        &self,
        node: &BinaryNode,
        sink: &WsSink,
        msg_id: &str,
        remote: &str,
        retry_participant: Option<String>,
    ) -> Result<(), ClientError> {
        let from = node.attr("from").unwrap_or_default().to_string();
        let msg_id = msg_id.to_string();
        let remote = remote.to_string();

        let cache_key = format!("{msg_id}:{remote}");
        let mut retry_count = self.msg_retry_cache.get(&cache_key).await.unwrap_or(0);
        if retry_count >= self.config.max_msg_retry_count {
            tracing::debug!(retry_count, cache_key, "reached retry limit, clearing");
            return Ok(());
        }
        retry_count += 1;
        self.msg_retry_cache.set(cache_key, retry_count).await;

        if baileys_core::is_jid_group(&remote) {
            self.sender_key_memory.remove(&remote).await;
        }

        // Tenta extrair e injetar a sessão E2E do bundle `<keys>` do retry
        // (port de `extractE2ESessionFromRetryReceipt`).
        //
        // Node: `if (bundle && retryParticipantJid)` — só injeta quando há
        // `retryParticipantJid`. Para grupo sem participant, não há bundle.
        let mut injected_from_bundle = false;
        let child_tags: Vec<String> = match &node.content {
            Some(baileys_core::BinaryContent::Children(children)) => {
                children.iter().map(|c| c.tag.clone()).collect()
            }
            _ => Vec::new(),
        };
        tracing::debug!(msg_id, from = %from, ?child_tags, retry_participant, "retry receipt recebido");
        if let (Some(retry_participant_jid), Some(keys)) = (retry_participant.as_deref(), node.child("keys")) {
            let identity = keys.child_bytes("identity").map(|b| b.to_vec());
            let skey = keys.child("skey");
            let pre_key = keys.child("key");
            let registration = node.child_bytes("registration").and_then(|b| {
                if b.len() >= 4 {
                    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                } else {
                    None
                }
            });

            let extract = |node: Option<&BinaryNode>| -> Option<(u32, Vec<u8>)> {
                let node = node?;
                let id = node.child_bytes("id").and_then(|b| {
                    if b.len() >= 3 {
                        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
                    } else {
                        None
                    }
                })?;
                let value = node.child_bytes("value").map(|b| baileys_crypto::generate_signal_pub_key(b))?;
                Some((id, value))
            };

            let bundle = (
                identity.clone(),
                extract(skey),
                skey.and_then(|s| s.child_bytes("signature").map(|b| b.to_vec())),
                extract(pre_key),
                registration,
            );
            if let (Some(identity), Some((sk_id, sk_pub)), Some(sk_sig), Some((pk_id, pk_pub)), Some(registration)) = bundle {
                let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
                // Node: `injectE2ESession({ jid: retryParticipantJid })` — JID cru.
                let dest = retry_participant_jid.to_string();
                match repo.inject_e2e_session(
                    &dest,
                    InjectSession {
                        registration_id: registration,
                        identity_key: baileys_crypto::generate_signal_pub_key(&identity),
                        signed_pre_key: InjectSignedPreKey {
                            key_id: sk_id,
                            public_key: sk_pub,
                            signature: sk_sig,
                        },
                        pre_key: Some(InjectPreKey {
                            key_id: pk_id,
                            public_key: pk_pub,
                            signature: vec![],
                        }),
                    },
                ) {
                    Ok(()) => {
                        tracing::debug!(retry_participant_jid, dest, "sessão E2E injetada do bundle de retry");
                        injected_from_bundle = true;
                    }
                    Err(e) => tracing::warn!(retry_participant_jid, error = %e, "falha ao injetar bundle de retry"),
                }
            } else {
                tracing::debug!(msg_id, has_keys = true, has_identity = identity.is_some(), "bundle de retry incompleto");
            }
        }

        // Sem bundle injetado → re-garante sessão com o participante.
        // `force` segue o `forceSession` do Node: forçado na primeira vez,
        // depois reusa.
        //
        // Node: `if (!injectedFromBundle && retryParticipantJid)` — para grupo
        // sem participant, NÃO re-garante sessão (não há device alvo).
        if !injected_from_bundle {
            if let Some(retry_participant_jid) = retry_participant.as_deref() {
                let force = {
                    if self.force_session_cache.contains(retry_participant_jid).await {
                        false
                    } else {
                        self.force_session_cache.set(retry_participant_jid.to_string(), ()).await;
                        true
                    }
                };
                let lids = self.node_get_lid(retry_participant_jid, sink).await?;
                self.assert_sessions(&[retry_participant_jid.to_string()], force, lids.as_deref(), sink).await?;
            }
        }

        // `getMessage(key)` (o `sendMessageCache` está comentado no Node): só o
        // store do app. Sem hook, a mensagem não é encontrada.
        let load = self.load_message_fn.lock().await.clone();
        let cached_bytes = match load {
            Some(load) => load(msg_id.clone(), remote.clone()).await.unwrap_or_default(),
            None => Vec::new(),
        };
        if cached_bytes.is_empty() {
            tracing::debug!(msg_id, remote, "Message not found, in retry");
            return Ok(());
        }
        let target_jid = remote.clone();

        // `delete msg.messageContextInfo` e `relayMessage(key.remoteJid, msg,
        // { messageId, isretry: true, participant? })`.
        let mut msg = wa::Message::decode(cached_bytes.as_slice()).unwrap_or_default();
        msg.message_context_info = None;

        // `retryNode.attrs.count` (Node `messages-recv.js:711`).
        let retry_count = node
            .child("retry")
            .and_then(|r| r.attr("count"))
            .and_then(|c| c.parse::<u32>().ok())
            .unwrap_or(1);

        // Node `handleReceipt`: `msgRelayOpts = { messageId: key.id, isretry: true }`
        // e, SÓ se `retryParticipantJid` existir, `msgRelayOpts.participant =
        // { jid, count }`. NÃO existe `sendToAll` no fluxo real (o
        // `sendMessagesAgain` é código morto); a decisão é exclusivamente a
        // presença/ausência do `retryParticipantJid`.
        //
        // - Grupo COM participant → `relayMessage(jid, msg, { participant })` →
        //   `isGroup && participant` (senderKeyDistributionMessage 1:1 só para
        //   o pedinte).
        // - Grupo SEM participant → `relayMessage(jid, msg, { isretry })` →
        //   `isGroup && !participant` com `isretry`: reenvia SÓ o `skmsg`,
        //   sem fanout (`getUSyncDevices` é pulado por `!isretry`) e sem
        //   distribuir sender key (`devices` vazio → `senderKeyJids` vazio).
        // - 1:1 → `participant && !isGroup` (1:1 direcionado ao pedinte).
        let result = match retry_participant.as_deref() {
            Some(retry_participant_jid) => {
                let relay_participant = RelayParticipant {
                    jid: retry_participant_jid.to_string(),
                    count: retry_count.max(1),
                };
                if baileys_core::is_jid_group(&target_jid) {
                    self.relay_group_message_retry(
                        &target_jid,
                        msg,
                        &msg_id,
                        &relay_participant,
                        sink,
                        &[],
                    )
                    .await
                } else {
                    self.relay_message_retry(
                        &target_jid,
                        msg,
                        &msg_id,
                        &relay_participant,
                        sink,
                        &[],
                    )
                    .await
                }
            }
            None => {
                // Grupo sem participant: reenvia SÓ o skmsg (isretry, sem
                // participant). Para 1:1, o Node sempre tem `retryParticipantJid`
                // (`attrs.participant || attrs.from`), então `None` só ocorre em
                // grupo; por segurança, trata como no-op se não for grupo.
                if baileys_core::is_jid_group(&target_jid) {
                    self.relay_group_message_isretry(&target_jid, msg, &msg_id, sink, &[])
                        .await
                } else {
                    Ok(SendMessageResult { message_id: msg_id.to_string() })
                }
            }
        };
        result.map(|_| ())
    }

    /// Envia uma mensagem de texto 1:1.
    ///
    /// Espelha o `relayMessage` 1:1 do Node: resolve LID + devices via USync,
    /// cifra por device (com `deviceSentMessage` para os nossos próprios
    /// devices), monta `<participants>` e anexa `device-identity` com
    /// signature key quando há `pkmsg`.
    pub async fn send_text(
        &self,
        jid: &str,
        text: &str,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        let ext_text = wa::message::ExtendedTextMessage {
            text: Some(text.to_string()),
            ..Default::default()
        };
        let message = wa::Message {
            extended_text_message: Some(Box::new(ext_text)),
            ..Default::default()
        };
        let msg_id = generate_message_id_v2(Some(&self.me_id()));
        self.send_one_to_one(jid, message, "text", &msg_id, sink, &[], None, false).await
    }

    /// `relayMessage` 1:1 com `messageId` pré-gerado (paridade Node:
    /// a mensagem é montada e o id conhecido ANTES do relay).
    pub async fn relay_message(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        self.relay_message_with_attrs(jid, message, message_id, sink, &[]).await
    }

    /// `relayMessage` 1:1 com `messageId` pré-gerado e atributos extras no
    /// stanza (`edit`, etc.) — usado por react/edit/forward (paridade Node).
    pub async fn relay_message_with_attrs(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        self.send_one_to_one(jid, message, "text", message_id, sink, extra_attrs, None, false).await
    }

    /// `relayMessage` de retry para 1:1 — `{ messageId, isretry: true, participant }`.
    ///
    /// Port do bloco `participant && !isGroup && !isStatus && !isNewsletter`
    /// do Node (`messages-send.ts` linhas 592–634): cifra SÓ para o
    /// `participant` pedinte (com `deviceSentMessage` se for device nosso),
    /// `device_fanout=false`, `enc` direto (sem `<participants>`) e
    /// `to = participant.jid` (+ `recipient` quando é device nosso).
    pub async fn relay_message_retry(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        participant: &RelayParticipant,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        self.send_one_to_one(jid, message, "text", message_id, sink, extra_attrs, Some(participant), true).await
    }

    /// `relayMessage(jid, msg, { messageId, isretry: true })` 1:1 sem
    /// `participant`: fanout normal, mas sem `tctoken` nem reporting token.
    pub async fn relay_message_isretry(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        self.send_one_to_one(jid, message, "text", message_id, sink, extra_attrs, None, true).await
    }

    /// `relayMessage` 1:1 — core do envio E2E para um chat individual.
    ///
    /// Port do bloco `else` (non-group) de `relayMessage` em `messages-send.js`:
    /// - `getLid` + `getUSyncDevices` para o fanout multi-device;
    /// - `meJids` recebem `deviceSentMessage`, `otherJids` a mensagem pura;
    /// - `peer_recipient_lid` e `device-identity` (com signature key) no stanza.
    async fn send_one_to_one(
        &self,
        jid: &str,
        message: wa::Message,
        msg_type: &str,
        msg_id: &str,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
        participant: Option<&RelayParticipant>,
        is_retry: bool,
    ) -> Result<SendMessageResult, ClientError> {
        let mut message = message;
        if !is_retry {
            crate::reporting::ensure_message_secret(&mut message);
        }
        let node_extra_attrs = relay_extra_attrs(&message);
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);

        // `participant && !isGroup && !isStatus && !isNewsletter` (Node linhas
        // 592–634): retry 1:1 — envia SÓ para o participant pedinte.
        if let Some(participant) = participant {
            // Node: `lids = getLid(jidNormalizedUser(participant.jid))` — só
            // resolve para PN; LID fica `undefined`.
            let lid = self.node_get_lid(&participant.jid, sink).await?;

            // `isMe`: device nosso? então `deviceSentMessage`.
            let is_participant_lid = baileys_core::is_lid_user(&participant.jid);
            let is_me = are_jids_same_user(
                &participant.jid,
                if is_participant_lid { &me_lid } else { &me_id },
            ) || are_jids_same_user(&participant.jid, &me_id)
                || are_jids_same_user(&participant.jid, &me_lid);

            let message_to_send = if is_me {
                wa::Message {
                    device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                        destination_jid: Some(baileys_core::jid_normalized_user(jid)),
                        message: Some(Box::new(message.clone())),
                        phash: None,
                    })),
                    ..Default::default()
                }
            } else {
                message.clone()
            };

            let dest = convert_lid_device(&participant.jid, lid.as_deref(), &me_id, &me_lid);
            let enc = repo.encrypt_message(
                &dest,
                &write_random_pad_max16(&message_to_send.encode_to_vec()),
            )?;

            let mut children = vec![retry_enc_node(&enc.r#type, enc.ciphertext, participant.count, &node_extra_attrs)];
            let destination_jid = baileys_core::jid_normalized_user(jid);
            children.extend(
                self.relay_stanza_tail(enc.r#type == "pkmsg", lid.as_deref(), &destination_jid, false, None).0,
            );

            // Node linhas 857–865: `to = participant.jid`; se device nosso,
            // `recipient = destinationJid`. `device_fanout=false`.
            let mut stanza = BinaryNode::new("message")
                .with_attr("id", msg_id)
                .with_attr("to", &participant.jid)
                .with_attr("device_fanout", "false");
            if is_me {
                stanza = stanza.with_attr("recipient", &destination_jid);
            }
            stanza = stanza.with_attr("type", msg_type);
            if let Some(lid) = &lid {
                if !baileys_core::is_lid_user(&destination_jid) {
                    stanza = stanza.with_attr("peer_recipient_lid", lid);
                }
            }
            for &(k, v) in extra_attrs {
                stanza = stanza.with_attr(k, v);
            }
            let stanza = stanza.with_children(children);

            self.send_node(&stanza, sink).await?;
            tracing::info!(msg_id, jid, participant = %participant.jid, "mensagem 1:1 reenviada (retry)");
            return Ok(SendMessageResult { message_id: msg_id.to_string() });
        }

        // LID do destinatário (para o `peer_recipient_lid` e endereçamento).
        let lid = self.get_lid(jid, sink).await?;

        // Devices: o do destinatário + o nosso próprio (para sincronizar o
        // `deviceSentMessage` com os outros aparelhos).
        let me_ref = if baileys_core::is_lid_user(jid) {
            me_lid.clone()
        } else {
            me_id.clone()
        };
        let mut device_jids = vec![jid.to_string()];
        if !device_jids.iter().any(|d| d == &me_ref) {
            device_jids.push(me_ref.clone());
        }
        let mut devices = self.get_usync_devices(&device_jids, sink, false).await?;

        let my_user = jid_user(&me_id).unwrap_or_default();
        let my_lid_user = jid_user(&me_lid).unwrap_or_default();
        tracing::debug!(me_id = %me_id, me_lid = %me_lid, my_user = %my_user, my_lid_user = %my_lid_user, "fanout 1:1 antes da correção de device 0");

        // Garante o device 0 do remetente no fanout (Node `messages-send.ts`
        // linhas 762–790): quando este companion não é o device 0 e o USync
        // não devolveu o phone, força `meId`/`meLid` device 0.
        let me_device = jid_device(&me_id).unwrap_or(0);
        if me_device != 0 {
            let has_me_phone = devices
                .iter()
                .any(|(u, d, _)| (u == &my_user || u == &my_lid_user) && *d == 0);
            if !has_me_phone {
                if baileys_core::is_lid_user(jid) {
                    devices.push((my_lid_user.clone(), 0, baileys_core::jid_normalized_user(&me_lid)));
                } else {
                    devices.push((my_user.clone(), 0, baileys_core::jid_normalized_user(&me_id)));
                }
            }
        }
        tracing::debug!(?devices, "fanout 1:1 após correção");

        // Separa meJids/otherJids (port do loop `for (const { user, device, jid } of devices)`).
        let mut me_jids: Vec<String> = Vec::new();
        let mut other_jids: Vec<String> = Vec::new();
        let mut all_jids: Vec<String> = Vec::new();
        let mut device_sender_ids: Vec<(String, String)> = Vec::new(); // (senderId, baseJid)

        for (user, device, dev_jid) in &devices {
            let server = if baileys_core::is_lid_user(dev_jid) {
                "lid"
            } else {
                "s.whatsapp.net"
            };
            // `jidEncode` do Node omite `:0` para device 0 (`${device ? ':${device}' : ''}`).
            let sender_id = if *device == 0 {
                format!("{user}@{server}")
            } else {
                format!("{user}:{device}@{server}")
            };
            if user == &my_user || user == &my_lid_user {
                me_jids.push(sender_id.clone());
            } else {
                other_jids.push(sender_id.clone());
            }
            all_jids.push(sender_id.clone());
            device_sender_ids.push((sender_id, dev_jid.clone()));
        }
        tracing::debug!(?me_jids, ?other_jids, "fanout 1:1 separado");

        // Node: `assertSessions(allJids, force=false, lids)` (force só com participant).
        self.assert_sessions(&all_jids, false, lid.as_deref(), sink).await?;

        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);

        // deviceSentMessage (para os nossos próprios devices).
        let me_msg = wa::Message {
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some(baileys_core::jid_normalized_user(jid)),
                message: Some(Box::new(message.clone())),
                phash: None,
            })),
            ..Default::default()
        };

        let mut participants: Vec<BinaryNode> = Vec::new();
        let mut should_include_device_identity = false;

        // `createParticipantNodes` aplica `patchMessageBeforeSending` em cada lote.
        let me_msg = self.patch_message(&me_msg);
        let other_msg = self.patch_message(&message);
        let lid_ref = lid.clone();
        for sender_id in &me_jids {
            let dest = convert_lid_device(sender_id, lid_ref.as_deref(), &me_id, &me_lid);
            let enc = repo.encrypt_message(&dest, &write_random_pad_max16(&me_msg.encode_to_vec()))?;
            if enc.r#type == "pkmsg" {
                should_include_device_identity = true;
            }
            tracing::debug!(sender_id = %sender_id, dest = %dest, enc_type = %enc.r#type, "encrypt me device");
            participants.push(participant_enc_node(sender_id, &enc.r#type, enc.ciphertext, &node_extra_attrs));
        }
        for sender_id in &other_jids {
            let dest = convert_lid_device(sender_id, lid_ref.as_deref(), &me_id, &me_lid);
            let enc = repo.encrypt_message(&dest, &write_random_pad_max16(&other_msg.encode_to_vec()))?;
            if enc.r#type == "pkmsg" {
                should_include_device_identity = true;
            }
            tracing::debug!(sender_id = %sender_id, dest = %dest, enc_type = %enc.r#type, "encrypt other device");
            participants.push(participant_enc_node(sender_id, &enc.r#type, enc.ciphertext, &node_extra_attrs));
        }

        let mut children = vec![BinaryNode::new("participants").with_children(participants)];
        let destination_jid = baileys_core::jid_normalized_user(jid);
        let (tail, tc_sender_timestamp) = self.relay_stanza_tail(
            should_include_device_identity,
            lid.as_deref(),
            &destination_jid,
            true,
            Some((&other_msg, msg_id, None)),
        );
        children.extend(tail);

        let mut stanza = BinaryNode::new("message")
            .with_attr("id", msg_id)
            .with_attr("type", msg_type)
            .with_attr("to", jid);
        if let Some(lid) = &lid {
            if !baileys_core::is_lid_user(jid) {
                stanza = stanza.with_attr("peer_recipient_lid", lid);
            }
        }
        for &(k, v) in extra_attrs {
            stanza = stanza.with_attr(k, v);
        }
        let stanza = stanza.with_children(children);

        self.send_node(&stanza, sink).await?;

        if tc_sender_timestamp.is_some_and(should_send_new_tc_token) {
            self.issue_privacy_token(&destination_jid, sink).await;
        }
        // Persiste a mensagem enviada no store do app (fire-and-forget) para
        // reenvio em retry após restart do processo.
        let encoded = message.encode_to_vec();
        let save = self.save_message_fn.lock().await.clone();
        if let Some(save) = save {
            let mid = msg_id.to_string();
            let jid_owned = jid.to_string();
            tokio::spawn(async move {
                save(mid, jid_owned, encoded).await;
            });
        }

        tracing::info!(msg_id, jid, kind = "1:1", devices = all_jids.len(), "mensagem enviada");
        Ok(SendMessageResult { message_id: msg_id.to_string() })
    }

    // --- envio de mídia ---

    /// Faz o upload de um arquivo de mídia e retorna as chaves + URL.
    ///
    /// Port de `waUploadToServer` (`getWAUploadToServer`): busca a `media_conn`
    /// (`<iq xmlns="w:m"><media_conn/>`), criptografa com AES-256-CBC e faz
    /// POST em `https://{host}{path}/{sha256b64}?auth=...&token=...`.
    pub async fn upload_media(
        &self,
        plaintext: &[u8],
        media_type: baileys_media::MediaType,
        sink: &WsSink,
    ) -> Result<MediaUpload, ClientError> {
        use rand::RngCore;

        // 1. Media connection.
        let query = BinaryNode::new("iq")
            .with_attr("type", "set")
            .with_attr("xmlns", "w:m")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("id", self.next_tag())
            .with_children(vec![BinaryNode::new("media_conn")]);
        let result = self.query_node(query, sink).await?;
        let conn = result.child("media_conn").ok_or(ClientError::MediaConn)?;
        let auth = conn.attr("auth").unwrap_or_default().to_string();
        let hosts: Vec<(String, u64)> = conn
            .children("host")
            .iter()
            .map(|h| {
                (
                    h.attr("hostname").unwrap_or_default().to_string(),
                    h.attr("maxContentLengthBytes").and_then(|v| v.parse().ok()).unwrap_or(0),
                )
            })
            .collect();
        if hosts.is_empty() {
            return Err(ClientError::MediaConn);
        }

        // 2. Criptografa (AES-256-CBC + HMAC) como `encryptedStream`.
        let mut media_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut media_key);
        let keys = baileys_media::get_media_keys(&media_key, media_type)
            .map_err(ClientError::Media)?;
        let enc = baileys_media::encrypt_media(plaintext, &keys).map_err(ClientError::Media)?;
        let sha_b64 = base64::engine::general_purpose::STANDARD.encode(&enc.file_enc_sha256);
        let upload_token = baileys_media::encode_base64_for_upload(&sha_b64);

        // 3. POST para cada host.
        let client = reqwest::Client::new();
        let mut uploaded: Option<(String, String)> = None;
        for (hostname, _max) in &hosts {
            let url = format!(
                "https://{hostname}{path}/{token}?auth={auth}&token={token}",
                path = media_type.upload_path(),
                token = upload_token,
                auth = urlencode(&auth),
            );
            let resp = client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("Origin", "https://web.whatsapp.com")
                .body(enc.enc_with_mac.clone())
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    if let Ok(json) = r.json::<serde_json::Value>().await {
                        let direct_path = json
                            .get("direct_path")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let media_url = json
                            .get("url")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        if !direct_path.is_empty() || media_url.is_some() {
                            uploaded = Some((
                                media_url.unwrap_or_else(|| baileys_media::url_from_direct_path(&direct_path)),
                                direct_path,
                            ));
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, hostname, "falha ao enviar mídia");
                }
            }
        }

        let (media_url, direct_path) = uploaded.ok_or(ClientError::MediaUploadFailed)?;

        Ok(MediaUpload {
            media_key: media_key.to_vec(),
            file_enc_sha256: enc.file_enc_sha256,
            file_sha256: enc.file_sha256,
            file_length: plaintext.len() as u64,
            media_url,
            direct_path,
        })
    }

    /// Envia uma mensagem de mídia (imagem/vídeo/áudio/documento).
    ///
    /// Constrói o `wa::Message` com o respectivo campo de mídia e usa o mesmo
    /// pipeline E2E do `send_text`.
    pub async fn send_media_message(
        &self,
        jid: &str,
        message: wa::Message,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        self.send_media_message_with_attrs(jid, message, sink, &[]).await
    }

    /// Envia uma mensagem de mídia (imagem/vídeo/áudio/documento) com
    /// atributos extras no stanza (`edit`, etc.).
    pub async fn send_media_message_with_attrs(
        &self,
        jid: &str,
        message: wa::Message,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        // Node `getMessageType` → "text" para mídia (só polls viram "poll").
        let msg_id = generate_message_id_v2(Some(&self.me_id()));
        self.send_one_to_one(jid, message, "text", &msg_id, sink, extra_attrs, None, false).await
    }

    /// Envia uma imagem (JPEG/PNG/WebP/GIF) a partir de bytes: sobe, extrai
    /// dimensões + thumbnail e encaminha E2E.
    pub async fn send_image(
        &self,
        jid: &str,
        bytes: &[u8],
        mimetype: &str,
        caption: Option<&str>,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        let upload = self.upload_media(bytes, baileys_media::MediaType::Image, sink).await?;
        let dims = baileys_media::extract_image_dimensions(bytes)
            .unwrap_or(baileys_media::ImageDimensions { width: 0, height: 0 });
        let thumb = baileys_media::image_thumbnail(bytes, 32)
            .map(|t| t.jpeg)
            .unwrap_or_default();
        let msg = crate::media::image_message(
            &upload, mimetype, dims.width, dims.height, caption, Some(thumb),
        );
        self.send_media_message(jid, msg, sink).await
    }

    /// Envia um vídeo a partir de bytes: sobe, probe FFmpeg (w/h/duração) +
    /// thumbnail e encaminha E2E.
    pub async fn send_video(
        &self,
        jid: &str,
        bytes: &[u8],
        mimetype: &str,
        caption: Option<&str>,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        let upload = self.upload_media(bytes, baileys_media::MediaType::Video, sink).await?;
        let probe = baileys_media::ffmpeg_probe(bytes).await.unwrap_or_default();
        let thumb = baileys_media::extract_video_thumb(bytes, 32)
            .await
            .unwrap_or_default();
        let msg = crate::media::video_message(
            &upload,
            mimetype,
            probe.width.unwrap_or(0),
            probe.height.unwrap_or(0),
            probe.seconds.map(|s| s.round() as u32).unwrap_or(0),
            caption,
            Some(thumb),
        );
        self.send_media_message(jid, msg, sink).await
    }

    /// Envia um áudio a partir de bytes, convertendo via FFmpeg.
    ///
    /// `ptt = true` → grava como mensagem de voz (OGG/Opus); `ptt = false` →
    /// áudio normal (MP3).
    pub async fn send_audio(
        &self,
        jid: &str,
        bytes: &[u8],
        ptt: bool,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        let (plaintext, mimetype, media_type) = if ptt {
            (
                baileys_media::prepare_audio_ptt(bytes).await?,
                "audio/ogg; codecs=opus",
                baileys_media::MediaType::Ptt,
            )
        } else {
            (
                baileys_media::prepare_audio_mp3(bytes).await?,
                "audio/mpeg",
                baileys_media::MediaType::Audio,
            )
        };
        let upload = self.upload_media(&plaintext, media_type, sink).await?;
        let probe = baileys_media::ffmpeg_probe(&plaintext).await.unwrap_or_default();
        let waveform = baileys_media::audio_waveform(&plaintext)
            .await
            .unwrap_or_default();
        let msg = crate::media::audio_message(
            &upload,
            mimetype,
            probe.seconds.map(|s| s.round() as u32).unwrap_or(0),
            ptt,
            Some(waveform),
        );
        self.send_media_message(jid, msg, sink).await
    }

    /// Envia um documento a partir de bytes (PDF, ZIP, etc).
    pub async fn send_document(
        &self,
        jid: &str,
        bytes: &[u8],
        mimetype: &str,
        filename: &str,
        caption: Option<&str>,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        let upload = self.upload_media(bytes, baileys_media::MediaType::Document, sink).await?;
        let msg = crate::media::document_message(&upload, mimetype, filename, caption, None);
        self.send_media_message(jid, msg, sink).await
    }

    // --- grupos (Fase 3) ---

    /// `groupMetadata` — busca os metadados de um grupo (com cache TTL,
    /// `groupMetaCache`, para evitar consultas repetidas — anti-ban).
    pub async fn group_metadata(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<crate::groups::GroupMetadata, ClientError> {
        if let Some(cached) = self.group_meta_cache.get(jid).await {
            return Ok(cached);
        }
        let query = crate::groups::group_metadata_query(jid).with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        let meta = crate::groups::extract_group_metadata(&result).ok_or(ClientError::GroupMetadata)?;
        self.group_meta_cache.set(jid.to_string(), meta.clone()).await;
        Ok(meta)
    }

    /// `/groups/flush` do container Node: descarta o cache do grupo e os
    /// devices dos participantes, busca os metadados de novo e força as
    /// sessões E2E (`assertSessions(participants.map(p => p.lid || p.id), true)`).
    ///
    /// O cache de devices é compartilhado (Redis), então só as entradas dos
    /// participantes saem — não o `flushAll` inteiro do Node.
    pub async fn refresh_group(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<crate::groups::GroupMetadata, ClientError> {
        self.group_meta_cache.remove(jid).await;
        let meta = self.group_metadata(jid, sink).await?;

        for p in &meta.participants {
            for user in [Some(p.id.as_str()), p.lid.as_deref()].into_iter().flatten() {
                let normalized = baileys_core::jid_normalized_user(user);
                if normalized.is_empty() {
                    continue;
                }
                self.devices_cache.remove(&normalized).await;
                self.devices_cache.remove(&format!("group-{normalized}")).await;
            }
        }

        let jids: Vec<String> = meta
            .participants
            .iter()
            .map(|p| p.lid.clone().filter(|l| !l.is_empty()).unwrap_or_else(|| p.id.clone()))
            .collect();
        self.assert_sessions(&jids, true, None, sink).await?;
        Ok(meta)
    }

    /// `groupCreate` — cria um grupo com os participantes.
    pub async fn group_create(
        &self,
        subject: &str,
        participants: &[String],
        sink: &WsSink,
    ) -> Result<crate::groups::GroupMetadata, ClientError> {
        let key = crate::groups::generate_sender_key();
        let query = crate::groups::group_create_query(subject, &key, participants)
            .with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        crate::groups::extract_group_metadata(&result)
            .ok_or(ClientError::GroupMetadata)
    }

    /// `groupLeave` — sai do grupo.
    pub async fn group_leave(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let query = crate::groups::group_leave_query(jid).with_attr("id", self.next_tag());
        self.query_node(query, sink).await?;
        Ok(())
    }

    /// `groupUpdateSubject`.
    pub async fn group_update_subject(
        &self,
        jid: &str,
        subject: &str,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let query = crate::groups::group_update_subject_query(jid, subject)
            .with_attr("id", self.next_tag());
        self.query_node(query, sink).await?;
        Ok(())
    }

    /// `groupUpdateDescription`.
    pub async fn group_update_description(
        &self,
        jid: &str,
        description: Option<&str>,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        // `prev = metadata.descId` + `id: generateMessageIDV2()` (Hineken).
        // Metadados frescos: um `descId` antigo do cache faz o servidor recusar.
        self.group_meta_cache.remove(jid).await;
        let prev = self.group_metadata(jid, sink).await?.desc_id;
        let new_id = description.map(|_| baileys_core::ids::generate_message_id_v2(None));
        let query = crate::groups::group_update_description_query(jid, description, prev.as_deref(), new_id.as_deref())
            .with_attr("id", self.next_tag());
        self.query_node(query, sink).await?;
        Ok(())
    }

    /// `groupParticipantsUpdate` — add/remove/promote/demote. Devolve o
    /// status por participante (`attrs.error` ou `200`).
    pub async fn group_update_participants(
        &self,
        jid: &str,
        participants: &[String],
        action: &str,
        sink: &WsSink,
    ) -> Result<Vec<crate::groups::ParticipantUpdateResult>, ClientError> {
        let query = crate::groups::group_participants_update_query(jid, participants, action)
            .with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        Ok(crate::groups::extract_participants_update(&result, action))
    }

    /// `groupInviteCode`.
    pub async fn group_invite_code(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<String, ClientError> {
        let query = crate::groups::group_invite_code_query(jid).with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        Ok(result
            .child("invite")
            .and_then(|i| i.attr("code"))
            .unwrap_or_default()
            .to_string())
    }

    /// Envia uma mensagem cifrada por sender-key para um grupo.
    pub async fn send_group_text(
        &self,
        jid: &str,
        text: &str,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        let ext_text = wa::message::ExtendedTextMessage {
            text: Some(text.to_string()),
            ..Default::default()
        };
        let message = wa::Message {
            extended_text_message: Some(Box::new(ext_text)),
            ..Default::default()
        };
        let msg_id = generate_message_id_v2(Some(&self.me_id()));
        self.send_group(jid, message, &msg_id, sink, &[], None, false).await
    }

    /// Envia uma mensagem cifrada por sender-key para um grupo (conteúdo
    /// arbitrário — mídia/lista/contato/localização/etc).
    pub async fn send_group_message(
        &self,
        jid: &str,
        message: wa::Message,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        self.send_group_message_with_attrs(jid, message, sink, &[]).await
    }

    /// Envia uma mensagem cifrada por sender-key para um grupo com atributos
    /// extras no stanza (`edit`, etc.).
    pub async fn send_group_message_with_attrs(
        &self,
        jid: &str,
        message: wa::Message,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        let msg_id = generate_message_id_v2(Some(&self.me_id()));
        self.send_group(jid, message, &msg_id, sink, extra_attrs, None, false).await
    }

    /// `relayMessage` para grupos com `messageId` pré-gerado (paridade Node).
    pub async fn relay_group_message(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        sink: &WsSink,
    ) -> Result<SendMessageResult, ClientError> {
        self.relay_group_message_with_attrs(jid, message, message_id, sink, &[]).await
    }

    /// `relayMessage` para grupos com `messageId` pré-gerado e atributos
    /// extras no stanza (`edit`, etc.) — usado por react/edit/forward.
    pub async fn relay_group_message_with_attrs(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        self.send_group(jid, message, message_id, sink, extra_attrs, None, false).await
    }

    /// `relayMessage` de retry para grupo — `{ messageId, isretry: true, participant }`.
    ///
    /// Port do `relayMessage` do Node com `participant` (retry de grupo):
    /// o reenvio vai SÓ para o `participant` pedinte (senão os demais
    /// participantes falham na decriptação), com `to = destino` e
    /// `participant = participant.jid` no stanza.
    pub async fn relay_group_message_retry(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        participant: &RelayParticipant,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        self.send_group(jid, message, message_id, sink, extra_attrs, Some(participant), true).await
    }

    /// `relayMessage(jid, msg, { messageId, isretry: true })` em grupo sem
    /// `participant`: reenvia só o `skmsg` (sem fanout nem sender key).
    pub async fn relay_group_message_isretry(
        &self,
        jid: &str,
        message: wa::Message,
        message_id: &str,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
    ) -> Result<SendMessageResult, ClientError> {
        self.send_group(jid, message, message_id, sink, extra_attrs, None, true).await
    }

    /// `relayMessage` para grupos — port do bloco `isGroup` do Node.
    ///
    /// Cifra o conteúdo com sender-key (`skmsg`) usando `me.lid` como autor e
    /// distribui o `senderKeyDistributionMessage` como `pkmsg` 1:1 para cada
    /// participante-device (port do bloco `senderKeyJids` do Node).
    async fn send_group(
        &self,
        jid: &str,
        message: wa::Message,
        msg_id: &str,
        sink: &WsSink,
        extra_attrs: &[(&str, &str)],
        participant: Option<&RelayParticipant>,
        is_retry: bool,
    ) -> Result<SendMessageResult, ClientError> {
        let mut message = message;
        if !is_retry {
            crate::reporting::ensure_message_secret(&mut message);
        }
        let node_extra_attrs = relay_extra_attrs(&message);
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let mut me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_default();

        // `me.lid` vazio → resolve via USync e persiste antes de cifrar, para
        // que a sender key do grupo NUNCA seja estabelecida com identidade PN
        // (senão o servidor retransmite o autor como `número@...` e o celular
        // do destinatário imprime o JID bruto na bolha).
        if !baileys_core::is_lid_user(&me_lid) {
            if let Some(lid) = self.get_lid(&me_id, sink).await? {
                me_lid = lid;
                let mut creds = self.store.creds();
                if let Some(me) = &mut creds.me {
                    me.lid = Some(me_lid.clone());
                    self.store.update_creds(creds.clone())?;
                    let _ = self.events.send(ClientEvent::CredsUpdate(creds));
                }
            }
        }
        if me_lid.is_empty() {
            return Err(ClientError::InvalidParams(
                "me.lid indisponível para envio em grupo".to_string(),
            ));
        }

        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);

        // Metadados do grupo (participantes) — o retry com participant NÃO faz
        // fanout, mas ainda precisa do `addressing_mode` (Node linha 545).
        let meta = self.group_metadata(jid, sink).await?;
        let addressing_mode = meta.addressing_mode.as_deref().unwrap_or("pn");

        // `isGroup && participant` (Node linhas 540–590): retry de grupo — a
        // mensagem volta como `senderKeyDistributionMessage` cifrada 1:1 para
        // SOMENTE o participante pedinte (não reenvia para todos).
        // `patchMessageBeforeSending(message)` — é o que vai no `skmsg` e no reporting.
        let patched = self.patch_message(&message);

        if let Some(participant) = participant {
            // Node: encryptGroupMessage({ group: destinationJid, data: bytes, meId: meLid }).
            let enc = repo.encrypt_group_message(
                jid,
                &me_lid,
                &write_random_pad_max16(&patched.encode_to_vec()),
            )?;
            let message_to_send = {
                let mut patched = patched.clone();
                patched.sender_key_distribution_message =
                    Some(wa::message::SenderKeyDistributionMessage {
                        axolotl_sender_key_distribution_message: Some(
                            enc.sender_key_distribution_message.clone(),
                        ),
                        group_id: Some(jid.to_string()),
                    });
                patched
            };
            let lid = self.node_get_lid(&participant.jid, sink).await?;
            let dest = convert_lid_device(&participant.jid, lid.as_deref(), &me_id, &me_lid);
            let enc_1to1 = repo.encrypt_message(
                &dest,
                &write_random_pad_max16(&message_to_send.encode_to_vec()),
            )?;

            let pkmsg = enc_1to1.r#type == "pkmsg";
            let mut children = vec![retry_enc_node(&enc_1to1.r#type, enc_1to1.ciphertext, participant.count, &node_extra_attrs)];
            children.extend(self.relay_stanza_tail(pkmsg, lid.as_deref(), jid, false, None).0);

            // Node linha 654: `stanza.attrs.to = destinationJid` +
            // `stanza.attrs.participant = participant.jid`.
            let mut stanza = BinaryNode::new("message")
                .with_attr("id", msg_id)
                .with_attr("type", get_message_type(&message))
                .with_attr("addressing_mode", addressing_mode);
            for &(k, v) in extra_attrs {
                stanza = stanza.with_attr(k, v);
            }
            stanza = stanza
                .with_attr("to", jid)
                .with_attr("participant", &participant.jid);
            if let Some(lid) = &lid {
                stanza = stanza.with_attr("peer_recipient_lid", lid);
            }
            let stanza = stanza.with_children(children);

            self.send_node(&stanza, sink).await?;
            tracing::info!(msg_id, jid, participant = %participant.jid, "mensagem de grupo reenviada (retry)");
            return Ok(SendMessageResult { message_id: msg_id.to_string() });
        }

        // Node: encryptGroupMessage({ group: destinationJid, data: bytes, meId: meLid }).
        let enc = repo.encrypt_group_message(
            jid,
            &me_lid,
            &write_random_pad_max16(&patched.encode_to_vec()),
        )?;

        // `isretry` sem participant (Node `if (!isretry)` pula o
        // `getUSyncDevices`): `devices` fica vazio, então não há
        // `senderKeyJids`/`<participants>`/`device-identity` — só o `skmsg`.
        if is_retry {
            let mut children = vec![skmsg_enc_node(enc.ciphertext)];
            children.extend(self.relay_stanza_tail(false, None, jid, false, None).0);

            let mut stanza = BinaryNode::new("message")
                .with_attr("id", msg_id)
                .with_attr("type", get_message_type(&message))
                .with_attr("addressing_mode", addressing_mode);
            for &(k, v) in extra_attrs {
                stanza = stanza.with_attr(k, v);
            }
            let stanza = stanza.with_attr("to", jid).with_children(children);

            self.send_node(&stanza, sink).await?;
            tracing::info!(msg_id, jid, "mensagem de grupo reenviada (isretry)");
            return Ok(SendMessageResult { message_id: msg_id.to_string() });
        }

        // Fanout completo (envio normal): devices de todos os participantes
        // (lid || id) + distribuição da sender key.

        // Node: `groupData.participants.map(p => p.lid || p.id)`.
        let participant_jids: Vec<String> = meta
            .participants
            .iter()
            .filter_map(|p| {
                p.lid
                    .clone()
                    .filter(|l| !l.is_empty())
                    .or_else(|| Some(p.id.clone()).filter(|id| !id.is_empty()))
            })
            .collect();

        let mut devices = self.get_usync_devices(&participant_jids, sink, true).await?;

        // Garante nosso device 0 (primary) no fanout — paridade Node
        // (`messages-send.ts:679-684`): quando o USync não retornou o phone,
        // empurra DOIS entries — o entry LID (`jlidUser` → `meLid`) e o entry
        // PN (`user` → `meId`). `me.lid` já está garantido acima, então nunca
        // fabricamos `@lid` a partir do PN.
        //
        // IMPORTANTE: no Node, `user` aqui vem de `jidDecode(jid).user` — e,
        // para envio de grupo, `jid` é o JID do grupo (`...@g.us`). Usar o
        // número do remetente (`me_id_user`) no lugar do `user` do destino faz
        // o `senderId` PN virar `{numero}@s.whatsapp.net`, distribuindo a
        // sender key sob a identidade PN do remetente — e o WhatsApp do
        // destinatário imprime `numero:device@s.whatsapp.net` na bolha.
        let me_lid_user = jid_user(&me_lid).unwrap_or_default();
        let has_me_phone = devices
            .iter()
            .any(|(u, d, _)| u == &me_lid_user && *d == 0);
        if !has_me_phone {
            devices.extend(device0_fallback_entries(&me_lid, &me_id, jid));
        }

        // senderKeyDistributionMessage como Message (port do `senderKeyMsg`).
        let sender_key_msg = wa::Message {
            sender_key_distribution_message: Some(
                wa::message::SenderKeyDistributionMessage {
                    group_id: Some(jid.to_string()),
                    axolotl_sender_key_distribution_message: Some(
                        enc.sender_key_distribution_message.clone(),
                    ),
                },
            ),
            ..Default::default()
        };

        let mut sender_key_jids: Vec<String> = Vec::new();
        // `sender-key-memory` do Node: `senderKeyMap[senderId] = true` — reuso
        // da distribuição de sender key já conhecida por grupo (anti-ban).
        let mut sender_key_map: HashMap<String, bool> =
            self.sender_key_memory.get(jid).await.unwrap_or_default();
        for (user, device, dev_jid) in &devices {
            let server = if baileys_core::is_lid_user(dev_jid) {
                "lid"
            } else {
                "s.whatsapp.net"
            };
            // `jidEncode` do Node omite `:0` para device 0.
            let sender_id = if *device == 0 {
                format!("{user}@{server}")
            } else {
                format!("{user}:{device}@{server}")
            };
            sender_key_map.insert(sender_id.clone(), true);
            sender_key_jids.push(sender_id);
        }
        if !sender_key_map.is_empty() {
            self.sender_key_memory.set(jid.to_string(), sender_key_map).await;
        }

        let mut participants: Vec<BinaryNode> = Vec::new();
        let mut should_include_device_identity = false;

        if !sender_key_jids.is_empty() {
            self.assert_sessions(&sender_key_jids, false, None, sink).await?;

            let sk_msg_bytes = self.patch_message(&sender_key_msg).encode_to_vec();
            for sender_id in &sender_key_jids {
                let dest = convert_lid_device(sender_id, None, &me_id, &me_lid);
                let sk_enc = repo
                    .encrypt_message(&dest, &write_random_pad_max16(&sk_msg_bytes))?;
                if sk_enc.r#type == "pkmsg" {
                    should_include_device_identity = true;
                }
                participants.push(participant_enc_node(sender_id, &sk_enc.r#type, sk_enc.ciphertext, &node_extra_attrs));
            }
        }

        // Node: `binaryNodeContent = [enc skmsg (só v/type), participants]` e
        // depois `device-identity`, `cstoken`, `reporting` (fora de retry).
        let mut children = vec![skmsg_enc_node(enc.ciphertext)];
        if !participants.is_empty() {
            children.push(BinaryNode::new("participants").with_children(participants));
        }
        children.extend(
            self.relay_stanza_tail(should_include_device_identity, None, jid, false, Some((&patched, msg_id, None))).0,
        );

        let mut stanza = BinaryNode::new("message")
            .with_attr("id", msg_id)
            .with_attr("type", get_message_type(&message))
            .with_attr("to", jid)
            .with_attr("addressing_mode", addressing_mode);
        for &(k, v) in extra_attrs {
            stanza = stanza.with_attr(k, v);
        }
        let stanza = stanza.with_children(children);

        self.send_node(&stanza, sink).await?;
        // Persiste a mensagem enviada no store do app (fire-and-forget).
        let encoded = message.encode_to_vec();
        let save = self.save_message_fn.lock().await.clone();
        if let Some(save) = save {
            let mid = msg_id.to_string();
            let jid_owned = jid.to_string();
            tokio::spawn(async move {
                save(mid, jid_owned, encoded).await;
            });
        }

        tracing::info!(msg_id, jid, kind = "grupo", devices = sender_key_jids.len(), "mensagem enviada");
        Ok(SendMessageResult { message_id: msg_id.to_string() })
    }

    // --- USync / contatos (Fase 3) ---

    /// `USync` genérico — monta e envia a query e faz o parse do resultado.
    pub async fn execute_usync(
        &self,
        protocols: &[crate::usync::USyncProtocol],
        users: &[crate::usync::USyncUser],
        context: &str,
        sink: &WsSink,
    ) -> Result<Vec<crate::usync::USyncResult>, ClientError> {
        let sid = generate_message_id_v2(None);
        let query = crate::usync::usync_query(protocols, users, context, "query", &sid)
            .with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        Ok(crate::usync::parse_usync_result(&result, protocols))
    }

    /// `getLid` do Node no `relayMessage`: só resolve JID PN (`isJidUser`);
    /// LID e grupo ficam `undefined` (afeta `peer_recipient_lid`/`cstoken`).
    async fn node_get_lid(&self, jid: &str, sink: &WsSink) -> Result<Option<String>, ClientError> {
        if !baileys_core::is_jid_user(jid) {
            return Ok(None);
        }
        self.get_lid(jid, sink).await
    }

    /// `handlePrivacyTokenNotification` + `chats.update { tcToken }` do
    /// `processNotification` (`case 'privacy_token'`).
    fn handle_privacy_token_notification(&self, node: &BinaryNode) {
        let Some(tokens) = node.child("tokens") else {
            return;
        };
        let from = baileys_core::jid_normalized_user(node.attr("from").unwrap_or_default());
        let issue_timestamp = chrono_now_secs() as i64;
        let mut chats = Vec::new();
        for token_node in tokens.children("token") {
            let Some(BinaryContent::Bytes(content)) = &token_node.content else {
                continue;
            };
            if token_node.attr("type") == Some("trusted_contact") {
                tracing::debug!(from = %from, "received trusted contact token");
                self.store_tc_token(
                    &from,
                    content,
                    token_node.attr("t").map(String::from),
                    Some(issue_timestamp),
                );
            }
            chats.push(ChatUpdate {
                id: token_node.attr("jid").unwrap_or_default().to_string(),
                tc_token: Some(content.to_vec()),
                ..Default::default()
            });
        }
        if !chats.is_empty() {
            let _ = self.events.send(ClientEvent::ChatsUpdate { chats });
        }
    }

    /// `authState.keys.set({ 'contacts-tc-token': { [jid]: { token, timestamp, senderTimestamp } } })`
    /// — BufferJSON igual ao Node (Redis `auth:{key}:contacts-tc-token-{jid}`).
    fn store_tc_token(&self, jid: &str, token: &[u8], timestamp: Option<String>, sender_timestamp: Option<i64>) {
        if jid.is_empty() || token.is_empty() {
            return;
        }
        let mut entry = serde_json::Map::new();
        entry.insert(
            "token".into(),
            serde_json::json!({
                "type": "Buffer",
                "data": base64::engine::general_purpose::STANDARD.encode(token),
            }),
        );
        if let Some(ts) = timestamp {
            entry.insert("timestamp".into(), serde_json::Value::String(ts));
        }
        if let Some(sender_ts) = sender_timestamp {
            entry.insert("senderTimestamp".into(), serde_json::Value::from(sender_ts));
        }
        let json = serde_json::Value::Object(entry).to_string();
        self.store.store_generic("contacts-tc-token", jid, &json);
    }

    /// Cauda do stanza do `relayMessage` (Node linhas 671–744), na ordem:
    /// `device-identity`, `cstoken`, `reporting`, `tctoken`. `reporting` é
    /// `None` em retry (`!isretry`); `tctoken` só existe em `is1on1Send`.
    ///
    /// Devolve também o `tcSenderTimestamp` (timestamp do token válido), usado
    /// para reemitir o token depois do envio.
    fn relay_stanza_tail(
        &self,
        include_device_identity: bool,
        lids: Option<&str>,
        destination_jid: &str,
        is_1on1_send: bool,
        reporting: Option<(&wa::Message, &str, Option<&str>)>,
    ) -> (Vec<BinaryNode>, Option<i64>) {
        let mut nodes = Vec::new();
        if include_device_identity {
            if let Some(account) = self.store.creds().account {
                if let Some(encoded) = crate::handshake::encode_signed_device_identity(&account, true) {
                    nodes.push(BinaryNode::new("device-identity").with_bytes(encoded));
                }
            }
        }

        let tc_token_jid = lids.unwrap_or(destination_jid);
        let mut tc_token_buffer: Option<Vec<u8>> = None;
        let mut tc_sender_timestamp: Option<i64> = None;
        if is_1on1_send {
            let mut tc_token_expired = true;
            if let Some(raw) = self.store.load_generic("contacts-tc-token", tc_token_jid) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(token_obj) = value.get("token").or_else(|| value.as_object().and_then(|m| m.get("token"))) {
                        // token pode vir como `{"type":"Buffer","data":"..."}` ou
                        // array de bytes (reviver do BufferJSON).
                        if let Some(bytes) = buffer_value_bytes(token_obj) {
                            tc_token_buffer = Some(bytes);
                        }
                    }
                    if let Some(ts) = value.get("timestamp").and_then(|v| match v {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    }) {
                        tc_token_expired = is_tc_token_expired(Some(&ts));
                        if tc_token_buffer.is_some() {
                            tc_sender_timestamp = ts.parse::<i64>().ok();
                        }
                    }
                }
            }
            if tc_token_buffer.is_some() && tc_token_expired {
                tracing::debug!(jid = destination_jid, "tctoken expirado, limpando");
                tc_token_buffer = None;
                tc_sender_timestamp = None;
                self.store.remove_generic("contacts-tc-token", tc_token_jid);
            }
        }

        if tc_token_buffer.is_none() {
            let creds = self.store.creds();
            if let Some(salt) = creds.nct_salt.as_ref() {
                let salt_bytes = decode_buffer(salt);
                if !salt_bytes.is_empty() {
                    nodes.push(BinaryNode::new("cstoken").with_bytes(compute_cs_token(&salt_bytes, tc_token_jid)));
                }
            }
        }

        if let Some((message, msg_id, participant)) = reporting {
            if crate::reporting::should_include_reporting_token(message) {
                let encoded = write_random_pad_max16(&message.encode_to_vec());
                if let Some(node) = crate::reporting::get_message_reporting_token(
                    &encoded,
                    message,
                    msg_id,
                    destination_jid,
                    participant,
                ) {
                    nodes.push(node);
                }
            }
        }

        if let Some(token) = tc_token_buffer {
            nodes.push(BinaryNode::new("tctoken").with_bytes(token));
        }
        (nodes, tc_sender_timestamp)
    }

    /// Reemissão do privacy token depois do envio 1:1 (`shouldSendNewTcToken`
    /// → `iq set xmlns="privacy"`). Sem aguardar a resposta, como o
    /// fire-and-forget do Node.
    async fn issue_privacy_token(&self, destination_jid: &str, sink: &WsSink) {
        let t = chrono_now_secs().to_string();
        let iq = BinaryNode::new("iq")
            .with_attr("id", self.next_tag())
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "set")
            .with_attr("xmlns", "privacy")
            .with_children(vec![BinaryNode::new("tokens").with_children(vec![
                BinaryNode::new("token")
                    .with_attr("jid", baileys_core::jid_normalized_user(destination_jid))
                    .with_attr("t", t)
                    .with_attr("type", "trusted_contact"),
            ])]);
        match self.send_node(&iq, sink).await {
            Ok(_) => tracing::debug!(jid = destination_jid, "issued privacy token after send"),
            Err(e) => tracing::debug!(jid = destination_jid, error = %e, "falha ao reemitir privacy token"),
        }
    }

    /// `getLid` — resolve o LID de um JID `@s.whatsapp.net` via USync
    /// (contact + lid), espelhando `getLid` de `messages-send.js`, com cache
    /// TTL (`lidCache`) para evitar consultas repetidas (anti-ban).
    pub async fn get_lid(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<Option<String>, ClientError> {
        if baileys_core::is_lid_user(jid) {
            return Ok(Some(jid.to_string()));
        }
        let normalized = baileys_core::jid_normalized_user(jid);
        if normalized.is_empty() {
            return Ok(None);
        }
        if let Some(cached) = self.lid_cache.get(&normalized).await {
            return Ok(Some(cached));
        }
        let phone = normalized
            .trim_start_matches('+')
            .split('@')
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_string();
        if phone.is_empty() {
            return Ok(None);
        }
        let results = self
            .execute_usync(
                &[crate::usync::USyncProtocol::Contact, crate::usync::USyncProtocol::LID],
                &[crate::usync::USyncUser {
                    id: None,
                    lid: None,
                    phone: Some(format!("+{phone}")),
                }],
                "interactive",
                sink,
            )
            .await?;
        let lid = results.first().and_then(|r| r.lid.clone());
        if let Some(l) = &lid {
            self.lid_cache.set(normalized, l.clone()).await;
        }
        Ok(lid)
    }

    /// `getUSyncDevices` — retorna os devices (user, device, jid) de um conjunto
    /// de JIDs via USync `devices` (contexto `message`), espelhando
    /// `getUSyncDevices` + `extractDeviceJids` de `messages-send.js`, com
    /// cache TTL (`devicesCache`) para evitar consultas repetidas (anti-ban).
    ///
    /// `group_devices` espelha o 4º argumento `groupDevices` do Node: prefixa
    /// a chave de cache com `group-` (resolvendo a LID), para que o fanout de
    /// grupo não colida com o cache de devices 1:1 do mesmo usuário.
    pub async fn get_usync_devices(
        &self,
        jids: &[String],
        sink: &WsSink,
        group_devices: bool,
    ) -> Result<Vec<(String, u32, String)>, ClientError> {
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        let my_user = jid_user(&me_id).unwrap_or_default();
        let my_device = jid_device(&me_id).unwrap_or(0);
        let my_lid_user = jid_user(&me_lid).unwrap_or_default();
        let my_lid_device = jid_device(&me_lid).unwrap_or(0);

        let mut out: Vec<(String, u32, String)> = Vec::new();
        // Deduplica preservando a ordem.
        let mut seen = std::collections::HashSet::new();

        // Normaliza + deduplica os JIDs de entrada (preservando ordem).
        let mut normalized_jids: Vec<String> = Vec::new();
        for jid in jids {
            if jid.is_empty() {
                continue;
            }
            let normalized = baileys_core::jid_normalized_user(jid);
            if normalized.is_empty() || normalized_jids.contains(&normalized) {
                continue;
            }
            normalized_jids.push(normalized);
        }

        let mut users: Vec<crate::usync::USyncUser> = Vec::new();
        let mut to_fetch: Vec<String> = Vec::new();
        for normalized in &normalized_jids {
            // Chave de cache: `group-{lid}` quando é fanout de grupo, `{jid}`
            // quando é 1:1 — mesmo esquema do Node (`labelLid`).
            let cache_key = self.devices_cache_key(normalized, group_devices, sink).await;
            // Cache por JID (chave = normalized; devices incluem os nossos e
            // os alheios, então o cache por JID é seguro como no Node).
            if let Some(devices) = self.devices_cache.get(&cache_key).await {
                for d in &devices {
                    let key = (d.0.clone(), d.1, d.2.clone());
                    if seen.insert(key.clone()) {
                        out.push(key);
                    }
                }
                continue;
            }
            to_fetch.push(normalized.clone());
            users.push(crate::usync::USyncUser {
                id: Some(normalized.clone()),
                lid: None,
                phone: None,
            });
        }

        if users.is_empty() {
            return Ok(out);
        }

        let results = self
            .execute_usync(&[crate::usync::USyncProtocol::Devices], &users, "message", sink)
            .await?;

        for r in &results {
            let user = jid_user(&r.id).unwrap_or_default();
            let mut jid_devices: Vec<(String, u32, String)> = Vec::new();
            for d in &r.devices {
                let device = d.id;
                let has_key_index = d.key_index.is_some();
                // extractDeviceJids: exclui o próprio device e exige key-index em devices não-zero.
                if (my_user != user || my_device != device)
                    && (my_lid_user != user || my_lid_device != device)
                    && (device == 0 || has_key_index)
                {
                    // `jid` normalizado (paridade Node `extractDeviceJids`, que
                    // guarda `userResult.id` — mas o log do Rust exibia `:0@lid`;
                    // normalizar só afeta o campo de exibição/cache, o `sender_id`
                    // é reconstruído de `user`+`device`+`server`).
                    let key = (user.clone(), device, baileys_core::jid_normalized_user(&r.id));
                    if seen.insert(key.clone()) {
                        out.push(key.clone());
                        jid_devices.push(key);
                    }
                }
            }
            // Armazena no cache (chave `group-{lid}` para grupo, `{jid}` 1:1).
            if !jid_devices.is_empty() {
                let cache_key = self.devices_cache_key(&r.id, group_devices, sink).await;
                if !cache_key.is_empty() {
                    self.devices_cache.set(cache_key, jid_devices).await;
                }
            }
        }

        Ok(out)
    }

    /// Chave do `devicesCache` — port do `labelLid` do Node:
    /// `group-{lid}` para fanout de grupo, senão `{jid}` normalizado.
    async fn devices_cache_key(&self, jid: &str, group_devices: bool, sink: &WsSink) -> String {
        let normalized = baileys_core::jid_normalized_user(jid);
        if normalized.is_empty() {
            return normalized;
        }
        if !group_devices {
            return normalized;
        }
        if baileys_core::is_lid_user(&normalized) {
            return format!("group-{normalized}");
        }
        // Node: resolve `getLid(jid)` e prefixa `group-{lid}`.
        if let Ok(Some(lid)) = self.get_lid(&normalized, sink).await {
            let lid_user = baileys_core::jid_normalized_user(&lid);
            if !lid_user.is_empty() {
                return format!("group-{lid_user}");
            }
        }
        format!("group-{normalized}")
    }

    /// `assertSessions` — busca chaves E2E do servidor se a sessão não existe
    /// (ou sempre, quando `force`).
    ///
    /// `lid` é o LID do destinatário para o `convertlidDevice` (Node
    /// `assertSessions(jids, force, lids)`).
    pub async fn assert_sessions(
        &self,
        jids: &[String],
        force: bool,
        lid: Option<&str>,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let store = self.store.as_ref() as &dyn SignalStore;
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        let mut to_fetch: Vec<String> = Vec::new();
        for jid in jids {
            let converted = convert_lid_device(jid, lid, &me_id, &me_lid);
            let addr = baileys_signal::protocol::session::jid_to_signal_protocol_address(&converted)
                .map(|a| a.to_string())
                .unwrap_or_default();
            if force || store.load_session(&addr)?.is_none() {
                to_fetch.push(jid.clone());
            }
        }

        if to_fetch.is_empty() {
            return Ok(());
        }

        tracing::debug!(to_fetch = ?to_fetch, "buscando sessões E2E");

        let users: Vec<BinaryNode> = to_fetch
            .iter()
            .map(|jid| BinaryNode::new("user").with_attr("jid", jid))
            .collect();

        let query = BinaryNode::new("iq")
            .with_attr("xmlns", "encrypt")
            .with_attr("type", "get")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("id", self.next_tag())
            .with_children(vec![BinaryNode::new("key").with_children(users)]);

        let result = self.query_node(query, sink).await?;

        let repo = SignalRepository::new(store);
        if let Some(list) = result.child("list") {
            for user in list.children("user") {
                let jid = user.attr("jid").unwrap_or_default().to_string();
                let skey = user.child("skey");
                let key = user.child("key");
                let identity = user.child_bytes("identity").map(|b| b.to_vec());
                let registration = user
                    .child_bytes("registration")
                    .and_then(|b| {
                        if b.len() >= 4 {
                            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);

                let extract = |node: Option<&BinaryNode>| -> Option<(u32, Vec<u8>, Vec<u8>)> {
                    let node = node?;
                    let id = node
                        .child_bytes("id")
                        .and_then(|b| {
                            if b.len() >= 3 {
                                Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let value = node.child_bytes("value").map(|b| baileys_crypto::generate_signal_pub_key(b));
                    let signature = node.child_bytes("signature").map(|b| b.to_vec()).unwrap_or_default();
                    value.map(|v| (id, v, signature))
                };

                let signed = extract(skey);
                let pre = extract(key);

                if let Some(identity) = identity {
                    if let Some((sk_id, sk_pub, sk_sig)) = signed {
                        let session = InjectSession {
                            registration_id: registration,
                            identity_key: baileys_crypto::generate_signal_pub_key(&identity),
                            signed_pre_key: InjectSignedPreKey {
                                key_id: sk_id,
                                public_key: sk_pub,
                                signature: sk_sig,
                            },
                            pre_key: pre.map(|(k_id, k_pub, _)| InjectPreKey {
                                key_id: k_id,
                                public_key: k_pub,
                                signature: vec![],
                            }),
                        };
                        let dest = convert_lid_device(&jid, lid, &me_id, &me_lid);
                        match repo.inject_e2e_session(&dest, session) {
                            Ok(()) => tracing::debug!(jid, dest, "sessão E2E injetada"),
                            Err(e) => tracing::warn!(jid, dest, error = %e, "falha ao injetar sessão E2E"),
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // --- infra de query / envio ---

    /// Envia um nó binário (fire-and-forget) — exposto para o CallManager.
    pub async fn send_node(
        &self,
        node: &BinaryNode,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let bytes = encode_binary_node(node);
        // Criptografa via Noise (igual ao `sendRawMessage` do Node).
        let frame = if let Some(noise) = self.noise.lock().await.clone() {
            noise.lock().await.encode_frame(&bytes)?
        } else {
            bytes
        };
        let mut sink = sink.lock().await;
        sink.send(WsMessage::Binary(frame))
            .await
            .map_err(ClientError::WebSocket)
    }

    /// Envia uma query e aguarda o resultado — exposto para helpers do container.
    pub async fn query_node(
        &self,
        node: BinaryNode,
        sink: &WsSink,
    ) -> Result<BinaryNode, ClientError> {
        let id = node.attr("id").unwrap_or_default().to_string();
        tracing::debug!(id = %id, "query_node: enviando query");
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_queries.lock().await.insert(id.clone(), tx);
        self.send_node(&node, sink).await?;

        match tokio::time::timeout(
            std::time::Duration::from_millis(self.config.default_query_timeout_ms),
            rx,
        )
        .await
        {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(ClientError::QueryDropped),
            Err(_) => {
                self.pending_queries.lock().await.remove(&id);
                Err(ClientError::QueryTimeout)
            }
        }
    }

    /// `groupFetchAllParticipating` — lista os grupos em que o número participa.
    pub async fn group_fetch_all_participating(
        &self,
        sink: &WsSink,
    ) -> Result<Vec<crate::groups::GroupMetadata>, ClientError> {
        let query = crate::groups::group_fetch_all_participating_query()
            .with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        tracing::debug!(result = ?result.tag, children = ?result.content.as_ref().map(|c| match c { baileys_core::BinaryContent::Children(ch) => ch.iter().map(|x| x.tag.clone()).collect::<Vec<_>>(), _ => vec![] }), "group_fetch_all_participating resultado");
        let mut out = Vec::new();
        if let Some(groups) = result.child("groups") {
            for group_node in groups.children("group") {
                let wrapped = BinaryNode::new("result").with_children(vec![group_node.clone()]);
                if let Some(meta) = crate::groups::extract_group_metadata(&wrapped) {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    /// `groupGetInviteInfo` — metadados de um grupo a partir do código de convite.
    pub async fn group_get_invite_info(
        &self,
        code: &str,
        sink: &WsSink,
    ) -> Result<crate::groups::GroupMetadata, ClientError> {
        let query = crate::groups::group_query_node(
            "@g.us",
            "get",
            vec![BinaryNode::new("invite").with_attr("code", code)],
        )
        .with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        crate::groups::extract_group_metadata(&result)
            .ok_or(ClientError::GroupMetadata)
    }

    /// `groupAcceptInvite` — entra num grupo via código de convite.
    pub async fn group_accept_invite(
        &self,
        code: &str,
        sink: &WsSink,
    ) -> Result<String, ClientError> {
        let query = crate::groups::group_query_node(
            "@g.us",
            "set",
            vec![BinaryNode::new("invite").with_attr("code", code)],
        )
        .with_attr("id", self.next_tag());
        let result = self.query_node(query, sink).await?;
        Ok(result
            .child("group")
            .and_then(|g| g.attr("jid"))
            .unwrap_or_default()
            .to_string())
    }

    /// `groupSettingUpdate` — announcement/not_announcement/locked/unlocked.
    pub async fn group_setting_update(
        &self,
        jid: &str,
        setting: &str,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let query = crate::groups::group_setting_update_query(jid, setting)
            .with_attr("id", self.next_tag());
        self.query_node(query, sink).await?;
        Ok(())
    }

    /// `profilePictureUrl` — busca a URL da foto de perfil (com cache TTL
    /// `profilePicture` para evitar consultas repetidas — anti-ban).
    pub async fn profile_picture_url(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<Option<String>, ClientError> {
        let normalized = baileys_core::jid_normalized_user(jid);
        if let Some(cached) = self.profile_picture_cache.get(&normalized).await {
            return Ok(Some(cached));
        }
        let query = BinaryNode::new("iq")
            .with_attr("target", &normalized)
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "get")
            .with_attr("xmlns", "w:profile:picture")
            .with_attr("id", self.next_tag())
            .with_children(vec![
                BinaryNode::new("picture").with_attr("type", "preview").with_attr("query", "url"),
            ]);
        let result = self.query_node(query, sink).await?;
        let url = result
            .child("picture")
            .and_then(|p| p.attr("url"))
            .map(String::from);
        if let Some(u) = &url {
            self.profile_picture_cache.set(normalized, u.clone()).await;
        }
        Ok(url)
    }

    /// `onWhatsApp` (USync contact+LID) — verifica existência no WhatsApp,
    /// com cache TTL (`onWhatsapp`).
    pub async fn on_whatsapp(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<Option<bool>, ClientError> {
        let normalized = baileys_core::jid_normalized_user(jid);
        if !normalized.is_empty() {
            if let Some(cached) = self.on_whatsapp_cache.get(&normalized).await {
                return Ok(Some(cached));
            }
        }
        let phone = normalized
            .trim_start_matches('+')
            .split('@')
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_string();
        if phone.is_empty() {
            return Ok(None);
        }
        let results = self
            .execute_usync(
                &[crate::usync::USyncProtocol::Contact],
                &[crate::usync::USyncUser {
                    id: None,
                    lid: None,
                    phone: Some(format!("+{phone}")),
                }],
                "interactive",
                sink,
            )
            .await?;
        let exists = results.first().map(|r| r.contact.unwrap_or(false));
        if let Some(e) = exists {
            let cache_key = if normalized.is_empty() {
                format!("{phone}@s.whatsapp.net")
            } else {
                normalized
            };
            // TTL diferenciado como no Node: existe = 1800s, não existe = 300s.
            let ttl = if e { Duration::from_secs(1800) } else { Duration::from_secs(300) };
            self.on_whatsapp_cache.set_with_ttl(cache_key, e, ttl).await;
        }
        Ok(exists)
    }

    /// `fetchStatus` — busca o status customizado via USync.
    pub async fn fetch_status(
        &self,
        jid: &str,
        sink: &WsSink,
    ) -> Result<Option<String>, ClientError> {
        let results = self
            .execute_usync(
                &[crate::usync::USyncProtocol::Status],
                &[crate::usync::USyncUser {
                    id: Some(baileys_core::jid_normalized_user(jid)),
                    lid: None,
                    phone: None,
                }],
                "interactive",
                sink,
            )
            .await?;
        Ok(results.first().and_then(|r| r.status.clone()))
    }

    /// `updateBlockStatus` — bloqueia/desbloqueia um usuário.
    pub async fn update_block_status(
        &self,
        jid: &str,
        action: &str,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let normalized = baileys_core::jid_normalized_user(jid);
        let query = BinaryNode::new("iq")
            .with_attr("xmlns", "blocklist")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "set")
            .with_attr("id", self.next_tag())
            .with_children(vec![
                BinaryNode::new("item")
                    .with_attr("action", action)
                    .with_attr("jid", &normalized),
            ]);
        self.query_node(query, sink).await?;
        Ok(())
    }

    /// `sendPresenceUpdate` — `available`/`unavailable`/`composing`/`paused`.
    pub async fn send_presence_update(
        &self,
        presence_type: &str,
        to_jid: Option<&str>,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let creds = self.store.creds();
        let me = creds.me.clone().unwrap_or_default();
        let me_id = me.id;
        let me_lid = me.lid.unwrap_or_default();

        let node = match presence_type {
            "available" | "unavailable" => {
                // `name` é o pushName da conta (`me.name`), nunca o JID: o
                // servidor grava esse valor como nome de perfil.
                let Some(name) = me.name.filter(|n| !n.is_empty()) else {
                    tracing::warn!("no name present, ignoring presence update request...");
                    return Ok(());
                };
                // `ev.emit('connection.update', { isOnline })` → `sendActiveReceipts`.
                self.send_active_receipts
                    .store(presence_type == "available", Ordering::Relaxed);
                BinaryNode::new("presence")
                    .with_attr("name", name.replace('@', ""))
                    .with_attr("type", presence_type)
            }
            _ => {
                let to = to_jid.unwrap_or_default();
                let from = if baileys_core::is_lid_user(to) { me_lid } else { me_id };
                let state = if presence_type == "recording" {
                    BinaryNode::new("composing").with_attr("media", "audio")
                } else {
                    BinaryNode::new(presence_type)
                };
                BinaryNode::new("chatstate")
                    .with_attr("from", from)
                    .with_attr("to", to)
                    .with_children(vec![state])
            }
        };
        self.send_node(&node, sink).await
    }

    /// `fetchPrivacySettings` — `<iq xmlns=privacy type=get><privacy/>`,
    /// reduzido a `{ name: value }` e cacheado (como o Node).
    pub async fn fetch_privacy_settings(
        &self,
        force: bool,
        sink: &WsSink,
    ) -> Result<HashMap<String, String>, ClientError> {
        if !force {
            if let Some(cached) = self.privacy_settings.lock().await.clone() {
                return Ok(cached);
            }
        }
        let query = BinaryNode::new("iq")
            .with_attr("xmlns", "privacy")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "get")
            .with_attr("id", self.next_tag())
            .with_children(vec![BinaryNode::new("privacy")]);
        let result = self.query_node(query, sink).await?;
        let mut settings = HashMap::new();
        if let Some(privacy) = result.child("privacy") {
            for category in privacy.children("category") {
                let name = category.attr("name").or_else(|| category.attr("config_code"));
                let value = category.attr("value").or_else(|| category.attr("config_value"));
                if let (Some(name), Some(value)) = (name, value) {
                    settings.insert(name.to_string(), value.to_string());
                }
            }
        }
        *self.privacy_settings.lock().await = Some(settings.clone());
        Ok(settings)
    }

    /// `readMessages` — `read` (readreceipts=all) ou `read-self`, agrupado
    /// por chat + participante (`aggregateMessageKeysNotFromMe`).
    pub async fn read_messages(
        &self,
        keys: &[wa::MessageKey],
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let settings = self.fetch_privacy_settings(false, sink).await?;
        let read_type = if settings.get("readreceipts").map(String::as_str) == Some("all") {
            "read"
        } else {
            "read-self"
        };

        let mut groups: Vec<(String, Option<String>, Vec<String>)> = Vec::new();
        for key in keys.iter().filter(|k| !k.from_me.unwrap_or(false)) {
            let jid = key.remote_jid.clone().unwrap_or_default();
            let participant = key.participant.clone().filter(|p| !p.is_empty());
            let Some(id) = key.id.clone() else { continue };
            match groups.iter_mut().find(|(j, p, _)| *j == jid && *p == participant) {
                Some((_, _, ids)) => ids.push(id),
                None => groups.push((jid, participant, vec![id])),
            }
        }
        for (jid, participant, ids) in groups {
            self.send_receipt(&jid, participant.as_deref(), &ids, Some(read_type), sink).await?;
        }
        Ok(())
    }

    /// `updateProfilePicture` — troca a foto de perfil (própria ou de grupo).
    pub async fn update_profile_picture(
        &self,
        jid: &str,
        jpeg: Vec<u8>,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let normalized = baileys_core::jid_normalized_user(jid);
        let me_id = self.me_id();
        let target = if normalized == baileys_core::jid_normalized_user(&me_id) {
            None
        } else {
            Some(normalized)
        };
        let mut query = BinaryNode::new("iq")
            .with_attr("to", S_WHATSAPP_NET)
            .with_attr("type", "set")
            .with_attr("xmlns", "w:profile:picture")
            .with_attr("id", self.next_tag());
        if let Some(t) = target {
            query = query.with_attr("target", t);
        }
        query = query.with_children(vec![
            BinaryNode::new("picture").with_attr("type", "image").with_bytes(jpeg),
        ]);
        self.query_node(query, sink).await?;
        Ok(())
    }

    fn next_tag(&self) -> String {
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst);
        format!("{}{}", self.tag_prefix, epoch)
    }

    /// `generateMessageTag` — id para queries montadas fora da lib.
    pub fn generate_message_tag(&self) -> String {
        self.next_tag()
    }

    /// `rejectCall` do Hineken: rejeita qualquer chamada pelo `callId`/`callFrom`,
    /// sem depender do estado do gerenciador de chamadas.
    pub async fn reject_call(&self, call_id: &str, call_from: &str, sink: &WsSink) -> Result<(), ClientError> {
        let stanza = BinaryNode::new("call")
            .with_attr("id", self.next_tag())
            .with_attr("from", self.me_id())
            .with_attr("to", call_from)
            .with_children(vec![BinaryNode::new("reject")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_from)
                .with_attr("count", "0")]);
        self.query_node(stanza, sink).await?;
        Ok(())
    }
}

fn to_buffer(bytes: &[u8]) -> baileys_store::creds::BufferValue {
    baileys_store::creds::BufferValue::Buffer {
        type_: "Buffer".to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

fn decode_buffer(value: &baileys_store::creds::BufferValue) -> Vec<u8> {
    match value {
        baileys_store::creds::BufferValue::Buffer { data, .. }
        | baileys_store::creds::BufferValue::Raw(data) => {
            base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default()
        }
    }
}

/// Monta o payload do QR exatamente como o Node Baileys (`genPairQR`):
/// `[ref, noiseKeyB64, identityKeyB64, advB64].join(',')`.
fn gen_qr(ref_str: &str, noise_b64: &str, identity_b64: &str, adv_b64: &str) -> String {
    format!("{ref_str},{noise_b64},{identity_b64},{adv_b64}")
}

fn write_random_pad_max16(msg: &[u8]) -> Vec<u8> {
    baileys_core::ids::write_random_pad_max16(msg)
}

/// URL-encode simples (espelha `encodeURIComponent` do JS para o token de auth).
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `convertlidDevice` — port de `Utils/messages.ts`.
fn convert_lid_device(jid: &str, lid: Option<&str>, meid: &str, melid: &str) -> String {
    let me_lid_user = jid_user(melid).unwrap_or_default();
    let me_jid_user = jid_user(meid).unwrap_or_default();
    let jid_user_name = jid_user(jid).unwrap_or_default();
    let jid_device = jid_device(jid);

    if jid_user_name == me_jid_user {
        return match jid_device {
            Some(0) | None => format!("{me_lid_user}@lid"),
            Some(d) => format!("{me_lid_user}:{d}@lid"),
        };
    }
    if jid_user_name == me_lid_user {
        return jid.to_string();
    }
    let Some(lid) = lid else {
        return jid.to_string();
    };
    let lid_user = jid_user(lid).unwrap_or_default();
    match jid_device {
        Some(0) | None => format!("{lid_user}@lid"),
        Some(d) => format!("{lid_user}:{d}@lid"),
    }
}

fn jid_user(jid: &str) -> Option<String> {
    baileys_core::jid_decode(jid).map(|d| d.user)
}

fn jid_device(jid: &str) -> Option<u32> {
    baileys_core::jid_decode(jid).and_then(|d| d.device)
}

/// Entradas de fallback do device 0 do remetente no fanout de grupo — port
/// de `messages-send.ts:679-684` do Node.
///
/// Quando o USync não retornou o phone (device 0), o Node empurra DOIS
/// entries: a LID (`jlidUser` → `meLid`) e a PN (`user` → `meId`), onde `user`
/// vem de `jidDecode(destinationJid).user` — para grupo, o user do próprio
/// grupo (`...@g.us`), NÃO o número do remetente. Isso faz o `senderId` PN
/// virar `{group_id}@s.whatsapp.net` (inócuo) em vez de distribuir a sender
/// key sob a identidade PN do remetente (`{numero}@s.whatsapp.net`), que é o
/// que faz o WhatsApp do destinatário exibir `numero:device@s.whatsapp.net`
/// na bolha.
fn device0_fallback_entries(
    me_lid: &str,
    me_id: &str,
    dest_jid: &str,
) -> Vec<(String, u32, String)> {
    let me_lid_user = jid_user(me_lid).unwrap_or_default();
    let dest_user = jid_user(dest_jid).unwrap_or_default();
    vec![
        (me_lid_user, 0, baileys_core::jid_normalized_user(me_lid)),
        (dest_user, 0, baileys_core::jid_normalized_user(me_id)),
    ]
}

fn is_jid_user(jid: &str) -> bool {
    baileys_core::is_jid_user(jid)
}

fn is_lid_user(jid: &str) -> bool {
    baileys_core::is_lid_user(jid)
}

/// Primeiro wrapper `FutureProofMessage` presente (`getFutureProofMessage`).
macro_rules! first_future_proof {
    (@fields $m:expr, $conv:ident, [$($field:ident),*]) => {{
        $( if $m.$field.is_some() { return $m.$field.$conv(); } )*
        None
    }};
    ($m:expr, $conv:ident) => {{
        first_future_proof!(@fields $m, $conv, [
            ephemeral_message, view_once_message, document_with_caption_message,
            view_once_message_v2, view_once_message_v2_extension, edited_message,
            status_add_yours, bot_task_message, event_cover_image, question_message,
            bot_invoke_message, lottie_sticker_message, group_status_message,
            limit_sharing_message, status_mention_message, poll_creation_message_v4,
            poll_creation_message_v5, associated_child_message, group_mentioned_message,
            group_status_mention_message, poll_creation_option_image_message
        ])
    }};
}

fn future_proof_ref(m: &wa::Message) -> Option<&wa::message::FutureProofMessage> {
    first_future_proof!(m, as_deref)
}

fn future_proof_mut(m: &mut wa::Message) -> Option<&mut wa::message::FutureProofMessage> {
    first_future_proof!(m, as_deref_mut)
}

/// `normalizeMessageContent` (até 5 níveis de wrapper).
fn normalize_message_content(message: &wa::Message) -> &wa::Message {
    let mut content = message;
    for _ in 0..5 {
        match future_proof_ref(content).and_then(|f| f.message.as_deref()) {
            Some(inner) => content = inner,
            None => break,
        }
    }
    content
}

fn normalize_message_content_mut(message: &mut wa::Message, depth: u8) -> &mut wa::Message {
    if depth >= 5 || future_proof_ref(message).and_then(|f| f.message.as_ref()).is_none() {
        return message;
    }
    let inner = future_proof_mut(message)
        .and_then(|f| f.message.as_deref_mut())
        .expect("wrapper verificado acima");
    normalize_message_content_mut(inner, depth + 1)
}

/// `cleanMessage` do Hineken: normaliza `remoteJid`/`participant` e traz as
/// keys de reação/voto para a perspectiva deste usuário.
fn clean_message(info: &mut wa::WebMessageInfo, me_id: &str) {
    let Some(key) = info.key.as_mut() else {
        return;
    };
    key.remote_jid = Some(baileys_core::jid_normalized_user(key.remote_jid.as_deref().unwrap_or_default()));
    key.participant = key.participant.as_deref().map(baileys_core::jid_normalized_user);
    let from_me = key.from_me.unwrap_or(false);
    let remote_jid = key.remote_jid.clone();
    let participant = key.participant.clone();

    let Some(message) = info.message.as_mut() else {
        return;
    };
    let content = normalize_message_content_mut(message, 0);
    let normalise_key = |msg_key: &mut wa::MessageKey| {
        if from_me {
            return;
        }
        msg_key.from_me = Some(if !msg_key.from_me.unwrap_or(false) {
            let who = msg_key
                .participant
                .as_deref()
                .filter(|p| !p.is_empty())
                .or(msg_key.remote_jid.as_deref())
                .unwrap_or_default();
            are_jids_same_user(who, me_id)
        } else {
            false
        });
        msg_key.remote_jid = remote_jid.clone();
        if msg_key.participant.as_deref().map_or(true, str::is_empty) {
            msg_key.participant = participant.clone();
        }
    };
    if let Some(k) = content.reaction_message.as_mut().and_then(|r| r.key.as_mut()) {
        normalise_key(k);
    }
    if let Some(k) = content
        .poll_update_message
        .as_mut()
        .and_then(|p| p.poll_creation_message_key.as_mut())
    {
        normalise_key(k);
    }
}

/// `decryptSecretEncryptedEdit`: HKDF-SHA256 (salt vazio, info = id + chatJid
/// + chatJid + "Message Edit") e AES-256-GCM sem AAD.
fn decrypt_secret_encrypted_edit(
    secret: &wa::message::SecretEncryptedMessage,
    message_secret: &[u8],
    original_msg_id: &str,
    chat_jid: &str,
) -> Result<wa::Message, String> {
    let enc_payload = secret.enc_payload.as_deref().ok_or("secretEncryptedMessage sem encPayload")?;
    let enc_iv = secret.enc_iv.as_deref().ok_or("secretEncryptedMessage sem encIv")?;
    let info = format!("{original_msg_id}{chat_jid}{chat_jid}Message Edit");
    let key = baileys_crypto::hkdf(message_secret, 32, None, &info).map_err(|e| e.to_string())?;
    let plaintext = baileys_crypto::aes_decrypt_gcm(enc_payload, &key, enc_iv, &[]).map_err(|e| e.to_string())?;
    wa::Message::decode(plaintext.as_slice()).map_err(|e| e.to_string())
}

fn is_jid_group(jid: &str) -> bool {
    baileys_core::is_jid_group(jid)
}

/// `getStatusFromReceiptType` (port de `Utils/generics.ts` do Hineken).
fn get_status_from_receipt_type(r#type: Option<&str>) -> Option<i32> {
    match r#type {
        Some("sender") => Some(wa::web_message_info::Status::ServerAck as i32),
        Some("played") => Some(wa::web_message_info::Status::Played as i32),
        Some("read") | Some("read-self") => Some(wa::web_message_info::Status::Read as i32),
        None => Some(wa::web_message_info::Status::DeliveryAck as i32),
        _ => None,
    }
}

/// `unixTimestampSeconds()`.
fn chrono_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `isTcTokenExpired` (port de `Utils/tc-token-utils.ts`) — bucket rolante
/// do WA Web: expira se o timestamp está antes do cutoff de 4 buckets.
fn is_tc_token_expired(timestamp: Option<&str>) -> bool {
    const BUCKET_DURATION: i64 = 604800; // 7 dias
    const NUM_BUCKETS: i64 = 4;
    let Some(ts) = timestamp else { return true };
    let Ok(ts) = ts.parse::<i64>() else { return true };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let current_bucket = now / BUCKET_DURATION;
    let cutoff_bucket = current_bucket - (NUM_BUCKETS - 1);
    let cutoff_timestamp = cutoff_bucket * BUCKET_DURATION;
    ts < cutoff_timestamp
}

/// `shouldSendNewTcToken` (port de `Utils/tc-token-utils.ts`): o bucket de
/// 7 dias atual já passou do bucket do timestamp.
fn should_send_new_tc_token(sender_timestamp: i64) -> bool {
    const BUCKET_DURATION: i64 = 604800;
    let now = chrono_now_secs() as i64;
    now / BUCKET_DURATION > sender_timestamp / BUCKET_DURATION
}

/// `computeCsToken` (port de `Utils/tc-token-utils.ts`) — HMAC-SHA256 do
/// `nctSalt` sobre o `recipientLid` UTF-8.
fn compute_cs_token(nct_salt: &[u8], recipient_lid: &str) -> Vec<u8> {
    baileys_crypto::hmac_sign(recipient_lid.as_bytes(), nct_salt, baileys_crypto::HmacVariant::Sha256)
}

/// Extrai bytes de um valor JSON do BufferJSON: `{"type":"Buffer","data":"..."}`
/// ou array de números (reviver do `contacts-tc-token`).
fn buffer_value_bytes(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Object(map) => {
            let data = map.get("data").or_else(|| map.get("value"));
            match data {
                Some(serde_json::Value::String(s)) => {
                    base64::engine::general_purpose::STANDARD.decode(s).ok()
                }
                Some(serde_json::Value::Array(arr)) => Some(
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect(),
                ),
                _ => None,
            }
        }
        serde_json::Value::Array(arr) => Some(
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect(),
        ),
        _ => None,
    }
}

/// `getMessageType` (port de `messages-send.js` do Hineken):
/// `poll` para criação de enquete, senão `text`.
fn get_message_type(message: &wa::Message) -> &'static str {
    if message.poll_creation_message.is_some()
        || message.poll_creation_message_v2.is_some()
        || message.poll_creation_message_v3.is_some()
    {
        return "poll";
    }
    "text"
}

/// `getMediaType` (port de `messages-send.js` do Hineken) — usada no
/// `extraAttrs['mediatype']` do `enc` skmsg para mensagens de mídia.
/// `extraAttrs` do `relayMessage`: `mediatype` e `decrypt-fail=hide` (pin).
/// Vão nos `enc` 1:1 (`createParticipantNodes`/retry), nunca no `skmsg`.
fn relay_extra_attrs(message: &wa::Message) -> Vec<(&'static str, &'static str)> {
    let mut attrs = Vec::new();
    if let Some(mediatype) = get_media_type(message) {
        attrs.push(("mediatype", mediatype));
    }
    if message.pin_in_chat_message.is_some() {
        attrs.push(("decrypt-fail", "hide"));
    }
    attrs
}

/// `<to jid><enc v=2 type ...extraAttrs/></to>` (`createParticipantNodes`).
fn participant_enc_node(
    jid: &str,
    enc_type: &str,
    ciphertext: Vec<u8>,
    extra_attrs: &[(&'static str, &'static str)],
) -> BinaryNode {
    let mut enc = BinaryNode::new("enc").with_attr("v", "2").with_attr("type", enc_type);
    for &(k, v) in extra_attrs {
        enc = enc.with_attr(k, v);
    }
    BinaryNode::new("to")
        .with_attr("jid", jid)
        .with_children(vec![enc.with_bytes(ciphertext)])
}

/// `<enc v=2 type count ...extraAttrs/>` do retry direcionado (`participant`).
fn retry_enc_node(
    enc_type: &str,
    ciphertext: Vec<u8>,
    count: u32,
    extra_attrs: &[(&'static str, &'static str)],
) -> BinaryNode {
    let mut enc = BinaryNode::new("enc")
        .with_attr("v", "2")
        .with_attr("type", enc_type)
        .with_attr("count", count.max(1).to_string());
    for &(k, v) in extra_attrs {
        enc = enc.with_attr(k, v);
    }
    enc.with_bytes(ciphertext)
}

/// `<enc v=2 type=skmsg/>` do grupo — o Node não espalha `extraAttrs` aqui.
fn skmsg_enc_node(ciphertext: Vec<u8>) -> BinaryNode {
    BinaryNode::new("enc")
        .with_attr("v", "2")
        .with_attr("type", "skmsg")
        .with_bytes(ciphertext)
}

fn get_media_type(message: &wa::Message) -> Option<&'static str> {
    if message.image_message.is_some() {
        Some("image")
    } else if let Some(v) = &message.video_message {
        Some(if v.gif_playback.unwrap_or(false) { "gif" } else { "video" })
    } else if let Some(a) = &message.audio_message {
        Some(if a.ptt.unwrap_or(false) { "ptt" } else { "audio" })
    } else if message.contact_message.is_some() {
        Some("vcard")
    } else if message.document_message.is_some() {
        Some("document")
    } else if message.contacts_array_message.is_some() {
        Some("contact_array")
    } else if message.live_location_message.is_some() {
        Some("livelocation")
    } else if message.sticker_message.is_some() {
        Some("sticker")
    } else if message.list_message.is_some() {
        Some("list")
    } else if message.list_response_message.is_some() {
        Some("list_response")
    } else if message.buttons_response_message.is_some() {
        Some("buttons_response")
    } else if message.order_message.is_some() {
        Some("order")
    } else if message.product_message.is_some() {
        Some("product")
    } else if message.interactive_response_message.is_some() {
        Some("native_flow_response")
    } else if message.group_invite_message.is_some() {
        Some("url")
    } else {
        None
    }
}

fn are_jids_same_user(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (jid_user(a), jid_user(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Erros do client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("sqlite: {0}")]
    Store(#[from] baileys_store::sqlite::StoreError),
    #[error("signal: {0}")]
    Signal(#[from] baileys_signal::error::SignalError),
    #[error("noise: {0}")]
    Noise(#[from] crate::noise::NoiseError),
    #[error("handshake: {0}")]
    Handshake(#[from] crate::handshake::HandshakeError),
    #[error("websocket: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("stream error ({code}): {detail}")]
    StreamError { code: i32, detail: String },
    #[error("connection failure ({code})")]
    Failure { code: i32 },
    #[error("multi-device beta not joined")]
    MultiDeviceMismatch,
    #[error("não autenticado")]
    NotAuthenticated,
    #[error("parâmetros inválidos: {0}")]
    InvalidParams(String),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("query timed out")]
    QueryTimeout,
    #[error("query channel dropped")]
    QueryDropped,
    #[error("media conn indisponível")]
    MediaConn,
    #[error("metadados de grupo ausentes")]
    GroupMetadata,
    #[error("media upload falhou em todos os hosts")]
    MediaUploadFailed,
    #[error("media: {0}")]
    Media(#[from] baileys_media::MediaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{account_from_json, account_to_json};

    fn temp_session_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("baileys-socket-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn device0_fallback_pn_uses_destination_user_not_sender() {
        // Paridade com `messages-send.ts:679-684`: a entrada PN do fallback
        // usa `jidDecode(destinationJid).user` — para grupo, o user do grupo
        // — NUNCA o número do remetente. Se usasse o número, o senderId PN
        // distribuiria a sender key sob `{numero}@s.whatsapp.net` e o
        // destinatário imprimiria `numero:device@s.whatsapp.net` na bolha.
        let me_lid = "5531999999999@lid";
        let me_id = "5511988888888:7@s.whatsapp.net";
        let group_jid = "1203630123456789@g.us";

        let entries = device0_fallback_entries(me_lid, me_id, group_jid);
        assert_eq!(entries.len(), 2);

        // Entrada LID: user = meLid user, jid = meLid normalizado.
        assert_eq!(entries[0].0, "5531999999999");
        assert_eq!(entries[0].1, 0);
        assert_eq!(entries[0].2, "5531999999999@lid");

        // Entrada PN: user = user do GRUPO (não o remetente), jid = meId normalizado.
        assert_eq!(entries[1].0, "1203630123456789");
        assert_eq!(entries[1].1, 0);
        assert_eq!(entries[1].2, "5511988888888@s.whatsapp.net");

        // O senderId PN gerado no fanout usa o user do destino, não do remetente.
        let (user, device, dev_jid) = &entries[1];
        let server = if baileys_core::is_lid_user(dev_jid) {
            "lid"
        } else {
            "s.whatsapp.net"
        };
        let sender_id = if *device == 0 {
            format!("{user}@{server}")
        } else {
            format!("{user}:{device}@{server}")
        };
        assert_eq!(sender_id, "1203630123456789@s.whatsapp.net");
        assert_ne!(sender_id, "5511988888888@s.whatsapp.net");
    }

    #[test]
    fn account_json_roundtrip_is_buffer_json_compatible() {
        // Formato exato do protobufjs + BufferJSON.replacer do Node.
        let account = wa::AdvSignedDeviceIdentity {
            details: Some(vec![1, 2, 3, 4]),
            account_signature_key: Some(vec![5, 6, 7, 8]),
            account_signature: Some(vec![9, 10, 11, 12]),
            device_signature: Some(vec![13, 14, 15, 16]),
        };

        let json = account_to_json(&account);
        // Campos camelCase como o protobufjs grava.
        assert_eq!(json["accountSignatureKey"]["type"], "Buffer");
        assert_eq!(
            json["details"]["data"],
            base64::engine::general_purpose::STANDARD.encode([1, 2, 3, 4])
        );

        let back = account_from_json(&json).unwrap();
        assert_eq!(back.details.as_deref(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(back.account_signature_key.as_deref(), Some(&[5, 6, 7, 8][..]));
        assert_eq!(back.account_signature.as_deref(), Some(&[9, 10, 11, 12][..]));
        assert_eq!(back.device_signature.as_deref(), Some(&[13, 14, 15, 16][..]));

        // Campos ausentes → None (o Node usa null, mas semanticamente equivalente).
        let partial = serde_json::json!({
            "details": null,
            "accountSignatureKey": {"type": "Buffer", "data": "BQ=="},
            "accountSignature": null,
            "deviceSignature": null
        });
        let decoded = account_from_json(&partial).unwrap();
        assert_eq!(decoded.details, None);
        assert_eq!(decoded.account_signature_key.as_deref(), Some(&[5][..]));
    }

    #[test]
    fn message_roundtrip_between_two_clients() {
        // Alice e Bob com stores SQLite reais (mesmo caminho do container).
        let alice_dir = temp_session_dir("alice");
        let bob_dir = temp_session_dir("bob");

        let alice = Client::new(&alice_dir, ClientConfig::default()).unwrap();
        let bob = Client::new(&bob_dir, ClientConfig::default()).unwrap();

        let alice_jid = "5511987654321@s.whatsapp.net";
        let bob_jid = "5511998765432@s.whatsapp.net";

        // Alice conhece o bundle de chaves do Bob.
        let bob_store = bob.signal_store();
        let (bob_identity, _) = bob_store.get_our_identity().unwrap();
        let (bob_spk_pub, _) = bob_store.load_signed_pre_key().unwrap();
        let pre_key = baileys_signal::protocol::prekey::generate_pre_key(9);
        // Grava a pre-key do Bob no store (mesmo formato do `upload_pre_keys`).
        let serialized = baileys_store::creds::SerializedKeyPair {
            public: to_buffer(&pre_key.key_pair.public),
            private: to_buffer(&pre_key.key_pair.private),
        };
        bob_store.store_pre_key(9, &serialized).unwrap();

        let alice_store = alice.signal_store();
        let repo = SignalRepository::new(alice_store.as_ref() as &dyn SignalStore);
        repo.inject_e2e_session(
            &convert_lid_device(bob_jid, None, alice_jid, alice_jid),
            InjectSession {
                registration_id: bob_store.get_our_registration_id().unwrap(),
                identity_key: bob_identity,
                signed_pre_key: InjectSignedPreKey {
                    key_id: 1,
                    public_key: bob_spk_pub,
                    signature: vec![],
                },
                pre_key: Some(InjectPreKey {
                    key_id: 9,
                    public_key: pre_key.key_pair.public,
                    signature: vec![],
                }),
            },
        )
        .unwrap();

        // Alice criptografa (caminho real do send_text).
        let payload = write_random_pad_max16(&wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("oi bob".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .encode_to_vec());
        let enc = repo
            .encrypt_message(&convert_lid_device(bob_jid, None, alice_jid, alice_jid), &payload)
            .unwrap();
        assert_eq!(enc.r#type, "pkmsg");

        // Bob descriptografa (caminho real do handle_message).
        let bob_repo = SignalRepository::new(bob_store.as_ref() as &dyn SignalStore);
        let pt = bob_repo
            .decrypt_message(alice_jid, &enc.r#type, &enc.ciphertext)
            .unwrap();
        let unpadded = baileys_core::ids::unpad_random_max16(&pt).unwrap();
        let decoded = wa::Message::decode(unpadded.as_slice()).unwrap();
        assert_eq!(
            decoded
                .extended_text_message
                .as_ref()
                .and_then(|m| m.text.as_deref()),
            Some("oi bob")
        );

        let _ = std::fs::remove_dir_all(&alice_dir);
        let _ = std::fs::remove_dir_all(&bob_dir);
    }
}
