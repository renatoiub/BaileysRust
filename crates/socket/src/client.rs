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
    pub pinned: Option<u32>,
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
pub struct GroupUpdate {
    pub id: String,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub desc: Option<String>,
    pub announce: Option<bool>,
    pub restrict: Option<bool>,
    pub invite_code: Option<String>,
    pub member_add_mode: Option<bool>,
    pub join_approval_mode: Option<bool>,
    pub suspended: Option<bool>,
    pub deleted: Option<bool>,
    pub delete_reason: Option<String>,
}

/// Atualização de participantes de grupo (espelha `group-participants.update`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GroupParticipantsUpdate {
    pub id: String,
    pub author: Option<String>,
    pub participants: Vec<String>,
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

use crate::cache::{CacheStore, TtlCache};

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
    /// Handle da task de rotação de QR (para cancelar ao parear).
    qr_rotation: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Cache de envio: `msg_id` → `(destino, Message codificado)` para o
    /// reenvio em `<receipt type="retry">` (port de `sendMessageCache`).
    /// Limitado a `SEND_CACHE_MAX` entradas (FIFO): o retry cai no store Redis
    /// do app (`load_message_fn`) quando o cache erra, então evictar é seguro.
    send_cache: Mutex<HashMap<String, (String, Vec<u8>)>>,
    /// Ordem FIFO de inserção no `send_cache` (msg_id) para evicção da mais
    /// antiga quando o limite é atingido.
    send_cache_order: Mutex<Vec<String>>,
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
        let (events, _) = tokio::sync::broadcast::channel(64);

        Ok(Self {
            store,
            config,
            epoch: AtomicU32::new(1),
            tag_prefix: generate_md_tag_prefix(),
            pending_queries: Mutex::new(HashMap::new()),
            events,
            sink: Mutex::new(None),
            noise: Mutex::new(None),
            last_close_code: AtomicI32::new(0),
            qr_rotation: Mutex::new(None),
            send_cache: Mutex::new(HashMap::new()),
            send_cache_order: Mutex::new(Vec::new()),
            force_session_cache: TtlCache::new(Duration::from_secs(600), 2000),
            retry_mutex: Mutex::new(()),
            msg_retry_cache: TtlCache::new(Duration::from_secs(3600), 2000),
            placeholder_resend_cache: TtlCache::new(Duration::from_secs(3600), 2000),
            lid_cache: TtlCache::new(Duration::from_secs(3600), 2000),
            devices_cache: TtlCache::new(Duration::from_secs(1000), 2000),
            on_whatsapp_cache: TtlCache::new(Duration::from_secs(7200), 1000),
            sender_key_memory: TtlCache::new(Duration::from_secs(86400), 2000),
            profile_picture_cache: TtlCache::new(Duration::from_secs(7200), 1000),
            group_meta_cache: TtlCache::new(Duration::from_secs(3600), 1000),
            save_message_fn: Mutex::new(None),
            load_message_fn: Mutex::new(None),
        })
    }

    /// Último código de desconexão (0 = nunca desconectou).
    pub fn last_close_code(&self) -> i32 {
        self.last_close_code.load(Ordering::SeqCst)
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

    /// Registra uma extensão de armazenamento de chaves de sinal (ex. Redis
    /// do app). Encaminha para o `SqliteSignalStore` (session/sender-key/
    /// pre-key via `load`/`store`/`remove`).
    pub fn set_store_extension(&self, ext: Arc<dyn SignalStoreExtension>) {
        self.store.set_extension(ext);
    }

    /// Registra o backend externo de cache (ex. Redis) para todos os caches.
    ///
    /// - Globais/compartilhados: `cache:global:{namespace}`.
    /// - Por conexão: `cache:instance:{instanceKey}:{namespace}` (isolados por
    ///   instância para não misturar conexões do mesmo container nem de
    ///   containers diferentes).
    ///
    /// O `TtlCache` faz fallback automático para memória quando o backend
    /// falha, então a operação não é interrompida.
    pub fn set_cache_backend(&self, instance_key: &str, backend: Arc<dyn CacheStore>) {
        self.lid_cache.set_backend("cache:global:lid", Some(backend.clone()));
        self.devices_cache.set_backend("cache:global:devices", Some(backend.clone()));
        self.on_whatsapp_cache.set_backend("cache:global:onwhatsapp", Some(backend.clone()));
        self.profile_picture_cache.set_backend("cache:global:profilepic", Some(backend.clone()));
        self.group_meta_cache.set_backend("cache:global:groupmeta", Some(backend.clone()));
        self.sender_key_memory
            .set_backend(&format!("cache:instance:{instance_key}:senderkey"), Some(backend.clone()));
        self.msg_retry_cache
            .set_backend(&format!("cache:instance:{instance_key}:msgretry"), Some(backend.clone()));
        self.placeholder_resend_cache
            .set_backend(&format!("cache:instance:{instance_key}:placeholder"), Some(backend.clone()));
        // `forceSession` do Node é `NodeCache({ stdTTL: 600 })` SÓ em memória
        // (cache-utils.ts) — nunca vai pro Redis. Offload aqui faria o force
        // valer por 24h/até expirar no Redis e o retry subsequente nunca
        // refaria o `<iq encrypt>` (mensagem presa em "aguardando").
    }

    /// Insere no `send_cache` com limite FIFO (`SEND_CACHE_MAX`). Remove a
    /// entrada mais antiga quando o limite é atingido — o retry cai no store
    /// Redis do app (`load_message_fn`), então a evicção é segura.
    async fn cache_send(&self, msg_id: String, jid: String, encoded: Vec<u8>) {
        const SEND_CACHE_MAX: usize = 500;
        let mut cache = self.send_cache.lock().await;
        if cache.len() >= SEND_CACHE_MAX {
            let mut order = self.send_cache_order.lock().await;
            while cache.len() >= SEND_CACHE_MAX {
                let Some(oldest) = order.first().cloned() else {
                    break;
                };
                order.remove(0);
                cache.remove(&oldest);
            }
        }
        if cache.insert(msg_id.clone(), (jid, encoded)).is_none() {
            // Só registra a ordem em inserção nova (não em substituição).
            self.send_cache_order.lock().await.push(msg_id);
        }
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
        let result = self.clone().run_inner().await;
        let (status_code, reason) = match &result {
            Ok(()) => (Self::WS_CONNECTION_CLOSED, "connectionClosed".to_string()),
            Err(e) => self.error_to_close(e),
        };
        self.last_close_code.store(status_code, Ordering::SeqCst);
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
        tracing::info!(url, "conectando ao WhatsApp");

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

        while let Some(msg) = stream.next().await {
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
                    let payload = match &creds.me {
                        Some(me) => generate_login_node(&me.id, &self.config),
                        None => generate_registration_node(&creds, &self.config),
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
                    tracing::info!("handshake Noise completo");
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
            tracing::info!("offline_preview recebido; pedi lote offline (count=100)");
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
            tracing::info!(count, "offline: servidor entregou notificações pendentes");
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
            tracing::info!(r#type = dtype, "dirty: sincronização pendente recebida");
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

        // Notificação de grupo (w:gp2) — criação/edição/participantes.
        if tag == "notification" && node.attr("type") == Some("w:gp2") {
            self.handle_group_notification(node);
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
            pinned: node.attr("pin").and_then(|v| v.parse::<u32>().ok()),
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
    fn handle_group_notification(&self, node: &BinaryNode) {
        let from = node.attr("from").unwrap_or_default().to_string();
        let participant = node.attr("participant").map(String::from);

        if let Some(create) = node.child("create") {
            let group_json = self.group_node_to_json(create, &from);
            let _ = self.events.send(ClientEvent::GroupsUpsert {
                groups: vec![group_json],
            });
            return;
        }

        // Filhos de update: subject, description, etc.
        let mut update = GroupUpdate {
            id: from.clone(),
            author: participant.clone(),
            ..Default::default()
        };
        let mut has_update = false;
        if let Some(subject) = node.child("subject") {
            update.subject = Some(subject.attr("subject").unwrap_or_default().to_string());
            update.author = subject.attr("participant").map(String::from).or(participant.clone());
            has_update = true;
        }
        if let Some(desc) = node.child("description") {
            update.desc = Some(desc.content_text());
            update.author = desc.attr("participant").map(String::from).or(participant.clone());
            has_update = true;
        }
        if let Some(announce) = node.child("announcement") {
            update.announce = Some(true);
            update.author = announce.attr("participant").map(String::from).or(participant.clone());
            has_update = true;
        }
        if let Some(restrict) = node.child("locked") {
            update.restrict = Some(true);
            update.author = restrict.attr("participant").map(String::from).or(participant.clone());
            has_update = true;
        }
        if let Some(code) = node.child("invite") {
            update.invite_code = code.attr("code").map(String::from);
            has_update = true;
        }
        if let Some(code) = node.child("code") {
            update.invite_code = code.attr("code").map(String::from);
            has_update = true;
        }
        if let Some(del) = node.child("delete") {
            update.deleted = Some(true);
            update.author = del.attr("participant").map(String::from).or(participant.clone());
            has_update = true;
        }

        // Participantes: add/remove/promote/demote.
        if let Some(participants_node) = node.child("add").or_else(|| node.child("remove")).or_else(|| node.child("promote")).or_else(|| node.child("demote")) {
            let action = participants_node.tag.clone();
            let mut jids: Vec<String> = Vec::new();
            for child in participants_node.children("participant") {
                if let Some(jid) = child.attr("jid") {
                    jids.push(jid.to_string());
                }
            }
            if !jids.is_empty() {
                let _ = self.events.send(ClientEvent::GroupParticipantsUpdate {
                    update: GroupParticipantsUpdate {
                        id: from.clone(),
                        author: participants_node.attr("participant").map(String::from).or(participant.clone()),
                        participants: jids,
                        action,
                    },
                });
            }
            return;
        }

        if has_update {
            let _ = self.events.send(ClientEvent::GroupsUpdate {
                updates: vec![update],
            });
        }
    }

    /// Converte um nó `<group>` (ou create) em JSON espelhando o
    /// `parseGroupData` do Node (id, subject, subjectOwner, author, etc.).
    fn group_node_to_json(&self, node: &BinaryNode, id: &str) -> serde_json::Value {
        let mut json = serde_json::Map::new();
        json.insert("id".to_string(), serde_json::Value::String(id.to_string()));
        json.insert("subject".to_string(), serde_json::Value::String(node.attr("subject").unwrap_or_default().to_string()));
        json.insert("subjectOwner".to_string(), serde_json::Value::String(node.attr("s_o").unwrap_or_default().to_string()));
        json.insert("subjectTime".to_string(), serde_json::Value::String(node.attr("s_t").unwrap_or_default().to_string()));
        json.insert("size".to_string(), serde_json::Value::String(node.attr("size").unwrap_or_default().to_string()));
        json.insert("creation".to_string(), serde_json::Value::String(node.attr("creation").unwrap_or_default().to_string()));
        json.insert("desc".to_string(), serde_json::Value::String(node.content_text()));
        json.insert("descId".to_string(), serde_json::Value::String(node.attr("id").unwrap_or_default().to_string()));
        json.insert("restrict".to_string(), serde_json::Value::String(node.attr("restrict").unwrap_or_default().to_string()));
        json.insert("announce".to_string(), serde_json::Value::String(node.attr("announce").unwrap_or_default().to_string()));
        serde_json::Value::Object(json)
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
            tracing::info!("pair-device passkey request — uso manual");
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
        tracing::info!("QR disponível");
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

        // Cancela qualquer rotação anterior (o Node tem um único `qrTimer`).
        self.cancel_qr_rotation().await;

        let handle = tokio::spawn(async move {
            for r in refs_rest {
                tokio::time::sleep(std::time::Duration::from_millis(qr_interval)).await;
                let qr = gen_qr(&r, &noise_key_b64_rot, &identity_key_b64_rot, &adv_b64_rot);
                tracing::info!("QR rotacionado");
                let _ = events_rot.send(ClientEvent::Qr(qr.clone()));
                let _ = events_rot.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
                    connection: "connecting".to_string(),
                    qr: Some(qr),
                    ..Default::default()
                }));
                qr_interval = 20_000; // refs seguintes: 20s
            }
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
        tracing::info!(lid = ?node.attr("lid"), "handle_success: iniciando login pós-success");
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

        let _ = self.events.send(ClientEvent::ConnectionUpdate(ConnectionUpdate {
            connection: "open".to_string(),
            ..Default::default()
        }));
        tracing::info!("conexão aberta com o WhatsApp");
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
        tracing::info!("upload_pre_keys_if_required: consultando pre-keys no servidor");
        let count = self.get_available_pre_keys_on_server(sink).await?;
        tracing::info!("{count} pre-keys no servidor");
        if count <= MIN_PREKEY_COUNT as i64 {
            self.upload_pre_keys(INITIAL_PREKEY_COUNT, sink).await?;
        }
        Ok(())
    }

    async fn get_available_pre_keys_on_server(
        &self,
        sink: &WsSink,
    ) -> Result<i64, ClientError> {
        tracing::info!("get_available_pre_keys_on_server: montando query count");
        let query = BinaryNode::new("iq")
            .with_attr("id", self.next_tag())
            .with_attr("xmlns", "encrypt")
            .with_attr("type", "get")
            .with_attr("to", S_WHATSAPP_NET)
            .with_children(vec![BinaryNode::new("count")]);
        tracing::info!("get_available_pre_keys_on_server: enviando query_node");
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
        tracing::info!(count, "fazendo upload de pre-keys");

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
        tracing::info!(count, "pre-keys enviadas");
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
        let participant = node.attr("participant").map(String::from);

        // Ack primeiro (class = message).
        self.send_message_ack(node, sink).await?;

        // Decodifica o envelope.
        let Some((full_message, author, sender, key_extras)) = self.decode_message_node(node) else {
            tracing::debug!(from = %from, "decode_message_node retornou None (mensagem ignorada)");
            return Ok(());
        };
        tracing::debug!(from = %from, participant = ?participant, author = %author, sender = %sender, "mensagem decodificada");

        // Descriptografa cada <enc>.
        let mut info = full_message;
        let mut decrypted_any = false;
        let mut decryptables = 0usize;
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        if let Some(BinaryContent::Children(children)) = &node.content {
            for child in children {
                let content_bytes = match &child.content {
                    Some(BinaryContent::Bytes(b)) => b.clone(),
                    _ => continue,
                };
                let e2e_type = match child.tag.as_str() {
                    "plaintext" => "plaintext".to_string(),
                    "enc" => child.attr("type").unwrap_or("msg").to_string(),
                    _ => {
                        tracing::debug!(tag = %child.tag, "filho ignorado no handle_message");
                        continue;
                    }
                };
                decryptables += 1;
                tracing::debug!(tag = %child.tag, e2e_type = %e2e_type, "descriptografando filho");

                let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);
                let decrypted = match e2e_type.as_str() {
                    "skmsg" => repo.decrypt_group_message(&sender, &author, &content_bytes),
                    "pkmsg" | "msg" => {
                        let user = if is_jid_user(&sender) { &sender } else { &author };
                        repo.decrypt_message(user, &e2e_type, &content_bytes)
                    }
                    "plaintext" => Ok(content_bytes.clone()),
                    _ => continue,
                };

                match decrypted {
                    Ok(buf) => {
                        decrypted_any = true;
                        let unpadded = baileys_core::ids::unpad_random_max16(&buf).unwrap_or(buf);
                        match wa::Message::decode(unpadded.as_slice()) {
                            Ok(decoded) => {
                                let inner = decoded.device_sent_message.as_ref().and_then(|d| d.message.clone().map(|m| *m));
                                let msg = inner.unwrap_or(decoded);
                                // Diagnóstico: só loga quando a mensagem decriptou VAZIA
                                // (nenhum campo reconhecido) — é o caso que vira [unknown].
                                let has_content = msg.conversation.is_some()
                                    || msg.extended_text_message.is_some()
                                    || msg.image_message.is_some()
                                    || msg.video_message.is_some()
                                    || msg.audio_message.is_some()
                                    || msg.document_message.is_some()
                                    || msg.sticker_message.is_some()
                                    || msg.protocol_message.is_some();
                                if !has_content {
                                    tracing::debug!(
                                        e2e_type = %e2e_type,
                                        conversation = msg.conversation.is_some(),
                                        extended_text = msg.extended_text_message.is_some(),
                                        image = msg.image_message.is_some(),
                                        video = msg.video_message.is_some(),
                                        audio = msg.audio_message.is_some(),
                                        document = msg.document_message.is_some(),
                                        sticker = msg.sticker_message.is_some(),
                                        protocol = msg.protocol_message.is_some(),
                                        "Message decodificada VAZIA (vira [unknown] no manager)"
                                    );
                                }
                                info.message = Some(msg.clone());

                                // Sender key distribution.
                                if let Some(skdm) = &msg.sender_key_distribution_message {
                                    if let Some(axolotl) = &skdm.axolotl_sender_key_distribution_message {
                                        if let Some(group_id) = &skdm.group_id {
                                            let _ = repo.process_sender_key_distribution_message(
                                                group_id,
                                                &author,
                                                axolotl,
                                            );
                                        }
                                    }
                                }

                                // Reação (messages.reaction).
                                if let Some(reaction) = &msg.reaction_message {
                                    let key = reaction.key.clone();
                                    let remote_jid = key
                                        .as_ref()
                                        .and_then(|k| k.remote_jid.clone())
                                        .unwrap_or_else(|| from.clone());
                                    let id = key
                                        .as_ref()
                                        .and_then(|k| k.id.clone())
                                        .unwrap_or_default();
                                    let _ = self.events.send(ClientEvent::MessagesReaction {
                                        reactions: vec![MessageReaction {
                                            remote_jid,
                                            id,
                                            from_me: key
                                                .as_ref()
                                                .and_then(|k| k.from_me)
                                                .unwrap_or(false),
                                            text: reaction.text.clone(),
                                            sender_timestamp_ms: reaction.sender_timestamp_ms,
                                        }],
                                    });
                                }

                                // ProtocolMessage: revoke/edit/history-sync.
                                if let Some(protocol) = &msg.protocol_message {
                                    self.handle_protocol_message(&protocol, &msg, &from, &participant)
                                        .await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "falha ao decodificar Message");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, e2e_type = %e2e_type, "falha ao descriptografar");
                        info.message_stub_type = Some(wa::web_message_info::StubType::Ciphertext as i32);
                        info.message_stub_parameters = vec![e.to_string()];
                    }
                }
            }
        }

        if !decrypted_any {
            let msg_id = info.key.as_ref().and_then(|k| k.id.clone()).unwrap_or_default();

            // Regra do Hineken (`decode-wa-message.ts` + `messages-recv.ts`):
            // - Sem nenhum ciphertext no nó ("Message absent from node"):
            //   PDO placeholder resend (receipt retry faria o outro reenviar à toa).
            // - Com ciphertext mas descriptografia falhou (bad MAC, sender key
            //   ausente, etc.): receipt retry com keys.
            if decryptables == 0 {
                info.message_stub_type = Some(wa::web_message_info::StubType::Ciphertext as i32);
                info.message_stub_parameters = vec!["Message absent from node".to_string()];

                // Fanout de bot/hosted/view-once: não pede resend (port do
                // `shouldSkipPlaceholderResend` do Hineken).
                let unavailable_type = node
                    .child("unavailable")
                    .and_then(|u| u.attr("type").map(String::from));
                let skip = matches!(
                    unavailable_type.as_deref(),
                    Some("bot_unavailable_fanout")
                        | Some("hosted_unavailable_fanout")
                        | Some("view_once_unavailable_fanout")
                );
                if skip {
                    tracing::debug!(msg_id = %msg_id, unavailable_type = ?unavailable_type, "mensagem sem ciphertext — fanout excluído, sem resend");
                } else {
                    // PDO placeholder resend (paridade Hineken): pede a
                    // re-entrega ao celular (device 0). Roda em task separada
                    // porque `request_placeholder_resend` faz `assert_sessions`
                    // → `query_node` (aguarda resposta do servidor).
                    tracing::info!(from = %from, msg_id = %msg_id, "mensagem sem ciphertext — pedindo PDO placeholder resend");
                    let msg_key = info.key.clone();
                    let client = self.clone();
                    let sink = sink.clone();
                    tokio::spawn(async move {
                        if let Some(key) = msg_key {
                            if let Err(e) = client.request_placeholder_resend(key, &sink).await {
                                tracing::warn!(error = %e, msg_id, "falha ao pedir placeholder resend");
                            }
                        }
                    });
                    // Registra a falha no manager (para o retry manual e o
                    // marcador de "recuperada" na re-entrega).
                    let _ = self.events.send(ClientEvent::MessageFailed {
                        info: info.clone(),
                        raw: node.clone(),
                        reason: "Message absent from node".to_string(),
                    });
                }
            } else {
                // Ciphertext falhou — mantém o erro real nos stub_parameters
                // (já setado no branch Err acima).
                let reason = info.message_stub_parameters.join(", ");
                tracing::info!(from = %from, msg_id = %msg_id, reason = %reason, "mensagem indecifrável — enviando receipt de retry automático");

                // Paridade Hineken: o ack já foi enviado no início do
                // `handle_message`; agora dispara o `<receipt type="retry">`.
                // Roda em task separada porque `send_retry_request` agora faz
                // `assert_sessions` → `query_node` (aguarda resposta do
                // servidor). Inline no loop de leitura = deadlock → `query
                // timed out` (mesmo bug do handle_success/receipt).
                let client = self.clone();
                let node = node.clone();
                let sink = sink.clone();
                let retry_node = node.clone();
                tokio::spawn(async move {
                    let _guard = client.retry_mutex.lock().await;
                    if let Err(e) = client.send_retry_request(&retry_node, &sink).await {
                        tracing::warn!(error = %e, msg_id, "falha ao enviar retry automático");
                    }
                });

                // Registra a falha no manager (para o retry manual e o
                // marcador de "recuperada" na re-entrega).
                let _ = self.events.send(ClientEvent::MessageFailed {
                    info: info.clone(),
                    raw: node.clone(),
                    reason,
                });
            }
        }

        // Receipt de entrega — o Hineken só envia no branch de sucesso
        // (descriptografou). No branch CIPHERTEXT ele manda só o ack + o
        // `<receipt type="retry">`. Enviar delivery receipt para o mesmo msg
        // id do retry (depois dele) contradiz o retry e atrapalha a
        // re-entrega — a ordem importa.
        let is_ciphertext = info.message_stub_type
            == Some(wa::web_message_info::StubType::Ciphertext as i32);
        if !is_ciphertext && !info.key.clone().unwrap_or_default().from_me.unwrap_or(false) {
            // Paridade Node: o receipt usa o `remoteJid` CRU (chatId antes do
            // `cleanMessage`); só o key do webhook é normalizado.
            let remote = sender.clone();
            let msg_id = info.key.clone().and_then(|k| k.id).unwrap_or_default();
            self.send_receipt(&remote, participant.as_deref(), &[msg_id], None, sink).await?;
        }

        let _ = self.events.send(ClientEvent::Message {
            info: info.clone(),
            raw: node.clone(),
            key_extras,
        });
        tracing::debug!(from = %from, msg_id = %info.key.clone().and_then(|k| k.id).unwrap_or_default(), "evento Message emitido");

        let _ = me_lid;
        Ok(())
    }

    /// Port de `decodeMessageNode` (parse do envelope, sem descriptografar).
    fn decode_message_node(
        &self,
        stanza: &BinaryNode,
    ) -> Option<(wa::WebMessageInfo, String, String, MessageKeyExtras)> {
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

        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_default();

        let from_me = {
            let candidate = participant.clone().unwrap_or_else(|| from.clone());
            are_jids_same_user(&candidate, &me_id) || (!me_lid.is_empty() && are_jids_same_user(&candidate, &me_lid))
        };

        let (chat_id, author): (String, String) = if is_jid_user(&from) || is_lid_user(&from) {
            let chat = if let Some(r) = recipient {
                r
            } else {
                from.clone()
            };
            let author = if from_me {
                let user = jid_user(&me_lid).unwrap_or_default();
                match jid_device(&from) {
                    Some(d) if d > 0 => format!("{user}:{d}@lid"),
                    _ => format!("{user}@lid"),
                }
            } else if let Some(sl) = &sender_lid {
                sl.clone()
            } else {
                from.clone()
            };
            (chat, author)
        } else if is_jid_group(&from) {
            let author = if from_me {
                let user = jid_user(&me_lid).unwrap_or_default();
                let dev = participant.as_deref().and_then(jid_device);
                match dev {
                    Some(d) if d > 0 => format!("{user}:{d}@lid"),
                    _ => format!("{user}@lid"),
                }
            } else if let Some(pl) = &participant_lid {
                pl.clone()
            } else {
                participant.clone().unwrap_or_default()
            };
            (from.clone(), author)
        } else {
            let author = participant_lid.clone().unwrap_or_else(|| participant.clone().unwrap_or_default());
            (from.clone(), author)
        };

        // Paridade `cleanMessage` (Hineken): o `key` é normalizado
        // (`jidNormalizedUser` em remoteJid e participant). `author`/`sender`
        // internos continuam com LID/device para a descriptografia.
        let normalized_remote = baileys_core::jid_normalized_user(&chat_id);
        let normalized_participant = participant
            .as_deref()
            .map(baileys_core::jid_normalized_user)
            .filter(|s| !s.is_empty());

        let key = wa::MessageKey {
            remote_jid: Some(normalized_remote),
            from_me: Some(from_me),
            id: Some(msg_id.clone()),
            participant: normalized_participant,
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

        let sender = chat_id.clone();
        Some((full, author, sender, key_extras))
    }

    /// Port de `processSyncAction`/`messaging-history.set` + `messages.update`
    /// a partir de um `ProtocolMessage` (revoke, message edit, history sync).
    async fn handle_protocol_message(
        &self,
        protocol: &wa::message::ProtocolMessage,
        _msg: &wa::Message,
        from: &str,
        participant: &Option<String>,
    ) {
        let r#type = protocol.r#type.unwrap_or(-1);
        let key = protocol.key.as_ref().cloned();

        // Revoke / MessageEdit → messages.update.
        if r#type == wa::message::protocol_message::Type::Revoke as i32
            || r#type == wa::message::protocol_message::Type::MessageEdit as i32
        {
            let is_revoke = r#type == wa::message::protocol_message::Type::Revoke as i32;
            let update = MessageStatusUpdate {
                key: MessageUpdateKey {
                    remote_jid: key
                        .as_ref()
                        .and_then(|k| k.remote_jid.clone())
                        .unwrap_or_else(|| from.to_string()),
                    id: key.as_ref().and_then(|k| k.id.clone()).unwrap_or_default(),
                    from_me: key.as_ref().and_then(|k| k.from_me).unwrap_or(false),
                    participant: key
                        .as_ref()
                        .and_then(|k| k.participant.clone())
                        .or_else(|| participant.clone()),
                },
                update: MessageUpdateData {
                    message_stub_type: if is_revoke {
                        Some(wa::web_message_info::StubType::Revoke as i32)
                    } else {
                        None
                    },
                    message: if is_revoke { Some(serde_json::Value::Null) } else { None },
                    ..Default::default()
                },
            };
            let _ = self.events.send(ClientEvent::MessagesUpdate {
                updates: vec![update],
            });
            return;
        }

        // History sync notification → parse do payload (inline ou download).
        if r#type == wa::message::protocol_message::Type::HistorySyncNotification as i32 {
            if let Some(notification) = &protocol.history_sync_notification {
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
        let mut data = baileys_crypto::aes_decrypt_cbc(body, cipher_key, iv).ok()?;

        // Remove padding PKCS7 (o Baileys usa `unpadRandomMax16` no path
        // inline; o download do history usa PKCS7 padrão do AES-CBC).
        if let Some(&pad) = data.last() {
            if (1..=16).contains(&pad) && data.len() >= pad as usize {
                data.truncate(data.len() - pad as usize);
            }
        }

        // Gzip?
        let decoded: Vec<u8> = if data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(data.as_slice());
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            out
        } else {
            data
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
        // Espelha `sendMessageAck` do Node: `type` só entra quando o nó tem
        // `type` E (não é `message` OU é `unavailable`). Para `unavailable`,
        // o `from` do ack vira o próprio `me.id`.
        let has_unavailable = node.child("unavailable").is_some();
        if let Some(r#type) = node.attr("type") {
            if node.tag != "message" || has_unavailable {
                ack = ack.with_attr("type", r#type);
            }
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
        if let Some(t) = r#type {
            node = node.with_attr("type", t);
        }
        if let Some(p) = participant {
            node = node.with_attr("participant", p);
        }
        node = node.with_attr("to", jid);

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

        // Decodifica o envelope para obter o msgKey (remoteJid).
        let remote_jid = self
            .decode_message_node(node)
            .map(|(full, _, _, _)| full.key.and_then(|k| k.remote_jid).unwrap_or_default())
            .unwrap_or_default();
        let cache_key = format!("{msg_id}:{remote_jid}");
        const MAX_MSG_RETRY_COUNT: u32 = 5;

        // Incrementa o contador de retries (thread-safe).
        let mut retry_count = self.msg_retry_cache.get(&cache_key).await.unwrap_or(0);
        if retry_count >= MAX_MSG_RETRY_COUNT {
            tracing::debug!(retry_count, msg_id, "retry atingiu o limite, ignorando");
            return Ok(());
        }
        retry_count += 1;
        self.msg_retry_cache.set(cache_key.clone(), retry_count).await;

        // Segunda tentativa (e além): o receipt com keys já foi; pede a mesma
        // mensagem ao celular via PDO e para.
        if retry_count > 1 {
            tracing::info!(msg_id, retry_count, "pedindo reenvio ao celular (PDO) após retry com keys");
            let msg_key = self
                .decode_message_node(node)
                .and_then(|(full, _, _, _)| full.key);
            if let Some(key) = msg_key {
                // Task separada: o PDO faz `assert_sessions` → `query_node`
                // (aguarda resposta do servidor). Inline no loop de leitura =
                // deadlock → `query timed out` (mesmo bug do retry/success).
                let client = self.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    if let Err(e) = client.request_placeholder_resend(key, &sink).await {
                        tracing::warn!(error = %e, msg_id, "falha ao pedir placeholder resend");
                    }
                });
            }
            return Ok(());
        }

        // Paridade Hineken (1ª tentativa): garante a sessão 1:1 com o
        // participante ANTES do receipt. A distribuição da sender key volta
        // como `pkmsg` 1:1; sem sessão, nem a distribuição descriptografa e a
        // `skmsg` continua falhando. `force` só na primeira vez por
        // dispositivo (force_session_cache) para não floodar `<iq encrypt>`.
        let retry_jid = node
            .attr("participant")
            .or_else(|| node.attr("from"))
            .unwrap_or_default()
            .to_string();
        let lid = if baileys_core::is_lid_user(&retry_jid) {
            Some(retry_jid.clone())
        } else {
            self.get_lid(&retry_jid, sink).await?
        };
        let force = {
            if self.force_session_cache.contains(&retry_jid).await {
                false
            } else {
                self.force_session_cache.set(retry_jid.clone(), ()).await;
                true
            }
        };
        if let Err(e) = self
            .assert_sessions(&[retry_jid.clone()], force, lid.as_deref(), sink)
            .await
        {
            tracing::warn!(jid = %retry_jid, error = %e, "assert_sessions no retry falhou (não fatal)");
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
        tracing::info!(msg_id, retry_count, "receipt de retry com keys enviado");
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
        tracing::info!(
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

        tracing::info!("STANZA_SEND\n{}", pretty_node(&stanza));
        self.send_node(&stanza, sink).await?;
        tracing::debug!(msg_id, jid, "peer data operation enviada");
        Ok(())
    }

    /// `handleReceipt` — responde ao `<receipt>` de entrada.
    ///
    /// Para `type="retry"`, reenvia a mensagem (port de `sendMessagesAgain` +
    /// `relayMessage` do Node): re-garante sessão com o participante (forçada)
    /// e re-cifra o conteúdo que estava no `send_cache`, respeitando grupo
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

        // Port de `handleReceipt` (Node): `isNodeFromMe`, `remoteJid`, `retryParticipantJid`.
        let p_or_from = participant.clone().unwrap_or_else(|| from.clone());
        let is_node_from_me = are_jids_same_user(&p_or_from, &me_id)
            || (!me_lid.is_empty() && are_jids_same_user(&p_or_from, &me_lid));
        let remote = if !is_node_from_me || baileys_core::is_jid_group(&from) {
            from.clone()
        } else {
            recipient.clone().unwrap_or_else(|| from.clone())
        };

        // `retryParticipantJid = attrs.participant || (attrs.from, se não for grupo)`.
        let retry_participant = participant.clone().unwrap_or_else(|| {
            if !baileys_core::is_jid_group(&from) {
                from.clone()
            } else {
                remote.clone()
            }
        });

        let (cached_jid, mut cached_bytes) = {
            let cache = self.send_cache.lock().await;
            cache
                .get(&msg_id)
                .cloned()
                .unwrap_or_else(|| (remote.clone(), Vec::new()))
        };
        let target_jid = if cached_jid.is_empty() { remote.clone() } else { cached_jid.clone() };

        // Se não está no cache em memória (ex: restart do processo), tenta
        // recuperar do store do app — port do `getMessage` do Hineken.
        if cached_bytes.is_empty() {
            let load = self.load_message_fn.lock().await.clone();
            if let Some(load) = load {
                match load(msg_id.clone(), target_jid.clone()).await {
                    Some(bytes) if !bytes.is_empty() => {
                        self.cache_send(msg_id.clone(), target_jid.clone(), bytes.clone()).await;
                        cached_bytes = bytes;
                        tracing::debug!(msg_id, target_jid, "mensagem recuperada do store para retry");
                    }
                    _ => {}
                }
            }
        }

        if cached_bytes.is_empty() {
            tracing::warn!(msg_id, target_jid, "retry solicitado mas mensagem não está no cache/store");
            return Ok(());
        }

        // Resolve o LID do destinatário para o endereçamento da sessão (Node
        // passa `lids` para `assertSessions` e `convertlidDevice`).
        let lid = if baileys_core::is_jid_group(&target_jid) {
            None
        } else {
            match self.get_lid(&target_jid, sink).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(error = %e, msg_id, target_jid, "retry: falha ao resolver LID");
                    return Ok(());
                }
            }
        };

        // Tenta extrair e injetar a sessão E2E do bundle `<keys>` do retry
        // (port de `extractE2ESessionFromRetryReceipt`).
        let mut injected_from_bundle = false;
        let child_tags: Vec<String> = match &node.content {
            Some(baileys_core::BinaryContent::Children(children)) => {
                children.iter().map(|c| c.tag.clone()).collect()
            }
            _ => Vec::new(),
        };
        tracing::debug!(msg_id, from = %from, ?child_tags, "retry receipt recebido");
        if let Some(keys) = node.child("keys") {
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
                let dest = convert_lid_device(&retry_participant, lid.as_deref(), &me_id, &me_lid);
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
                        tracing::debug!(retry_participant, dest, "sessão E2E injetada do bundle de retry");
                        injected_from_bundle = true;
                    }
                    Err(e) => tracing::warn!(retry_participant, error = %e, "falha ao injetar bundle de retry"),
                }
            } else {
                tracing::debug!(msg_id, has_keys = true, has_identity = identity.is_some(), "bundle de retry incompleto");
            }
        }

        // Sem bundle injetado → re-garante sessão com o participante.
        // `force` segue o `forceSession` do Node: forçado na primeira vez,
        // depois reusa.
        if !injected_from_bundle {
            let force = {
                if self.force_session_cache.contains(&retry_participant).await {
                    false
                } else {
                    self.force_session_cache.set(retry_participant.clone(), ()).await;
                    true
                }
            };
            self.assert_sessions(&[retry_participant.clone()], force, lid.as_deref(), sink).await?;
        }

        // Node `messages-recv.ts:898`: antes do reenvio em grupo, apaga a
        // `sender-key-memory` do grupo para forçar nova distribuição da
        // sender key (senão o peer reusa uma chave antiga e não decripta).
        if baileys_core::is_jid_group(&target_jid) {
            self.sender_key_memory.remove(&target_jid).await;
        }

        // Node `messages-recv.ts:940-946`: recupera a mensagem, apaga o
        // `messageContextInfo` (segredo de reporting) e delega para o
        // `relayMessage` com `{ messageId, isretry: true, participant }`.
        let mut msg = wa::Message::decode(cached_bytes.as_slice()).unwrap_or_default();
        msg.message_context_info = None;

        // `retryNode.attrs.count` (Node `messages-recv.ts:881`).
        let retry_count = node
            .child("retry")
            .and_then(|r| r.attr("count"))
            .and_then(|c| c.parse::<u32>().ok())
            .unwrap_or(1);

        let relay_participant = RelayParticipant {
            jid: retry_participant.clone(),
            count: retry_count.max(1),
        };

        let result = if baileys_core::is_jid_group(&target_jid) {
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
        _is_retry: bool,
    ) -> Result<SendMessageResult, ClientError> {
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
            // LID do participant (endereçamento da sessão).
            let lid = self.get_lid(&participant.jid, sink).await?;

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

            let count_str = participant.count.max(1).to_string();
            let mut enc_attrs: Vec<(&str, &str)> = vec![
                ("v", "2"),
                ("type", &enc.r#type),
                ("count", &count_str),
            ];
            for (k, v) in extra_attrs {
                enc_attrs.push((k, v));
            }
            let mut enc_node = BinaryNode::new("enc").with_bytes(enc.ciphertext);
            for (k, v) in enc_attrs {
                enc_node = enc_node.with_attr(k, v);
            }

            let mut children = vec![enc_node];
            if enc.r#type == "pkmsg" {
                if let Some(account) = self.store.creds().account {
                    if let Some(encoded) = crate::handshake::encode_signed_device_identity(&account, true) {
                        children.push(BinaryNode::new("device-identity").with_bytes(encoded));
                    }
                }
            }

            // Node linhas 857–865: `to = participant.jid`; se device nosso,
            // `recipient = destinationJid`. `device_fanout=false`.
            let mut stanza = BinaryNode::new("message")
                .with_attr("id", msg_id)
                .with_attr("to", &participant.jid)
                .with_attr("device_fanout", "false");
            if is_me {
                stanza = stanza.with_attr("recipient", baileys_core::jid_normalized_user(jid));
            }
            stanza = stanza.with_attr("type", msg_type);
            for &(k, v) in extra_attrs {
                stanza = stanza.with_attr(k, v);
            }
            let stanza = stanza.with_children(children);

            tracing::info!("STANZA_SEND\n{}", pretty_node(&stanza));
            self.send_node(&stanza, sink).await?;
            tracing::debug!(msg_id, jid, participant = %participant.jid, "mensagem 1:1 reenviada para participante (retry)");
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

        // Se nenhum device foi retornado (USync vazio/offline), cai no envio
        // direto para o JID normalizado — mantém o comportamento anterior.
        if all_jids.is_empty() {
            let normalized = baileys_core::jid_normalized_user(jid);
            other_jids.push(normalized.clone());
            all_jids.push(normalized);
        }

        // Garante sessões com todos os alvos.
        self.assert_sessions(&all_jids, false, lid.as_deref(), sink).await?;

        // Device 0 do remetente (phone): força o refresh da sessão E2E uma
        // única vez por conexão. Quando a sessão local dessincroniza, o phone
        // fica "aguardando mensagem" e nem sempre emite retry; buscar o bundle
        // fresco via `<iq encrypt>` recupera na hora (port do `forceSession`
        // usado no retry do Hineken).
        {
            let own_device0: Vec<String> = me_jids
                .iter()
                .filter(|j| {
                    let u = jid_user(j).unwrap_or_default();
                    let d = jid_device(j).unwrap_or(0);
                    (u == my_user || u == my_lid_user) && d == 0
                })
                .cloned()
                .collect();
            for dev0 in own_device0 {
                let already = {
                    if self.force_session_cache.contains(&dev0).await {
                        true
                    } else {
                        self.force_session_cache.set(dev0.clone(), ()).await;
                        false
                    }
                };
                if already {
                    continue;
                }
                match self.assert_sessions(&[dev0.clone()], true, lid.as_deref(), sink).await {
                    Ok(()) => tracing::debug!(jid = %dev0, "sessão do device 0 do remetente atualizada"),
                    Err(e) => tracing::warn!(jid = %dev0, error = %e, "refresh forçado da sessão do device 0 falhou (não fatal)"),
                }
            }
        }

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

        let lid_ref = lid.clone();
        for sender_id in &me_jids {
            let dest = convert_lid_device(sender_id, lid_ref.as_deref(), &me_id, &me_lid);
            let enc = repo.encrypt_message(&dest, &write_random_pad_max16(&me_msg.encode_to_vec()))?;
            if enc.r#type == "pkmsg" {
                should_include_device_identity = true;
            }
            tracing::debug!(sender_id = %sender_id, dest = %dest, enc_type = %enc.r#type, "encrypt me device");
            participants.push(BinaryNode::new("to").with_attr("jid", sender_id).with_children(vec![
                BinaryNode::new("enc")
                    .with_attr("v", "2")
                    .with_attr("type", &enc.r#type)
                    .with_bytes(enc.ciphertext),
            ]));
        }
        for sender_id in &other_jids {
            let dest = convert_lid_device(sender_id, lid_ref.as_deref(), &me_id, &me_lid);
            let enc = repo.encrypt_message(&dest, &write_random_pad_max16(&message.encode_to_vec()))?;
            if enc.r#type == "pkmsg" {
                should_include_device_identity = true;
            }
            tracing::debug!(sender_id = %sender_id, dest = %dest, enc_type = %enc.r#type, "encrypt other device");
            participants.push(BinaryNode::new("to").with_attr("jid", sender_id).with_children(vec![
                BinaryNode::new("enc")
                    .with_attr("v", "2")
                    .with_attr("type", &enc.r#type)
                    .with_bytes(enc.ciphertext),
            ]));
        }

        let mut children = vec![BinaryNode::new("participants").with_children(participants)];
        if should_include_device_identity {
            if let Some(account) = self.store.creds().account {
                if let Some(encoded) = crate::handshake::encode_signed_device_identity(&account, true) {
                    children.push(BinaryNode::new("device-identity").with_bytes(encoded));
                }
            }
        }

        // tctoken / cstoken (Node `messages-send.ts` linhas 881–947): em 1:1
        // (sem retry/status/newsletter), resolve o token de contato confiável
        // (`contacts-tc-token`) por LID e anexa ao stanza. Sem `tctoken`, o
        // WhatsApp pode não confirmar a entrega em alguns cenários 1:1.
        let tc_token_jid = lid.as_deref().unwrap_or(jid);
        let mut tc_token_buffer: Option<Vec<u8>> = None;
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
                }
            }
        }
        if tc_token_buffer.is_some() && tc_token_expired {
            tracing::debug!(jid, "tctoken expirado, limpando");
            tc_token_buffer = None;
            self.store.remove_generic("contacts-tc-token", tc_token_jid);
        }

        // `cstoken` quando não há `tctoken` e `nctSalt` existe.
        if tc_token_buffer.is_none() {
            let creds = self.store.creds();
            if let Some(salt) = creds.nct_salt.as_ref() {
                let salt_bytes = decode_buffer(salt);
                if !salt_bytes.is_empty() {
                    let recipient_lid = lid.as_deref().unwrap_or(jid);
                    let cs_token = compute_cs_token(&salt_bytes, recipient_lid);
                    children.push(BinaryNode::new("cstoken").with_bytes(cs_token));
                }
            }
        }

        // `tctoken` quando há token válido.
        if let Some(token) = tc_token_buffer {
            children.push(BinaryNode::new("tctoken").with_bytes(token));
        }

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

        tracing::info!("STANZA_SEND\n{}", pretty_node(&stanza));

        self.send_node(&stanza, sink).await?;

        // Cache para reenvio em retry.
        self.cache_send(msg_id.to_string(), jid.to_string(), message.encode_to_vec()).await;

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

        tracing::debug!(msg_id, jid, "mensagem enviada");
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
        let query = crate::groups::group_update_description_query(jid, description, None, None)
            .with_attr("id", self.next_tag());
        self.query_node(query, sink).await?;
        Ok(())
    }

    /// `groupParticipantsUpdate` — add/remove/promote/demote.
    pub async fn group_update_participants(
        &self,
        jid: &str,
        participants: &[String],
        action: &str,
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        let query = crate::groups::group_participants_update_query(jid, participants, action)
            .with_attr("id", self.next_tag());
        self.query_node(query, sink).await?;
        Ok(())
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
        _is_retry: bool,
    ) -> Result<SendMessageResult, ClientError> {
        let me_id = self.store.creds().me.clone().map(|m| m.id).unwrap_or_default();
        let me_lid = self
            .store
            .creds()
            .me
            .clone()
            .and_then(|m| m.lid)
            .unwrap_or_else(|| me_id.clone());

        let repo = SignalRepository::new(self.store.as_ref() as &dyn SignalStore);

        // Metadados do grupo (participantes) — o retry com participant NÃO faz
        // fanout, mas ainda precisa do `addressing_mode` (Node linha 545).
        let meta = self.group_metadata(jid, sink).await?;
        let addressing_mode = meta.addressing_mode.as_deref().unwrap_or("pn");

        // `isGroup && participant` (Node linhas 540–590): retry de grupo — a
        // mensagem volta como `senderKeyDistributionMessage` cifrada 1:1 para
        // SOMENTE o participante pedinte (não reenvia para todos).
        if let Some(participant) = participant {
            // Node: encryptGroupMessage({ group: destinationJid, data: bytes, meId: meLid }).
            let enc = repo.encrypt_group_message(
                jid,
                &me_lid,
                &write_random_pad_max16(&message.encode_to_vec()),
            )?;
            let message_to_send = {
                let mut patched = message.clone();
                patched.sender_key_distribution_message =
                    Some(wa::message::SenderKeyDistributionMessage {
                        axolotl_sender_key_distribution_message: Some(
                            enc.sender_key_distribution_message.clone(),
                        ),
                        group_id: Some(jid.to_string()),
                    });
                patched
            };
            let lid = self.get_lid(&participant.jid, sink).await?;
            let dest = convert_lid_device(&participant.jid, lid.as_deref(), &me_id, &me_lid);
            let enc_1to1 = repo.encrypt_message(
                &dest,
                &write_random_pad_max16(&message_to_send.encode_to_vec()),
            )?;

            let count_str = participant.count.max(1).to_string();
            let mut enc_attrs: Vec<(&str, &str)> = vec![
                ("v", "2"),
                ("type", &enc_1to1.r#type),
                ("count", &count_str),
            ];
            // `extraAttrs['mediatype']` do Node (`messages-send.ts` linhas 508–511).
            if let Some(mediatype) = get_media_type(&message) {
                enc_attrs.push(("mediatype", mediatype));
            }
            for (k, v) in extra_attrs {
                enc_attrs.push((k, v));
            }
            let mut enc_node = BinaryNode::new("enc").with_bytes(enc_1to1.ciphertext);
            for (k, v) in enc_attrs {
                enc_node = enc_node.with_attr(k, v);
            }

            let mut children = vec![enc_node];
            if enc_1to1.r#type == "pkmsg" {
                if let Some(account) = self.store.creds().account {
                    if let Some(encoded) = crate::handshake::encode_signed_device_identity(&account, true) {
                        children.push(BinaryNode::new("device-identity").with_bytes(encoded));
                    }
                }
            }

            // Node linha 854: `stanza.attrs.to = destinationJid` +
            // `stanza.attrs.participant = participant.jid`.
            let mut stanza = BinaryNode::new("message")
                .with_attr("id", msg_id)
                .with_attr("type", get_message_type(&message))
                .with_attr("to", jid)
                .with_attr("participant", &participant.jid)
                .with_attr("addressing_mode", addressing_mode);
            for &(k, v) in extra_attrs {
                stanza = stanza.with_attr(k, v);
            }
            let stanza = stanza.with_children(children);

            tracing::info!("STANZA_SEND\n{}", pretty_node(&stanza));
            self.send_node(&stanza, sink).await?;
            tracing::debug!(msg_id, jid, participant = %participant.jid, "mensagem de grupo reenviada para participante (retry)");
            return Ok(SendMessageResult { message_id: msg_id.to_string() });
        }

        // Node: encryptGroupMessage({ group: destinationJid, data: bytes, meId: meLid }).
        let enc = repo.encrypt_group_message(
            jid,
            &me_lid,
            &write_random_pad_max16(&message.encode_to_vec()),
        )?;

        // (`_is_retry` sem participant cai no fanout normal, como no Node quando
        // `sendToAll` é verdadeiro — o retry sem device do participante.)

        // Devices de todos os participantes (lid || id).
        let participant_jids: Vec<String> = meta
            .participants
            .iter()
            .map(|p| p.lid.clone().or_else(|| {
                if p.jid.is_empty() {
                    None
                } else {
                    Some(p.jid.clone())
                }
            }))
            .filter(|j| j.is_some())
            .map(|j| j.unwrap())
            .collect();

        let mut devices = self.get_usync_devices(&participant_jids, sink, true).await?;

        // Garante nosso device 0 (primary) no fanout, como o Node faz:
        // apenas via LID (`{user: jlidUser, device: 0, jid: jidNormalizedUser(meLid)}`).
        // O push por PN (`@s.whatsapp.net`) fazia o Android de terceiros exibir o
        // JID bruto `número:device` em vez de resolver a sender key do autor.
        let me_lid_user = jid_user(&me_lid).unwrap_or_default();
        let me_id_user = jid_user(&me_id).unwrap_or_default();
        let has_me_phone = devices
            .iter()
            .any(|(u, d, _)| u == &me_lid_user && *d == 0);
        if !has_me_phone {
            // Phone via LID: quando `me.lid` está vazio (`me_lid` caiu para PN),
            // forçamos `{user}@lid` em vez de cair em `@s.whatsapp.net`.
            let phone_lid_jid = if baileys_core::is_lid_user(&me_lid) {
                baileys_core::jid_normalized_user(&me_lid)
            } else {
                format!("{me_lid_user}@lid")
            };
            devices.push((me_lid_user.clone(), 0, phone_lid_jid));
        }
        tracing::debug!(?devices, "fanout grupo após correção de device 0");

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
        tracing::debug!(?sender_key_jids, "fanout grupo: sender_key_jids");
        tracing::info!(
            participants = sender_key_jids.len(),
            group = jid,
            msg_id,
            "envio em grupo: fanout preparado"
        );

        let mut participants: Vec<BinaryNode> = Vec::new();
        let mut should_include_device_identity = false;

        if !sender_key_jids.is_empty() {
            self.assert_sessions(&sender_key_jids, false, None, sink).await?;

            // Device 0 do remetente (phone): força o refresh da sessão E2E
            // uma única vez por conexão (mesma lógica do 1:1).
            {
                let own_device0: Vec<String> = sender_key_jids
                    .iter()
                    .filter(|j| {
                        let u = jid_user(j).unwrap_or_default();
                        let d = jid_device(j).unwrap_or(0);
                        (u == me_lid_user || u == me_id_user) && d == 0
                    })
                    .cloned()
                    .collect();
                for dev0 in own_device0 {
                    let already = {
                        if self.force_session_cache.contains(&dev0).await {
                            true
                        } else {
                            self.force_session_cache.set(dev0.clone(), ()).await;
                            false
                        }
                    };
                    if already {
                        continue;
                    }
                    match self.assert_sessions(&[dev0.clone()], true, None, sink).await {
                        Ok(()) => tracing::debug!(jid = %dev0, "sessão do device 0 do remetente atualizada (grupo)"),
                        Err(e) => tracing::warn!(jid = %dev0, error = %e, "refresh forçado da sessão do device 0 falhou (grupo, não fatal)"),
                    }
                }
            }

            let sk_msg_bytes = sender_key_msg.encode_to_vec();
            for sender_id in &sender_key_jids {
                let dest = convert_lid_device(sender_id, None, &me_id, &me_lid);
                let sk_enc = repo
                    .encrypt_message(&dest, &write_random_pad_max16(&sk_msg_bytes))?;
                if sk_enc.r#type == "pkmsg" {
                    should_include_device_identity = true;
                }
                participants.push(BinaryNode::new("to").with_attr("jid", sender_id).with_children(vec![
                    BinaryNode::new("enc")
                        .with_attr("v", "2")
                        .with_attr("type", &sk_enc.r#type)
                        .with_bytes(sk_enc.ciphertext),
                ]));
            }
        }

        let mut children = Vec::new();
        // Node `messages-send.ts` linha 739: o `enc` (skmsg) vem ANTES de
        // `participants` e de `device-identity` no content do stanza.
        // `extraAttrs` do Node: `mediatype` no `enc` skmsg para mensagens de mídia.
        let mut skmsg_enc = BinaryNode::new("enc")
            .with_attr("v", "2")
            .with_attr("type", "skmsg");
        if let Some(mediatype) = get_media_type(&message) {
            skmsg_enc = skmsg_enc.with_attr("mediatype", mediatype);
        }
        children.push(skmsg_enc.with_bytes(enc.ciphertext));
        if !participants.is_empty() {
            children.push(BinaryNode::new("participants").with_children(participants));
        }
        if should_include_device_identity {
            if let Some(account) = self.store.creds().account {
                if let Some(encoded) = crate::handshake::encode_signed_device_identity(&account, true) {
                    children.push(BinaryNode::new("device-identity").with_bytes(encoded));
                }
            }
        }

        let mut stanza = BinaryNode::new("message")
            .with_attr("id", msg_id)
            .with_attr("type", get_message_type(&message))
            .with_attr("to", jid)
            .with_attr("addressing_mode", addressing_mode);
        for &(k, v) in extra_attrs {
            stanza = stanza.with_attr(k, v);
        }
        let stanza = stanza.with_children(children);

        tracing::debug!(
            msg_id,
            group = jid,
            stanza_type = %stanza.attr("type").unwrap_or_default(),
            to = %stanza.attr("to").unwrap_or_default(),
            addressing_mode = %stanza.attr("addressing_mode").unwrap_or_default(),
            participants = sender_key_jids.len(),
            ?sender_key_jids,
            "stanza de grupo preparado"
        );

        tracing::info!("STANZA_SEND\n{}", pretty_node(&stanza));

        self.send_node(&stanza, sink).await?;

        // Cache para reenvio em retry.
        self.cache_send(msg_id.to_string(), jid.to_string(), message.encode_to_vec()).await;

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

        tracing::debug!(msg_id, jid, "mensagem de grupo enviada");
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
                    let key = (user.clone(), device, r.id.clone());
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
            "available" | "unavailable" => BinaryNode::new("presence")
                .with_attr("name", me_id.replace('@', ""))
                .with_attr("type", presence_type),
            _ => {
                let to = to_jid.unwrap_or_default();
                let from = if baileys_core::is_lid_user(&to) { me_lid } else { me_id };
                BinaryNode::new("chatstate")
                    .with_attr("from", from)
                    .with_attr("to", to)
                    .with_children(vec![BinaryNode::new(presence_type)])
            }
        };
        self.send_node(&node, sink).await
    }

    /// `readMessages` — envia receipts de leitura (read/read-self).
    pub async fn read_messages(
        &self,
        keys: &[wa::MessageKey],
        sink: &WsSink,
    ) -> Result<(), ClientError> {
        if keys.is_empty() {
            return Ok(());
        }
        let remote = keys[0].remote_jid.clone().unwrap_or_default();
        let participant = keys[0].participant.clone();
        let ids: Vec<String> = keys.iter().filter_map(|k| k.id.clone()).collect();
        self.send_receipt(&remote, participant.as_deref(), &ids, Some("read"), sink)
            .await
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

fn is_jid_user(jid: &str) -> bool {
    baileys_core::is_jid_user(jid)
}

fn is_lid_user(jid: &str) -> bool {
    baileys_core::is_lid_user(jid)
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

/// Pretty-print de um `BinaryNode` no shape do `console.dir(stanza, { depth: null })`
/// do Node/Hineken: `{ tag, attrs: {objeto}, content }`, com bytes em hex
/// (`<0a 12 ...>`), multilinha e indentação de 2 espaços. Usado nos logs
/// `STANZA_SEND` para diff linha a linha com o TS.
fn pretty_node(node: &baileys_core::BinaryNode) -> String {
    serde_json::to_string_pretty(&pretty_node_value(node)).unwrap_or_default()
}

fn pretty_node_value(node: &baileys_core::BinaryNode) -> serde_json::Value {
    // `attrs` vira objeto (como no Node), não `[["k","v"], ...]`. Chave
    // duplicada → a última vence (mesmo efeito de sobrescrever no objeto JS).
    let mut attrs = serde_json::Map::new();
    for (k, v) in &node.attrs {
        attrs.insert(k.clone(), serde_json::Value::String(v.clone()));
    }

    let content = match &node.content {
        Some(baileys_core::BinaryContent::Children(children)) => {
            serde_json::Value::Array(children.iter().map(pretty_node_value).collect())
        }
        Some(baileys_core::BinaryContent::String(s)) => serde_json::Value::String(s.clone()),
        Some(baileys_core::BinaryContent::Bytes(b)) => {
            // Espelha o `<Buffer 0a 12 34 ...>` do Node, truncando como o
            // `inspect` faz para buffers grandes (legível para o diff).
            let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
            let shown = if hex.len() > 128 {
                let mut v = hex[..128].to_vec();
                v.push("...".to_string());
                v
            } else {
                hex
            };
            serde_json::Value::String(format!("<{}>", shown.join(" ")))
        }
        None => serde_json::Value::Null,
    };

    serde_json::json!({
        "tag": node.tag,
        "attrs": serde_json::Value::Object(attrs),
        "content": content,
    })
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
