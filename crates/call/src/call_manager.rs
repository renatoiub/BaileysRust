//! `NativeCallManager` — orquestração da chamada (port de
//! `services/call/call-manager.ts` + o roteamento de `player-bridge.ts`).
//!
//! Signaling via [`CallSocket`] (o container implementa em cima do `Client`),
//! mídia por relays WebRTC ([`SctpRelayManager`]): MLow 960 amostras → RTP
//! PT 120 com extensão 0xDEBE → SRTP por JID → DataChannel. A recepção decodifica
//! num processo filho ([`MlowIsolatedDecoder`]) e emite [`CallEvent::Audio`].
//!
//! Estado em `std::sync::Mutex` (nunca mantido através de `.await`).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use baileys_core::{BinaryContent, BinaryNode};
use baileys_proto::proto as wa;
use bytes::Bytes;
use tokio::task::JoinHandle;

use crate::audio::AudioEngine;
use crate::encryption::{derive_per_jid_srtp_key, generate_call_key, generate_secure_ssrc};
use crate::mlow::{MlowCodec, MlowOptions};
use crate::mlow_isolated::MlowIsolatedDecoder;
use crate::rtp::RtpSession;
use crate::sctp_relay::{RelayEvent, RelayInfo, SctpRelayManager};
use crate::signaling::{
    build_accept_receipt_stanza, build_accept_stanza, build_accepted_elsewhere_stanza,
    build_mute_v2_stanza, build_offer_stanza, build_post_accept_transport_stanza,
    build_preaccept_stanza, build_reject_stanza, build_terminate_to_device_stanza,
    build_transport_stanza, decrypt_call_key_in_node, encode_call_message, ensure_device_jid,
    extract_node_info, extract_relay_endpoints, generate_call_id, jid_base, needs_decryption,
    parse_relay_from_ack,
};
use crate::srtp::SrtpSession;
use crate::state::{CallInfo, CallTransition};
use crate::stun::{is_rtp_packet, is_stun_packet};
use crate::types::{
    CallMediaType, CallOfferOptions, CallState, EndCallReason, RelayData, RelayEndpoint,
    SRTP_RECV_AUTH_TAG_LEN, SRTP_SEND_AUTH_TAG_LEN,
};

/// Future boxeado devolvido pelo [`CallSocket`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Socket WhatsApp visto pelo CallManager (o container implementa sobre o
/// `baileys_socket::Client`).
pub trait CallSocket: Send + Sync {
    /// `creds.me.id`.
    fn me_id(&self) -> String;
    /// `creds.me.lid`.
    fn me_lid(&self) -> Option<String>;
    /// `encodeSignedDeviceIdentity(creds.account, true)`.
    fn device_identity(&self) -> Option<Vec<u8>>;
    /// `sendNode` — aguarda a escrita (ordem preservada).
    fn send_node(&self, node: BinaryNode) -> BoxFuture<'_, Result<(), String>>;
    /// `getLid(jid)`.
    fn get_lid(&self, jid: String) -> BoxFuture<'_, Option<String>>;
    /// `getUSyncDevices([jid], true, false)` → `(user, device)`.
    fn get_usync_devices(&self, jid: String) -> BoxFuture<'_, Result<Vec<(String, u32)>, String>>;
    /// `assertSessions(jids, force)`.
    fn assert_sessions(&self, jids: Vec<String>, force: bool) -> BoxFuture<'_, Result<(), String>>;
    /// `createParticipantNodes(jids, message, extraAttrs, lid)` →
    /// `(nodes, shouldIncludeDeviceIdentity)`.
    fn create_participant_nodes(
        &self,
        jids: &[String],
        message: &wa::Message,
        extra_attrs: &[(&str, &str)],
        lid: Option<&str>,
    ) -> Result<(Vec<BinaryNode>, bool), String>;
    /// `signalRepository.encryptMessage` → `(type, ciphertext)`.
    fn encrypt_message(&self, jid: &str, data: &[u8]) -> Result<(String, Vec<u8>), String>;
    /// `signalRepository.decryptMessage` (plaintext com padding).
    fn decrypt_message(&self, jid: &str, enc_type: &str, ciphertext: &[u8])
        -> Result<Vec<u8>, String>;
    /// `contacts-tc-token[jid].token`.
    fn tc_token(&self, jid: &str) -> Option<Vec<u8>>;
}

/// Erros do call manager.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("A call is already in progress")]
    CallInProgress,
    #[error("No call with id {0}")]
    NoSuchCall(String),
    #[error("Call {0} cannot be accepted in state {1}")]
    CannotAccept(String, String),
    #[error("socket: {0}")]
    Socket(String),
    #[error("MLow indisponível: {0}")]
    Codec(#[from] crate::mlow::MlowError),
    #[error("state: {0}")]
    State(#[from] crate::state::InvalidTransition),
    #[error("Sem call_key na oferta — impossível aceitar (decrypt falhou?)")]
    NoCallKey,
}

/// Eventos do CallManager (`call:state`, `call:incoming`, `call:accepted`,
/// `call:ended`, `call:audio`, `call:error`).
#[derive(Debug, Clone)]
pub enum CallEvent {
    State(CallInfo),
    Incoming(CallInfo),
    Accepted(CallInfo),
    Ended(CallInfo),
    Audio { call_id: String, pcm: Vec<f32> },
    Error { call_id: Option<String>, message: String },
}

// ---------------------------------------------------------------------------
// callIds encerrados / terminate já notificado (webhook e dispatch ignoram ecos)
// ---------------------------------------------------------------------------

const ENDED_CALL_TTL: Duration = Duration::from_secs(120);

fn registry(cell: &'static OnceLock<Mutex<HashMap<String, Instant>>>) -> MutexGuard<'static, HashMap<String, Instant>> {
    cell.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn registry_note(cell: &'static OnceLock<Mutex<HashMap<String, Instant>>>, call_id: &str) {
    if call_id.is_empty() {
        return;
    }
    let mut map = registry(cell);
    map.insert(call_id.to_string(), Instant::now());
    if map.len() > 200 {
        map.retain(|_, t| t.elapsed() <= ENDED_CALL_TTL);
    }
}

fn registry_has(cell: &'static OnceLock<Mutex<HashMap<String, Instant>>>, call_id: &str) -> bool {
    if call_id.is_empty() {
        return false;
    }
    let mut map = registry(cell);
    match map.get(call_id) {
        Some(t) if t.elapsed() <= ENDED_CALL_TTL => true,
        Some(_) => {
            map.remove(call_id);
            false
        }
        None => false,
    }
}

static ENDED_CALLS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
static TERMINATE_WEBHOOK_SENT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

/// `markCallEnded`.
pub fn mark_call_ended(call_id: &str) {
    registry_note(&ENDED_CALLS, call_id);
}

/// `isCallRecentlyEnded`.
pub fn is_call_recently_ended(call_id: &str) -> bool {
    registry_has(&ENDED_CALLS, call_id)
}

/// `noteTerminateWebhookSent`.
pub fn note_terminate_webhook_sent(call_id: &str) {
    registry_note(&TERMINATE_WEBHOOK_SENT, call_id);
}

/// `wasTerminateWebhookSent`.
pub fn was_terminate_webhook_sent(call_id: &str) -> bool {
    registry_has(&TERMINATE_WEBHOOK_SENT, call_id)
}

// ---------------------------------------------------------------------------
// helpers de JID
// ---------------------------------------------------------------------------

/// `/:\d+@/` — JID com device explícito.
fn has_device(jid: &str) -> bool {
    let Some(at) = jid.find('@') else {
        return false;
    };
    match jid[..at].rsplit_once(':') {
        Some((_, d)) => !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

fn device_num(jid: &str) -> u32 {
    let Some(at) = jid.find('@') else {
        return 0;
    };
    jid[..at]
        .rsplit_once(':')
        .and_then(|(_, d)| d.parse().ok())
        .unwrap_or(0)
}

fn usync_device_jid(user: &str, device: u32, server: &str) -> String {
    if device != 0 {
        format!("{user}:{device}@{server}")
    } else {
        format!("{user}@{server}")
    }
}

fn server_of(bare: &str) -> &str {
    if bare.contains("@lid") {
        "lid"
    } else {
        bare.split_once('@').map(|(_, s)| s).filter(|s| !s.is_empty()).unwrap_or("s.whatsapp.net")
    }
}

fn has_video_node(node: &BinaryNode) -> bool {
    matches!(&node.content, Some(BinaryContent::Children(c)) if c.iter().any(|n| n.tag == "video"))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// estado
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    audio_send: u64,
    audio_drop: u64,
    audio_recv: u64,
    recv_real: u64,
    recv_dtx: u64,
    srtp_errors: u64,
    relay_packets: u64,
    stun_responses: u64,
    self_echo: u64,
    recv_seq_gaps: u64,
    recv_dup_drops: u64,
}

#[derive(Default)]
struct Inner {
    call: Option<CallInfo>,
    initial_transport_sent: bool,
    outgoing_preaccept_sent: bool,
    self_ssrc: u32,
    peer_ssrcs: Vec<u32>,
    peer_ssrc_to_device: HashMap<u32, String>,
    accepted_by_jid: Option<String>,
    accept_in_progress: bool,
    media_active: bool,
    media_inactive_drop_logged: bool,
    actual_peer_ssrc: Option<u32>,
    ssrc_resubscribed: bool,
    pinned_rtp_relay: Option<String>,
    last_recv_seq: Option<u16>,
    stats: Stats,
}

#[derive(Default)]
struct Media {
    rtp: Option<RtpSession>,
    srtp: Option<SrtpSession>,
    encoder: Option<MlowCodec>,
    encode_buf: Vec<f32>,
    first_packet_sent: bool,
    real_audio_send_count: u64,
}

struct CaptureLoop {
    handle: JoinHandle<()>,
    silence: bool,
}

enum DispatchJob {
    Node(BinaryNode),
    EventAccept { call_id: String, from: String },
}

/// Gerenciador nativo de chamada (uma chamada por vez, como cada manager do Node).
pub struct NativeCallManager {
    socket: Arc<dyn CallSocket>,
    debug: bool,
    me: Weak<NativeCallManager>,
    inner: Mutex<Inner>,
    media: Mutex<Media>,
    decoder: tokio::sync::Mutex<Option<MlowIsolatedDecoder>>,
    sctp: SctpRelayManager,
    audio_engine: Arc<AudioEngine>,
    capture: Mutex<Option<CaptureLoop>>,
    events: tokio::sync::broadcast::Sender<CallEvent>,
    dispatch_tx: tokio::sync::mpsc::UnboundedSender<DispatchJob>,
}

const MLOW_FRAME_SAMPLES: usize = 960;
const WA_RELAY_PORT: u16 = 3478;
const MAX_RELAYS: usize = 2;

impl NativeCallManager {
    pub fn new(socket: Arc<dyn CallSocket>, debug: bool) -> Arc<Self> {
        let (events, _) = tokio::sync::broadcast::channel(1024);
        let (sctp, mut relay_rx) = SctpRelayManager::new();
        let (dispatch_tx, mut dispatch_rx) = tokio::sync::mpsc::unbounded_channel();
        let manager = Arc::new_cyclic(|me| Self {
            socket,
            debug,
            me: me.clone(),
            inner: Mutex::new(Inner::default()),
            media: Mutex::new(Media::default()),
            decoder: tokio::sync::Mutex::new(None),
            sctp,
            audio_engine: Arc::new(AudioEngine::new(Default::default())),
            capture: Mutex::new(None),
            events,
            dispatch_tx,
        });

        let weak = Arc::downgrade(&manager);
        tokio::spawn(async move {
            while let Some(job) = dispatch_rx.recv().await {
                let Some(m) = weak.upgrade() else {
                    break;
                };
                match job {
                    DispatchJob::Node(node) => {
                        if let Err(e) = m.dispatch_call_node(&node).await {
                            tracing::warn!("[CallManager] dispatch de nó de chamada falhou: {e}");
                        }
                    }
                    DispatchJob::EventAccept { call_id, from } => {
                        m.handle_call_event_accept(&call_id, &from).await;
                    }
                }
            }
        });

        let weak = Arc::downgrade(&manager);
        tokio::spawn(async move {
            while let Some(ev) = relay_rx.recv().await {
                let Some(m) = weak.upgrade() else {
                    break;
                };
                match ev {
                    RelayEvent::Connected { ip, port } => {
                        tracing::info!("[SCTP] DataChannel connected: {ip}:{port}");
                        m.on_relay_connected();
                    }
                    RelayEvent::Receive { ip, port, data } => {
                        m.on_relay_data(data, Some(&ip), Some(port)).await;
                    }
                }
            }
        });
        manager
    }

    fn st(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    fn md(&self) -> MutexGuard<'_, Media> {
        lock(&self.media)
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CallEvent> {
        self.events.subscribe()
    }

    pub fn audio_engine(&self) -> &Arc<AudioEngine> {
        &self.audio_engine
    }

    /// `getCurrentCall`.
    pub fn current_call(&self) -> Option<CallInfo> {
        self.st().call.clone()
    }

    fn emit(&self, ev: CallEvent) {
        let _ = self.events.send(ev);
    }

    fn emit_state(&self) {
        if let Some(call) = self.current_call() {
            self.emit(CallEvent::State(call));
        }
    }

    fn me_jids(&self) -> (String, Option<String>) {
        let me_id = self.socket.me_id();
        let me_lid = self.socket.me_lid().filter(|l| !l.is_empty());
        (me_id, me_lid)
    }

    fn our_bases(&self) -> HashSet<String> {
        let (me_id, me_lid) = self.me_jids();
        let mut bases = HashSet::new();
        if let Some(l) = &me_lid {
            bases.insert(jid_base(l));
        }
        if !me_id.is_empty() {
            bases.insert(jid_base(&me_id));
        }
        bases
    }

    async fn send(&self, node: BinaryNode) -> Result<(), String> {
        self.socket.send_node(node).await
    }

    // -----------------------------------------------------------------------
    // API pública (player)
    // -----------------------------------------------------------------------

    /// `startCall`.
    pub async fn start_call(&self, options: CallOfferOptions) -> Result<String, CallError> {
        if let Some(c) = self.current_call() {
            if !c.is_ended() {
                return Err(CallError::CallInProgress);
            }
        }

        let encoder = MlowCodec::new(MlowOptions::default())?;

        let call_id = generate_call_id();
        let media_type = if options.is_video {
            CallMediaType::Video
        } else {
            CallMediaType::Audio
        };
        let (me_id, me_lid) = self.me_jids();
        let call_creator = ensure_device_jid(me_lid.as_deref().unwrap_or(&me_id));
        let peer_jid = self.resolve_peer_lid(&options.peer_jid).await;

        let mut call = CallInfo::new_outgoing(
            call_id.clone(),
            peer_jid.clone(),
            call_creator.clone(),
            media_type,
        );
        let call_key = generate_call_key();
        call.encryption_key = Some(call_key.clone());

        let ssrc = generate_secure_ssrc(&call_id, &call_creator, 0);
        let peer_ssrc = generate_secure_ssrc(&call_id, &ensure_device_jid(&peer_jid), 0);
        {
            let mut st = self.st();
            st.call = Some(call);
            st.initial_transport_sent = false;
            st.outgoing_preaccept_sent = false;
            st.self_ssrc = ssrc;
            st.peer_ssrcs = vec![peer_ssrc];
        }
        {
            let mut md = self.md();
            md.rtp = Some(RtpSession::whatsapp_opus(ssrc));
            md.encoder = Some(encoder);
            md.srtp = None;
        }
        *self.decoder.lock().await = Some(MlowIsolatedDecoder::new());

        tracing::info!(
            "[CallManager] created call {call_id} creator={call_creator} peer={peer_jid} ssrc=0x{ssrc:08X} peerSsrc=0x{peer_ssrc:08X}"
        );

        let sent = async {
            let offer = self
                .build_offer(&call_id, &call_key, &peer_jid, options.is_video, &call_creator, &options.peer_devices)
                .await?;
            self.send(offer).await
        }
        .await;
        if let Err(e) = sent {
            tracing::error!("[CallManager] offer falhou: {e}");
            self.finish_call_local();
            return Err(CallError::Socket(e));
        }

        {
            let mut st = self.st();
            if let Some(c) = st.call.as_mut().filter(|c| c.call_id == call_id) {
                c.apply_transition(CallTransition::OfferSent)?;
            }
        }
        self.emit_state();
        tracing::info!("[CallManager] offer sent, state → Ringing");
        Ok(call_id)
    }

    /// `acceptCall`.
    pub async fn accept_call(&self, call_id: &str) -> Result<(), CallError> {
        let (call_key, peer_jid, call_creator, is_video, endpoints) = {
            let mut st = self.st();
            let call = match st.call.as_mut() {
                Some(c) if c.call_id == call_id => c,
                _ => return Err(CallError::NoSuchCall(call_id.to_string())),
            };
            if !call.can_accept() {
                return Err(CallError::CannotAccept(
                    call_id.to_string(),
                    call.state_data.state.as_str().to_string(),
                ));
            }
            call.apply_transition(CallTransition::LocalAccepted)?;
            let snapshot = (
                call.encryption_key.clone(),
                call.peer_jid.clone(),
                call.call_creator.clone(),
                call.media_type == CallMediaType::Video,
                call.relay_data.as_ref().map(|r| r.endpoints.clone()).unwrap_or_default(),
            );
            st.accept_in_progress = true;
            snapshot
        };
        self.emit_state();

        let call_key = call_key.ok_or(CallError::NoCallKey)?;
        let accept = self
            .build_accept(call_id, &call_key, &peer_jid, &call_creator, is_video)
            .await
            .map_err(CallError::Socket)?;
        self.send(accept).await.map_err(CallError::Socket)?;
        tracing::info!("[CallManager] accept enviado peer={peer_jid} creator={call_creator}");

        self.notify_own_devices_terminated(call_id, &call_creator, Some("accepted_elsewhere"))
            .await;

        self.init_srtp_keys();
        if !endpoints.is_empty() {
            tracing::info!("[CallManager] acceptCall: conectando {} relays...", endpoints.len());
            self.connect_relays(endpoints).await;
        } else {
            tracing::warn!("[CallManager] acceptCall: sem endpoints na oferta");
        }
        self.ensure_media_flow();
        self.schedule_media_flow_retries(call_id);

        self.send_post_accept_signals(&peer_jid, call_id, &call_creator).await;

        if let Some(call) = self.current_call().filter(|c| c.call_id == call_id) {
            self.emit(CallEvent::Accepted(call));
        }
        Ok(())
    }

    /// `rejectCall`.
    pub async fn reject_call(&self, call_id: &str, reason: EndCallReason) -> Result<(), CallError> {
        let (peer_device, creator, snapshot) = {
            let mut st = self.st();
            let accepted_by = st.accepted_by_jid.clone();
            let call = match st.call.as_mut() {
                Some(c) if c.call_id == call_id => c,
                _ => return Err(CallError::NoSuchCall(call_id.to_string())),
            };
            let peer_device = ensure_device_jid(accepted_by.as_deref().unwrap_or(&call.peer_jid));
            call.apply_transition(CallTransition::LocalRejected { reason })?;
            (peer_device, call.call_creator.clone(), call.clone())
        };

        match self.send(build_reject_stanza(&peer_device, call_id, &creator)).await {
            Ok(()) => tracing::info!("[CallManager] reject enviado to={peer_device}"),
            Err(e) => tracing::warn!("[CallManager] reject send: {e}"),
        }
        self.notify_own_devices_terminated(call_id, &creator, Some("accepted_elsewhere"))
            .await;

        self.emit(CallEvent::Ended(snapshot.clone()));
        self.emit(CallEvent::State(snapshot));
        self.finish_call_local();
        Ok(())
    }

    /// `endCall`.
    pub async fn end_call(&self, reason: EndCallReason) -> Result<(), CallError> {
        let (peer_device, call_id, creator, snapshot) = {
            let mut st = self.st();
            let accepted_by = st.accepted_by_jid.clone();
            let Some(call) = st.call.as_mut().filter(|c| !c.is_ended()) else {
                return Ok(());
            };
            let peer_device = ensure_device_jid(accepted_by.as_deref().unwrap_or(&call.peer_jid));
            call.apply_transition(CallTransition::Terminated { reason })?;
            (peer_device, call.call_id.clone(), call.call_creator.clone(), call.clone())
        };

        self.notify_peer_devices_terminated(&peer_device, &call_id, &creator).await;
        self.notify_own_devices_terminated(&call_id, &creator, None).await;

        self.emit(CallEvent::Ended(snapshot.clone()));
        self.emit(CallEvent::State(snapshot));
        self.finish_call_local();
        Ok(())
    }

    /// `setMute`.
    pub fn set_mute(&self, muted: bool) {
        {
            let mut st = self.st();
            let Some(call) = st.call.as_mut().filter(|c| c.is_active()) else {
                return;
            };
            if call
                .apply_transition(CallTransition::AudioMuteChanged { muted })
                .is_err()
            {
                return;
            }
        }
        self.emit_state();
        if muted {
            self.stop_capture();
        } else {
            self.start_capture();
        }
    }

    /// `setExternalAudioMode`.
    pub fn set_external_audio_mode(&self, enabled: bool) {
        self.audio_engine.set_external_mode(enabled);
        if enabled {
            self.reset_encode_state();
            tracing::info!("[CallManager] external audio mode enabled (live call)");
        }
    }

    /// `feedLiveAudio` / `feedExternalAudio`.
    pub fn feed_live_audio(&self, samples: &[f32]) {
        self.audio_engine.feed_external_audio(samples);
    }

    /// `destroy`.
    pub fn destroy(&self) {
        self.finish_call_local();
    }

    // -----------------------------------------------------------------------
    // roteamento (`dispatchCallNode` / `handleBaileysCallEvents`)
    // -----------------------------------------------------------------------

    /// Enfileira um nó de chamada: processados em ordem, fora do laço de
    /// eventos da conexão.
    pub fn enqueue_call_node(&self, node: BinaryNode) {
        let _ = self.dispatch_tx.send(DispatchJob::Node(node));
    }

    /// Enfileira o backup `ev call status=accept` (mesma fila dos nós).
    pub fn enqueue_call_event_accept(&self, call_id: String, from: String) {
        let _ = self.dispatch_tx.send(DispatchJob::EventAccept { call_id, from });
    }

    /// Encaminha um nó `<call>` ou `<ack class=call>` ao handler certo.
    pub async fn dispatch_call_node(&self, node: &BinaryNode) -> Result<(), CallError> {
        let info = extract_node_info(node);

        if let Some(i) = &info {
            if !i.call_id.is_empty()
                && is_call_recently_ended(&i.call_id)
                && matches!(i.tag.as_str(), "offer" | "terminate" | "reject")
            {
                tracing::info!("[CallManager] ignore {} callId={} (já encerrada)", i.tag, i.call_id);
                return Ok(());
            }
        }

        let is_ack_like = node.tag == "ack" || (info.is_none() && node.attr("type") == Some("offer"));
        if is_ack_like {
            self.handle_call_ack(node).await;
            return Ok(());
        }
        let Some(info) = info else {
            return Ok(());
        };

        if info.tag != "offer" && !info.call_id.is_empty() {
            if let Some(current) = self.current_call() {
                if current.call_id != info.call_id
                    && matches!(info.tag.as_str(), "accept" | "preaccept" | "transport" | "mute_v2" | "mute")
                {
                    tracing::info!(
                        "[CallManager] ignore {} callId={} (current={})",
                        info.tag,
                        info.call_id,
                        current.call_id
                    );
                    return Ok(());
                }
            }
        }

        let peer_jid = if info.peer_jid.is_empty() {
            node.attr("from").unwrap_or_default().to_string()
        } else {
            info.peer_jid.clone()
        };

        let result = match info.tag.as_str() {
            "offer" => self.handle_call_offer(node, &peer_jid).await,
            "accept" => {
                tracing::info!("[CallManager] dispatch accept callId={} from={peer_jid}", info.call_id);
                self.handle_call_accept(node, &peer_jid).await;
                Ok(())
            }
            "preaccept" => {
                self.handle_call_preaccept(node, &peer_jid).await;
                Ok(())
            }
            "transport" => {
                self.handle_call_transport(node, &peer_jid).await;
                Ok(())
            }
            "relaylatency" => {
                if self.debug {
                    tracing::debug!("[CallManager] relaylatency ignorado (igual ao Go)");
                }
                Ok(())
            }
            "mute_v2" | "mute" => {
                self.handle_call_mute_v2(node, &peer_jid).await;
                Ok(())
            }
            "terminate" | "reject" => {
                self.handle_call_terminate(node);
                Ok(())
            }
            "relay_election" | "relayelection" => {
                self.handle_relay_election(node);
                Ok(())
            }
            _ => {
                if node.attr("type") == Some("offer") {
                    self.handle_call_ack(node).await;
                }
                Ok(())
            }
        };

        if let Err(e) = &result {
            self.emit(CallEvent::Error {
                call_id: Some(info.call_id.clone()),
                message: e.to_string(),
            });
        }
        result
    }

    /// `handleBaileysCallEvents` para um evento `status=accept`: no caller
    /// destrava a chamada quando o `<accept>` raw não chegou.
    pub async fn handle_call_event_accept(&self, call_id: &str, from: &str) {
        let Some(current) = self.current_call().filter(|c| !c.is_ended()) else {
            tracing::warn!("[CallManager] ev call accept sem chamada callId={call_id}");
            return;
        };
        let matches = current.call_id == call_id
            || (current.is_initiator() && current.state_data.state == CallState::Ringing);
        if !matches {
            tracing::warn!("[CallManager] ev call accept sem manager callId={call_id}");
            return;
        }
        if !current.is_initiator() {
            tracing::info!("[CallManager] ev call accept ignorado (callee) callId={call_id}");
            return;
        }
        tracing::info!("[CallManager] ev call accept → signalPeerAccepted callId={call_id} peer={from}");
        self.signal_peer_accepted(Some(from).filter(|f| !f.is_empty())).await;
    }

    // -----------------------------------------------------------------------
    // handlers de signaling
    // -----------------------------------------------------------------------

    /// `handleCallOffer`.
    async fn handle_call_offer(&self, node: &BinaryNode, peer_jid: &str) -> Result<(), CallError> {
        let Some(info) = extract_node_info(node) else {
            return Ok(());
        };
        let call_id = info.call_id.clone();

        if let Some(current) = self.current_call() {
            if !current.is_ended() {
                tracing::warn!(
                    "[CallManager] incoming offer ignorada callId={call_id} — já há chamada ativa ({})",
                    current.call_id
                );
                return Ok(());
            }
        }

        let call_creator = info
            .inner_node
            .attr("call-creator")
            .map(String::from)
            .unwrap_or_else(|| peer_jid.to_string());
        let is_video = has_video_node(&info.inner_node);

        let (me_id, me_lid) = self.me_jids();
        let socket = self.socket.clone();
        let decrypt = move |jid: &str, t: &str, c: &[u8]| socket.decrypt_message(jid, t, c);
        let ours: Vec<String> = [me_lid.clone(), Some(me_id.clone())].into_iter().flatten().collect();
        let (decrypted_node, call_key) =
            match decrypt_call_key_in_node(&decrypt, &info.inner_node, peer_jid, &ours) {
                Ok((n, k)) => (n, Some(k)),
                Err(_) => (info.inner_node.clone(), None),
            };

        let mut parsed = parse_relay_from_ack(&decrypted_node);
        if parsed.endpoints.is_empty() {
            let alt = parse_relay_from_ack(&info.inner_node);
            if !alt.endpoints.is_empty() {
                parsed = alt;
            }
        }
        if parsed.endpoints.is_empty() {
            parsed.endpoints = extract_relay_endpoints(&decrypted_node);
        }
        tracing::info!(
            "[OFFER] relays={} participants={} callKey={} peerJid={peer_jid}",
            parsed.endpoints.len(),
            parsed.participant_jids.len(),
            if call_key.is_some() { "sim" } else { "NAO" }
        );

        let encoder = MlowCodec::new(MlowOptions::default())?;

        let media_type = if is_video { CallMediaType::Video } else { CallMediaType::Audio };
        let caller_pn = info
            .inner_node
            .attr("caller_pn")
            .or_else(|| node.attr("caller_pn"))
            .map(String::from);
        let mut call = CallInfo::new_incoming(
            call_id.clone(),
            peer_jid.to_string(),
            call_creator.clone(),
            caller_pn,
            media_type,
        );
        call.encryption_key = call_key;
        let relay_count = parsed.endpoints.len();
        if relay_count > 0 {
            call.relay_data = Some(parsed);
        }

        let self_lid = ensure_device_jid(me_lid.as_deref().unwrap_or(&me_id));
        let our_bases = self.our_bases();
        let ssrc = {
            let mut st = self.st();
            let participants = call
                .relay_data
                .as_ref()
                .map(|r| r.participant_jids.clone())
                .unwrap_or_default();
            st.call = Some(call);
            st.initial_transport_sent = false;
            st.self_ssrc = generate_secure_ssrc(&call_id, &self_lid, 0);
            st.peer_ssrcs = vec![generate_secure_ssrc(&call_id, &ensure_device_jid(peer_jid), 0)];

            if !participants.is_empty() {
                let our_device = ensure_device_jid(
                    participants
                        .iter()
                        .find(|j| our_bases.contains(&jid_base(j)) && has_device(j))
                        .map(String::as_str)
                        .unwrap_or(&self_lid),
                );
                st.self_ssrc = generate_secure_ssrc(&call_id, &our_device, 0);
                let peer_all: Vec<String> = participants
                    .iter()
                    .filter(|j| !our_bases.contains(&jid_base(j)))
                    .cloned()
                    .collect();
                if let Some(peer_raw) = peer_all.first().cloned() {
                    let cands = build_peer_candidates(&mut st, &call_id, &peer_raw, 24, &peer_all);
                    st.peer_ssrcs = cands;
                }
                tracing::info!(
                    "[OFFER-SSRC] self={our_device} ssrc=0x{:08x} peerCands={}",
                    st.self_ssrc,
                    st.peer_ssrcs.len()
                );
            }
            st.self_ssrc
        };
        {
            let mut md = self.md();
            md.rtp = Some(RtpSession::whatsapp_opus(ssrc));
            md.encoder = Some(encoder);
            md.srtp = None;
        }
        *self.decoder.lock().await = Some(MlowIsolatedDecoder::new());

        if let Err(e) = self
            .send(build_preaccept_stanza(peer_jid, &call_id, &call_creator))
            .await
        {
            tracing::error!("[CallManager] erro enviando preaccept: {e}");
        }

        if let Some(call) = self.current_call() {
            self.emit(CallEvent::Incoming(call.clone()));
            self.emit(CallEvent::State(call));
        }
        tracing::info!(
            "[CallManager] incoming call {call_id} from {peer_jid} (creator={call_creator}, video={is_video}, relays={relay_count})"
        );
        Ok(())
    }

    /// `handleCallAccept` (caller: peer atendeu).
    async fn handle_call_accept(&self, node: &BinaryNode, peer_jid: &str) {
        let Some(current) = self.current_call() else {
            return;
        };
        if !current.is_initiator() {
            tracing::info!(
                "[CallManager] ignore accept (somos callee, state={}) from={peer_jid}",
                current.state_data.state.as_str()
            );
            return;
        }
        let Some(info) = extract_node_info(node) else {
            return;
        };
        let call_id = current.call_id.clone();
        let call_creator = current.call_creator.clone();
        let participants = current
            .relay_data
            .as_ref()
            .map(|r| r.participant_jids.clone())
            .unwrap_or_default();
        let (me_id, me_lid) = self.me_jids();

        if needs_decryption(&info.tag) {
            let mut ours: Vec<String> = [me_lid.clone(), Some(me_id.clone()), Some(call_creator.clone())]
                .into_iter()
                .flatten()
                .filter(|j| !j.is_empty())
                .collect();
            ours.extend(participants.iter().cloned());
            let socket = self.socket.clone();
            let decrypt = move |jid: &str, t: &str, c: &[u8]| socket.decrypt_message(jid, t, c);
            match decrypt_call_key_in_node(&decrypt, &info.inner_node, peer_jid, &ours) {
                Ok((_, peer_key)) => {
                    let our_key = current.encryption_key.clone();
                    let keys_match = our_key.as_deref() == Some(peer_key.as_slice());
                    tracing::info!("[CallManager] accept decrypt callKey match={keys_match} peer={peer_jid}");
                    if let (false, Some(our_key)) = (keys_match, our_key) {
                        let our_bases = self.our_bases();
                        let our_device = ensure_device_jid(
                            participants
                                .iter()
                                .find(|j| our_bases.contains(&jid_base(j)) && has_device(j))
                                .cloned()
                                .unwrap_or_else(|| me_lid.clone().unwrap_or_else(|| me_id.clone()))
                                .as_str(),
                        );
                        let peer_device = ensure_device_jid(peer_jid);
                        match (
                            derive_per_jid_srtp_key(&our_key, &our_device),
                            derive_per_jid_srtp_key(&peer_key, &peer_device),
                        ) {
                            (Ok(send), Ok(recv)) => match SrtpSession::new(
                                &send,
                                &recv,
                                Some(SRTP_SEND_AUTH_TAG_LEN),
                                Some(SRTP_RECV_AUTH_TAG_LEN),
                            ) {
                                Ok(s) => {
                                    self.md().srtp = Some(s);
                                    tracing::info!(
                                        "[CallManager] SRTP re-initialized with peer's call_key send={our_device} recv={peer_device}"
                                    );
                                }
                                Err(e) => tracing::error!("[CallManager] per-JID SRTP re-derivation failed: {e}"),
                            },
                            _ => tracing::error!("[CallManager] per-JID SRTP re-derivation failed"),
                        }
                    }
                }
                Err(e) => tracing::warn!("[CallManager] accept decrypt: sem callKey ({e})"),
            }
        }

        let accepted = {
            let mut st = self.st();
            let Some(call) = st.call.as_mut().filter(|c| c.call_id == call_id) else {
                return;
            };
            if let Err(e) = call.apply_transition(CallTransition::RemoteAccepted) {
                tracing::warn!("[CallManager] remote_accepted failed state={}: {e}", call.state_data.state.as_str());
            }
            let snapshot = call.clone();
            st.accepted_by_jid = Some(peer_jid.to_string());
            if let Some(actual) = st.actual_peer_ssrc {
                tracing::info!("[CallManager] accept: keeping actual peer SSRC=0x{actual:08x}");
            } else {
                let extras = if has_device(peer_jid) { Vec::new() } else { participants.clone() };
                let cands = build_peer_candidates(&mut st, &call_id, peer_jid, 24, &extras);
                tracing::info!("[CallManager] accept SSRC: {} peer sub(s) for {peer_jid}", cands.len());
                st.peer_ssrcs = cands;
            }
            (snapshot, st.peer_ssrcs.clone())
        };
        self.emit(CallEvent::State(accepted.0.clone()));
        tracing::info!("[CallManager] handleCallAccept → Connecting (peer={peer_jid})");
        self.emit(CallEvent::Accepted(accepted.0));

        self.sctp.set_subscription_ssrcs(&accepted.1);
        self.sctp.resend_subscriptions();
        self.init_srtp_keys();

        self.notify_peer_devices_accepted_elsewhere(peer_jid).await;

        let me = Some(me_id.as_str());
        if let Err(e) = self
            .send(build_post_accept_transport_stanza(peer_jid, &call_id, &call_creator, me))
            .await
        {
            tracing::error!("[CallManager] erro enviando transport: {e}");
        }
        if let Err(e) = self
            .send(build_mute_v2_stanza(peer_jid, &call_id, &call_creator, 0, me))
            .await
        {
            tracing::error!("[CallManager] erro enviando mute_v2: {e}");
        }
        if let Some(accept_msg_id) = node.attr("id").filter(|id| !id.is_empty()) {
            let our_jid = me_lid.clone().unwrap_or_else(|| me_id.clone());
            if let Err(e) = self
                .send(build_accept_receipt_stanza(peer_jid, accept_msg_id, &call_id, &call_creator, &our_jid))
                .await
            {
                tracing::error!("[CallManager] erro enviando accept receipt: {e}");
            }
        }

        if self.sctp.has_connection() {
            self.ensure_media_flow();
        } else if let Some(endpoints) = self.current_endpoints() {
            self.connect_relays(endpoints).await;
            self.ensure_media_flow();
        }
        self.schedule_media_flow_retries(&call_id);
    }

    /// `handleCallPreaccept` (caller: manda o transport inicial uma vez).
    async fn handle_call_preaccept(&self, node: &BinaryNode, peer_jid: &str) {
        if extract_node_info(node).is_none() {
            return;
        }
        let (call_id, creator) = {
            let mut st = self.st();
            let Some(call) = st.call.as_ref() else {
                return;
            };
            if !call.is_initiator() || call.relay_data.is_none() || st.initial_transport_sent {
                return;
            }
            let ids = (call.call_id.clone(), call.call_creator.clone());
            st.initial_transport_sent = true;
            ids
        };
        let me_id = self.socket.me_id();
        if let Err(e) = self
            .send(build_transport_stanza(peer_jid, &call_id, &creator, Some(&me_id)))
            .await
        {
            self.st().initial_transport_sent = false;
            tracing::error!("[CallManager] erro enviando transport inicial: {e}");
        }
    }

    /// `handleCallTransport`.
    async fn handle_call_transport(&self, node: &BinaryNode, peer_jid: &str) {
        let Some(current) = self.current_call() else {
            return;
        };
        if current.is_initiator() && current.state_data.state == CallState::Ringing {
            tracing::info!("[CallManager] transport while Ringing → signalPeerAccepted peer={peer_jid}");
            self.signal_peer_accepted(Some(peer_jid)).await;
        }

        let Some(info) = extract_node_info(node) else {
            return;
        };
        let relays = extract_relay_endpoints(&info.inner_node);
        if relays.is_empty() {
            return;
        }
        {
            let mut st = self.st();
            if let Some(call) = st.call.as_mut() {
                call.relay_data
                    .get_or_insert_with(RelayData::default)
                    .endpoints = relays.clone();
            }
        }
        if !self.sctp.has_connection() {
            self.connect_relays(relays).await;
        }
        self.ensure_media_flow();
    }

    /// `handleCallAck` (`<ack class=call type=offer>` com os relays).
    async fn handle_call_ack(&self, node: &BinaryNode) {
        let Some(current) = self.current_call() else {
            return;
        };
        if node.attr("type") != Some("offer") {
            return;
        }
        if let Some(error) = node.attr("error") {
            tracing::error!("[CallManager] ACK error: {error}");
            return;
        }

        let parsed = parse_relay_from_ack(node);
        if parsed.endpoints.is_empty() {
            return;
        }
        tracing::info!(
            "[ACK] relays={} participants={} selfPid={:?} peerPid={:?}",
            parsed.endpoints.len(),
            parsed.participant_jids.join(","),
            parsed.self_pid,
            parsed.peer_pid
        );

        let call_id = current.call_id.clone();
        let relays = parsed.endpoints.clone();
        let participants = parsed.participant_jids.clone();
        let has_key = current.encryption_key.is_some();
        {
            let mut st = self.st();
            let Some(call) = st.call.as_mut().filter(|c| c.call_id == call_id) else {
                return;
            };
            call.relay_data = Some(parsed);

            if !participants.is_empty() {
                let (me_id, me_lid) = self.me_jids();
                let our_cred = me_lid.clone().unwrap_or_else(|| me_id.clone());
                let our_bases = self.our_bases();
                let our_device = ensure_device_jid(
                    participants
                        .iter()
                        .find(|j| our_bases.contains(&jid_base(j)) && has_device(j))
                        .map(String::as_str)
                        .unwrap_or(&our_cred),
                );
                let peer_jids: Vec<String> = participants
                    .iter()
                    .filter(|j| !our_bases.contains(&jid_base(j)))
                    .map(|j| ensure_device_jid(j))
                    .collect();
                let fallback_peer = ensure_device_jid(&current.peer_jid);
                let peer_device = peer_jids
                    .iter()
                    .max_by_key(|j| device_num(j))
                    .cloned()
                    .unwrap_or(fallback_peer);

                let new_self = generate_secure_ssrc(&call_id, &our_device, 0);
                if new_self != st.self_ssrc {
                    st.self_ssrc = new_self;
                    self.md().rtp = Some(RtpSession::whatsapp_opus(new_self));
                }
                let cands = build_peer_candidates(&mut st, &call_id, &peer_device, 24, &peer_jids);
                tracing::info!(
                    "[ACK] peerSsrcs={} primary={peer_device} (+{} listed)",
                    cands.len(),
                    peer_jids.len()
                );
                st.peer_ssrcs = cands;
            }
        }
        if !participants.is_empty() {
            if has_key {
                self.init_srtp_keys();
            } else {
                tracing::warn!("[CallManager] WARNING: No call_key — SRTP not initialized!");
            }
        }

        let send_preaccept = {
            let mut st = self.st();
            let send = current.is_initiator() && !st.outgoing_preaccept_sent;
            if send {
                st.outgoing_preaccept_sent = true;
            }
            send
        };
        if send_preaccept {
            if let Err(e) = self
                .send(build_preaccept_stanza(&current.peer_jid, &call_id, &current.call_creator))
                .await
            {
                self.st().outgoing_preaccept_sent = false;
                tracing::error!("[CallManager] erro enviando preaccept (caller): {e}");
            }
        }

        self.connect_relays(relays).await;
        self.maybe_start_caller_silence_warmup();
    }

    /// `handleRelayElection`.
    fn handle_relay_election(&self, node: &BinaryNode) {
        let Some(BinaryContent::Children(children)) = &node.content else {
            return;
        };
        let Some(inner) = children.first() else {
            return;
        };
        let idx = inner
            .attr("elected_relay_idx")
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| inner.attr("relay_id").and_then(|v| v.parse().ok()))
            .or_else(|| match &inner.content {
                Some(BinaryContent::Bytes(b)) if b.len() >= 4 => {
                    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
                }
                Some(BinaryContent::Bytes(b)) if !b.is_empty() => Some(b[0] as usize),
                _ => None,
            });
        if let Some(idx) = idx {
            if let Some(call) = self.st().call.as_mut() {
                call.elected_relay_idx = Some(idx);
            }
            tracing::info!("[CallManager] elected relay index: {idx}");
        }
    }

    /// `handleCallMuteV2`.
    async fn handle_call_mute_v2(&self, node: &BinaryNode, peer_jid: &str) {
        let Some(current) = self.current_call() else {
            return;
        };
        if current.is_initiator() && current.state_data.state == CallState::Ringing {
            tracing::info!("[CallManager] mute_v2 while Ringing → signalPeerAccepted peer={peer_jid}");
            self.signal_peer_accepted(Some(peer_jid)).await;
        }
        if extract_node_info(node).is_none() {
            return;
        }
        let Some(current) = self.current_call() else {
            return;
        };
        let me_id = self.socket.me_id();
        if let Err(e) = self
            .send(build_mute_v2_stanza(peer_jid, &current.call_id, &current.call_creator, 0, Some(&me_id)))
            .await
        {
            tracing::debug!("[CallManager] erro enviando mute_v2: {e}");
        }
    }

    fn is_own_account_jid(&self, jid: &str, call_creator: &str) -> bool {
        if jid.is_empty() {
            return false;
        }
        let base = jid_base(jid);
        if self.our_bases().contains(&base) {
            return true;
        }
        !call_creator.is_empty() && jid_base(call_creator) == base
    }

    /// `handleCallTerminate` (terminate/reject do peer ou ecos MD).
    fn handle_call_terminate(&self, node: &BinaryNode) {
        let info = extract_node_info(node);
        let reason_attr = info
            .as_ref()
            .and_then(|i| i.inner_node.attr("reason"))
            .unwrap_or_default()
            .to_string();
        let reason = if reason_attr == "accepted_elsewhere" {
            EndCallReason::AcceptedElsewhere
        } else {
            EndCallReason::UserEnded
        };
        let tag = info.as_ref().map(|i| i.tag.clone()).unwrap_or_default();
        let from_jid = info
            .as_ref()
            .map(|i| i.peer_jid.clone())
            .filter(|p| !p.is_empty())
            .or_else(|| node.attr("from").map(String::from))
            .unwrap_or_default();

        let snapshot = {
            let mut st = self.st();
            let accept_in_progress = st.accept_in_progress;
            let Some(call) = st.call.as_mut() else {
                return;
            };
            if let Some(i) = &info {
                if !i.call_id.is_empty() && i.call_id != call.call_id {
                    tracing::info!(
                        "[CallManager] ignore terminate callId={} (current={})",
                        i.call_id,
                        call.call_id
                    );
                    return;
                }
            }
            let state = call.state_data.state;
            let creator = call.call_creator.clone();
            if call.is_initiator()
                && (tag == "reject" || tag == "terminate")
                && self.is_own_account_jid(&from_jid, &creator)
                && (state == CallState::Ringing || state == CallState::Connecting)
            {
                tracing::info!(
                    "[CallManager] ignore self {tag} while outgoing ({}) from={from_jid}",
                    state.as_str()
                );
                return;
            }
            if reason == EndCallReason::AcceptedElsewhere
                && !call.is_initiator()
                && (accept_in_progress || state == CallState::Connecting || state == CallState::Active)
            {
                tracing::info!(
                    "[CallManager] ignore accepted_elsewhere — atendimento local ({}, acceptInProgress={accept_in_progress})",
                    state.as_str()
                );
                return;
            }
            let _ = call.apply_transition(CallTransition::Terminated { reason });
            tracing::info!(
                "[CallManager] terminate reason={}{} callId={}",
                reason.as_str(),
                if reason_attr.is_empty() { String::new() } else { format!(" ({reason_attr})") },
                call.call_id
            );
            call.clone()
        };

        self.emit(CallEvent::Ended(snapshot.clone()));
        self.emit(CallEvent::State(snapshot));
        self.finish_call_local();
    }

    /// `signalPeerAccepted` — caller: peer atendeu por um caminho alternativo
    /// (evento `status=accept`, transport/mute_v2 em Ringing). Idempotente.
    async fn signal_peer_accepted(&self, peer_jid: Option<&str>) {
        let (call_id, snapshot, subs) = {
            let mut st = self.st();
            let Some(call) = st.call.as_mut().filter(|c| !c.is_ended() && c.is_initiator()) else {
                return;
            };
            if call.state_data.state == CallState::Ringing {
                if let Err(e) = call.apply_transition(CallTransition::RemoteAccepted) {
                    tracing::warn!("[CallManager] signalPeerAccepted transition: {e}");
                }
            }
            let call_id = call.call_id.clone();
            let participants = call
                .relay_data
                .as_ref()
                .map(|r| r.participant_jids.clone())
                .unwrap_or_default();
            let snapshot = call.clone();
            let mut subs = None;
            if let Some(peer) = peer_jid {
                st.accepted_by_jid = Some(peer.to_string());
                if st.actual_peer_ssrc.is_none() {
                    let extras = if has_device(peer) { Vec::new() } else { participants };
                    let cands = build_peer_candidates(&mut st, &call_id, peer, 24, &extras);
                    st.peer_ssrcs = cands.clone();
                    subs = Some(cands);
                }
            }
            (call_id, snapshot, subs)
        };
        if let Some(subs) = subs {
            self.sctp.set_subscription_ssrcs(&subs);
            self.sctp.resend_subscriptions();
        }

        self.emit(CallEvent::State(snapshot.clone()));
        tracing::info!(
            "[CallManager] signalPeerAccepted → {} peer={}",
            snapshot.state_data.state.as_str(),
            peer_jid.unwrap_or(&snapshot.peer_jid)
        );
        self.emit(CallEvent::Accepted(snapshot));

        self.init_srtp_keys();
        if self.sctp.has_connection() {
            self.ensure_media_flow();
        } else if let Some(endpoints) = self.current_endpoints() {
            self.connect_relays(endpoints).await;
            self.ensure_media_flow();
        }
        self.schedule_media_flow_retries(&call_id);
    }

    fn current_endpoints(&self) -> Option<Vec<RelayEndpoint>> {
        self.st()
            .call
            .as_ref()
            .and_then(|c| c.relay_data.as_ref())
            .map(|r| r.endpoints.clone())
            .filter(|e| !e.is_empty())
    }

    // -----------------------------------------------------------------------
    // stanzas compostas
    // -----------------------------------------------------------------------

    /// `resolveAccountDeviceJids`: devices da conta via USync `@lid` + extras.
    async fn resolve_account_device_jids(&self, account_jid: &str, extra: &[String]) -> (Vec<String>, Option<String>) {
        let bare = jid_base(account_jid);
        let lid = self.socket.get_lid(bare.clone()).await;
        let usync_target = lid.clone().unwrap_or_else(|| bare.clone());

        fn add(devices: &mut Vec<String>, jid: &str) {
            if !jid.contains('@') {
                return;
            }
            let device = ensure_device_jid(jid);
            if !devices.contains(&device) {
                devices.push(device);
            }
        }
        let mut devices: Vec<String> = Vec::new();
        match self.socket.get_usync_devices(usync_target.clone()).await {
            Ok(list) => {
                for (user, device) in list {
                    if !user.is_empty() {
                        add(&mut devices, &usync_device_jid(&user, device, "lid"));
                    }
                }
            }
            Err(e) => tracing::warn!("[Signaling] USync devices failed for {usync_target}: {e}"),
        }
        for j in extra {
            add(&mut devices, j);
        }
        if devices.is_empty() && !bare.is_empty() {
            add(&mut devices, &bare);
        }
        (devices, lid)
    }

    /// `buildOfferStanza`.
    async fn build_offer(
        &self,
        call_id: &str,
        call_key: &[u8],
        peer_jid: &str,
        is_video: bool,
        call_creator: &str,
        extra_devices: &[String],
    ) -> Result<BinaryNode, String> {
        let (devices, lid) = self.resolve_account_device_jids(peer_jid, extra_devices).await;
        if devices.is_empty() {
            tracing::warn!("[buildOfferStanza] no valid device JIDs for {peer_jid}");
        }
        tracing::info!("[buildOfferStanza] call-creator={call_creator} devices={devices:?}");

        self.socket.assert_sessions(devices.clone(), false).await?;

        let message = wa::Message {
            call: Some(Box::new(wa::message::Call {
                call_key: Some(call_key.to_vec()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let (destinations, include_identity) =
            self.socket
                .create_participant_nodes(&devices, &message, &[("count", "0")], lid.as_deref())?;

        let privacy = self.socket.tc_token(lid.as_deref().unwrap_or(peer_jid));
        let me_id = self.socket.me_id();
        Ok(build_offer_stanza(
            call_id,
            call_key,
            peer_jid,
            call_creator,
            is_video,
            Some(&me_id),
            destinations,
            include_identity,
            self.socket.device_identity(),
            privacy,
        ))
    }

    /// `buildAcceptStanza` — um único `<enc count=0>` para o device do caller.
    async fn build_accept(
        &self,
        call_id: &str,
        call_key: &[u8],
        peer_jid: &str,
        call_creator: &str,
        is_video: bool,
    ) -> Result<BinaryNode, String> {
        let creator_or_peer = if call_creator.is_empty() { peer_jid } else { call_creator };
        let target_device = ensure_device_jid(creator_or_peer);
        let to_jid = jid_base(creator_or_peer);
        let lid = self.socket.get_lid(to_jid.clone()).await;

        self.socket.assert_sessions(vec![target_device.clone()], false).await?;

        let (enc_type, ciphertext) = self
            .socket
            .encrypt_message(&target_device, &encode_call_message(call_key))
            .map_err(|e| format!("Failed to encrypt accept for {target_device}: {e}"))?;
        let include_identity = enc_type == "pkmsg";
        let enc_node = BinaryNode::new("enc")
            .with_attr("v", "2")
            .with_attr("type", &enc_type)
            .with_attr("count", "0")
            .with_bytes(ciphertext);
        let to = lid.unwrap_or(to_jid);
        tracing::info!("[buildAcceptStanza] enc → {target_device} to={to} type={enc_type}");
        Ok(build_accept_stanza(
            call_id,
            call_creator,
            &to,
            is_video,
            enc_node,
            include_identity,
            self.socket.device_identity(),
        ))
    }

    /// `sendPostAcceptSignals` (callee): transport type=1 + mute_v2.
    async fn send_post_accept_signals(&self, peer_jid: &str, call_id: &str, call_creator: &str) {
        let me_id = self.socket.me_id();
        let me = Some(me_id.as_str());
        let result = async {
            self.send(build_post_accept_transport_stanza(peer_jid, call_id, call_creator, me))
                .await?;
            self.send(build_mute_v2_stanza(peer_jid, call_id, call_creator, 0, me))
                .await
        }
        .await;
        match result {
            Ok(()) => tracing::info!("[CallManager] transport + mute_v2 enviados (pós-accept)"),
            Err(e) => tracing::error!("[CallManager] erro ao enviar transport/mute_v2: {e}"),
        }
    }

    // -----------------------------------------------------------------------
    // multi-device
    // -----------------------------------------------------------------------

    /// `listOwnSiblingDeviceJids`.
    async fn list_own_sibling_device_jids(&self) -> Vec<String> {
        let (me_id, me_lid) = self.me_jids();
        let our_cred = me_lid.clone().unwrap_or_else(|| me_id.clone());
        if our_cred.is_empty() {
            return Vec::new();
        }
        let self_device = ensure_device_jid(&our_cred);
        let self_nums: HashSet<u32> = [me_lid.clone(), Some(me_id.clone())]
            .into_iter()
            .flatten()
            .filter(|j| !j.is_empty())
            .map(|j| device_num(&j))
            .collect();
        let our_bases = self.our_bases();

        let mut found: Vec<String> = Vec::new();
        let mut add = |jid: &str| {
            if !jid.contains('@') || !our_bases.contains(&jid_base(jid)) {
                return;
            }
            let device = ensure_device_jid(jid);
            if device == self_device || self_nums.contains(&device_num(&device)) {
                return;
            }
            if !found.contains(&device) {
                found.push(device);
            }
        };

        let participants = self
            .current_call()
            .and_then(|c| c.relay_data)
            .map(|r| r.participant_jids)
            .unwrap_or_default();
        for jid in &participants {
            add(jid);
        }
        for bare in [me_lid, Some(me_id)].into_iter().flatten().filter(|j| !j.is_empty()) {
            let usync_bare = jid_base(&bare);
            let server = server_of(&usync_bare).to_string();
            match self.socket.get_usync_devices(usync_bare).await {
                Ok(list) => {
                    for (user, device) in list {
                        if !user.is_empty() {
                            add(&usync_device_jid(&user, device, &server));
                        }
                    }
                }
                Err(e) => tracing::warn!("[CallManager] USync own devices failed: {e}"),
            }
        }
        found
    }

    /// `notifyOwnDevicesTerminated` (reason `accepted_elsewhere` no accept/reject).
    async fn notify_own_devices_terminated(&self, call_id: &str, call_creator: &str, reason: Option<&str>) {
        let siblings = self.list_own_sibling_device_jids().await;
        if siblings.is_empty() {
            tracing::info!(
                "[CallManager] terminate MD own: nenhum sibling ({})",
                reason.unwrap_or("hangup")
            );
            return;
        }
        tracing::info!(
            "[CallManager] terminate MD own → {} sibling(s) reason={}: {}",
            siblings.len(),
            reason.unwrap_or("hangup"),
            siblings.join(", ")
        );
        for device in siblings {
            if let Err(e) = self
                .send(build_terminate_to_device_stanza(&device, call_id, call_creator, reason))
                .await
            {
                tracing::warn!("[CallManager] terminate MD own to {device}: {e}");
            }
        }
    }

    /// `listPeerDeviceJids`.
    async fn list_peer_device_jids(&self, primary_peer: &str) -> Vec<String> {
        let our_bases = self.our_bases();
        let current = self.current_call();
        let mut candidates: Vec<String> = current
            .as_ref()
            .and_then(|c| c.relay_data.as_ref())
            .map(|r| r.participant_jids.clone())
            .unwrap_or_default();
        if !primary_peer.is_empty() {
            candidates.push(primary_peer.to_string());
        }

        let mut peer_bare = jid_base(primary_peer);
        if peer_bare.is_empty() {
            peer_bare = current.as_ref().map(|c| jid_base(&c.peer_jid)).unwrap_or_default();
        }
        if !peer_bare.is_empty() {
            let server = server_of(&peer_bare).to_string();
            match self.socket.get_usync_devices(peer_bare).await {
                Ok(list) => {
                    for (user, device) in list {
                        if !user.is_empty() {
                            candidates.push(usync_device_jid(&user, device, &server));
                        }
                    }
                }
                Err(e) => tracing::warn!("[CallManager] USync peer devices failed: {e}"),
            }
        }

        let mut out: Vec<String> = Vec::new();
        for jid in candidates {
            if our_bases.contains(&jid_base(&jid)) {
                continue;
            }
            let device = ensure_device_jid(&jid);
            if !out.contains(&device) {
                out.push(device);
            }
        }
        out
    }

    /// `notifyPeerDevicesAcceptedElsewhere` (caller, ao receber accept).
    async fn notify_peer_devices_accepted_elsewhere(&self, accepting_device: &str) {
        let Some(current) = self.current_call() else {
            return;
        };
        let accept_device = ensure_device_jid(accepting_device);
        let others: Vec<String> = self
            .list_peer_device_jids(&accept_device)
            .await
            .into_iter()
            .filter(|d| *d != accept_device)
            .collect();
        if others.is_empty() {
            tracing::info!("[CallManager] peer accepted_elsewhere: nenhum outro device do peer");
            return;
        }
        tracing::info!(
            "[CallManager] peer accepted_elsewhere → {}: {}",
            others.len(),
            others.join(", ")
        );
        for device in others {
            if let Err(e) = self
                .send(build_accepted_elsewhere_stanza(&device, &current.call_id, &current.call_creator))
                .await
            {
                tracing::warn!("[CallManager] peer accepted_elsewhere to {device}: {e}");
            }
        }
    }

    /// `notifyPeerDevicesTerminated` (hangup).
    async fn notify_peer_devices_terminated(&self, primary_peer: &str, call_id: &str, call_creator: &str) {
        let mut peers = self.list_peer_device_jids(primary_peer).await;
        if peers.is_empty() && !primary_peer.is_empty() {
            peers.push(ensure_device_jid(primary_peer));
        }
        tracing::info!("[CallManager] terminate MD peer → {}: {}", peers.len(), peers.join(", "));
        for device in peers {
            if let Err(e) = self
                .send(build_terminate_to_device_stanza(&device, call_id, call_creator, None))
                .await
            {
                tracing::warn!("[CallManager] terminate MD peer to {device}: {e}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // SRTP
    // -----------------------------------------------------------------------

    /// `resolveOurDeviceJid` — nunca usa o callCreator no callee.
    fn resolve_our_device_jid(&self, call: Option<&CallInfo>) -> String {
        let (me_id, me_lid) = self.me_jids();
        let our_cred = me_lid.clone().unwrap_or_else(|| me_id.clone());
        let our_bases = self.our_bases();
        let participants = call
            .and_then(|c| c.relay_data.as_ref())
            .map(|r| r.participant_jids.clone())
            .unwrap_or_default();
        if let Some(j) = participants
            .iter()
            .find(|j| our_bases.contains(&jid_base(j)) && has_device(j))
        {
            return ensure_device_jid(j);
        }
        if let Some(c) = call.filter(|c| c.is_initiator() && !c.call_creator.is_empty()) {
            if our_bases.contains(&jid_base(&c.call_creator)) || our_bases.is_empty() {
                return ensure_device_jid(&c.call_creator);
            }
        }
        ensure_device_jid(&our_cred)
    }

    fn set_srtp(&self, call_key: &[u8], our_device: &str, peer_device: &str) -> Result<(), String> {
        let send = derive_per_jid_srtp_key(call_key, our_device).map_err(|e| e.to_string())?;
        let recv = derive_per_jid_srtp_key(call_key, peer_device).map_err(|e| e.to_string())?;
        let session = SrtpSession::new(
            &send,
            &recv,
            Some(SRTP_SEND_AUTH_TAG_LEN),
            Some(SRTP_RECV_AUTH_TAG_LEN),
        )
        .map_err(|e| e.to_string())?;
        self.md().srtp = Some(session);
        Ok(())
    }

    /// `initSrtpKeys` — send = nosso device, recv = device do peer.
    fn init_srtp_keys(&self) {
        let (call, accepted_by) = {
            let st = self.st();
            (st.call.clone(), st.accepted_by_jid.clone())
        };
        let Some(call) = call else {
            return;
        };
        let Some(call_key) = call.encryption_key.clone() else {
            tracing::info!("[SRTP] No call_key — SRTP not initialized!");
            return;
        };
        let (me_id, me_lid) = self.me_jids();
        let our_bases = self.our_bases();
        let participants = call
            .relay_data
            .as_ref()
            .map(|r| r.participant_jids.clone())
            .unwrap_or_default();

        let mut our_device = self.resolve_our_device_jid(Some(&call));
        let mut raw_peer = accepted_by.clone().unwrap_or_else(|| call.peer_jid.clone());
        if accepted_by.is_none() {
            let mut peer_parts: Vec<&String> = participants
                .iter()
                .filter(|j| !our_bases.contains(&jid_base(j)))
                .collect();
            peer_parts.sort_by_key(|j| std::cmp::Reverse(device_num(j)));
            if let Some(p) = peer_parts.first() {
                raw_peer = (*p).clone();
            }
        }
        if !raw_peer.is_empty() && our_bases.contains(&jid_base(&raw_peer)) {
            raw_peer = participants
                .iter()
                .find(|j| !our_bases.contains(&jid_base(j)))
                .cloned()
                .unwrap_or_else(|| call.peer_jid.clone());
            if our_bases.contains(&jid_base(&raw_peer)) {
                tracing::warn!("[SRTP] peer JID ainda é nossa conta ({raw_peer}) — abort init");
                return;
            }
        }
        let mut peer_device = ensure_device_jid(&raw_peer);

        if our_device == peer_device || jid_base(&our_device) == jid_base(&peer_device) {
            let fallback_our = ensure_device_jid(me_lid.as_deref().unwrap_or(&me_id));
            let fallback_peer = ensure_device_jid(&call.peer_jid);
            if !fallback_our.is_empty()
                && !fallback_peer.is_empty()
                && jid_base(&fallback_our) != jid_base(&fallback_peer)
            {
                tracing::warn!(
                    "[SRTP] send/recv mesma conta ({our_device}/{peer_device}) — corrigindo our={fallback_our} peer={fallback_peer}"
                );
                our_device = fallback_our;
                peer_device = fallback_peer;
            } else if our_device == peer_device {
                tracing::warn!("[SRTP] send===recv ({our_device}) — forçando nosso device {fallback_our}");
                our_device = fallback_our;
            }
        }

        match self.set_srtp(&call_key, &our_device, &peer_device) {
            Ok(()) => tracing::info!(
                "[SRTP] Per-JID mode: send={our_device} recv={peer_device} sendAuth={SRTP_SEND_AUTH_TAG_LEN} recvAuth={SRTP_RECV_AUTH_TAG_LEN}"
            ),
            Err(e) => tracing::info!("[SRTP] key derivation failed: {e}"),
        }
    }

    /// `reinitRecvSrtpForDevice` — recv passa a ser o device real do peer.
    fn reinit_recv_srtp_for_device(&self, peer_device: &str) {
        let call = self.current_call();
        let Some(call_key) = call.as_ref().and_then(|c| c.encryption_key.clone()) else {
            return;
        };
        let our_device = self.resolve_our_device_jid(call.as_ref());
        match self.set_srtp(&call_key, &our_device, peer_device) {
            Ok(()) => tracing::info!("[SRTP] re-derivado p/ device real do peer: recv={peer_device}"),
            Err(e) => tracing::info!("[SRTP] re-derivação falhou: {e}"),
        }
    }

    // -----------------------------------------------------------------------
    // relays + mídia
    // -----------------------------------------------------------------------

    /// `connectRelays` — até 2 relays UDP (protocol 0) na porta 3478.
    async fn connect_relays(&self, endpoints: Vec<RelayEndpoint>) {
        tracing::info!(
            "[CallManager] connecting to {} relay endpoints via WebRTC/SCTP DataChannel...",
            endpoints.len()
        );
        let mut seen = HashSet::new();
        let unique: Vec<RelayEndpoint> = endpoints
            .into_iter()
            .filter(|ep| ep.protocol.unwrap_or(0) == 0)
            .filter(|ep| seen.insert(format!("{}:{}", ep.ip, ep.port)))
            .collect();
        let relays: Vec<RelayInfo> = unique
            .iter()
            .filter(|ep| !ep.key.is_empty() && ep.raw_token.is_some())
            .take(MAX_RELAYS)
            .map(|ep| RelayInfo {
                ip: ep.ip.clone(),
                port: WA_RELAY_PORT,
                token: ep.token.clone(),
                auth_token: ep.auth_token.clone(),
                raw_auth_token: ep.raw_auth_token.clone(),
                raw_token: ep.raw_token.clone(),
                key: ep.key.clone(),
                relay_id: ep.relay_id,
                name: ep
                    .relay_name
                    .clone()
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| format!("{}:{WA_RELAY_PORT}", ep.ip)),
                auth_token_id: ep.auth_token_id.clone(),
            })
            .collect();
        if unique.len() > MAX_RELAYS {
            tracing::info!("[RELAY] using {MAX_RELAYS}/{} endpoints", unique.len());
        }
        if relays.is_empty() {
            tracing::error!("[CallManager] No relay configs");
            return;
        }

        let (self_ssrc, peer_ssrcs, self_pid, peer_pid) = {
            let mut st = self.st();
            let Some(call) = st.call.clone() else {
                return;
            };
            if st.peer_ssrcs.is_empty() || (st.peer_ssrcs.len() == 1 && st.peer_ssrcs[0] == st.self_ssrc) {
                let cands = build_peer_candidates(&mut st, &call.call_id, &call.peer_jid, 24, &[]);
                tracing::info!("[RELAY] peerSsrcs was self/empty — rebuilt {} candidates", cands.len());
                st.peer_ssrcs = cands;
            }
            let rd = call.relay_data.as_ref();
            (
                st.self_ssrc,
                st.peer_ssrcs.clone(),
                rd.and_then(|r| r.self_pid).unwrap_or(0),
                rd.and_then(|r| r.peer_pid).unwrap_or(0),
            )
        };
        self.sctp.set_ssrc(self_ssrc);
        self.sctp.set_subscription_ssrcs(&peer_ssrcs);
        self.sctp.set_pids(self_pid, peer_pid);
        self.sctp.configure_relays(relays).await;
        tracing::info!(
            "[RELAY] SCTP: {} connected, selfSsrc=0x{self_ssrc:08x} peerSsrcs={:?}",
            self.sctp.connected_count(),
            peer_ssrcs.iter().map(|s| format!("0x{s:08x}")).collect::<Vec<_>>()
        );
    }

    fn on_relay_connected(&self) {
        self.ensure_media_flow();
        self.maybe_start_caller_silence_warmup();
    }

    /// Caller: DataChannel abriu em Ringing → warmup de silêncio para o peer
    /// não ficar mudo ao atender.
    fn maybe_start_caller_silence_warmup(&self) {
        let state = {
            let st = self.st();
            let Some(call) = st.call.as_ref().filter(|c| c.is_initiator()) else {
                return;
            };
            if st.media_active {
                return;
            }
            call.state_data.state
        };
        if state != CallState::Ringing && state != CallState::Connecting {
            return;
        }
        {
            let md = self.md();
            if md.srtp.is_none() || md.rtp.is_none() || md.encoder.is_none() {
                return;
            }
        }
        if !self.sctp.has_connection() {
            return;
        }
        self.start_silence_capture();
        tracing::info!("[MEDIA] caller silence warmup state={}", state.as_str());
    }

    /// Retries curtos: o DataChannel costuma abrir depois do configure.
    fn schedule_media_flow_retries(&self, call_id: &str) {
        for ms in [80u64, 300, 1000, 2500] {
            let weak = self.me.clone();
            let call_id = call_id.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let Some(m) = weak.upgrade() else {
                    return;
                };
                {
                    let st = m.st();
                    if st.call.as_ref().map(|c| c.call_id.as_str()) != Some(call_id.as_str()) || st.media_active {
                        return;
                    }
                }
                m.ensure_media_flow();
            });
        }
    }

    /// `ensureMediaFlow` — Connecting→Active + início da mídia (idempotente).
    fn ensure_media_flow(&self) {
        let (start, transitioned) = {
            let mut st = self.st();
            let Some(call) = st.call.as_mut() else {
                return;
            };
            let state = call.state_data.state;
            if state != CallState::Connecting && state != CallState::Active {
                tracing::debug!("[MEDIA] ensureMediaFlow skip: state={}", state.as_str());
                return;
            }
            let transitioned =
                state == CallState::Connecting && call.apply_transition(CallTransition::MediaConnected).is_ok();
            (!st.media_active, transitioned)
        };
        if transitioned {
            self.emit_state();
            tracing::info!("[CallManager] accepted → Active (sctp={})", self.sctp.has_connection());
        }
        if start {
            self.start_media_flow();
        }
    }

    /// RTP com a chamada ainda tocando → promove (caller) e liga a mídia.
    fn try_activate_media_from_incoming_rtp(&self) {
        let promoted = {
            let mut st = self.st();
            if st.media_active {
                return;
            }
            let logged = st.media_inactive_drop_logged;
            let Some(call) = st.call.as_mut() else {
                return;
            };
            let state = call.state_data.state;
            if state == CallState::Ringing && call.is_initiator() {
                match call.apply_transition(CallTransition::RemoteAccepted) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!("[MEDIA] RTP promote failed state={}: {e}", state.as_str());
                        false
                    }
                }
            } else {
                if state == CallState::IncomingRinging && !call.is_initiator() && !logged {
                    tracing::warn!("[MEDIA] RTP while still IncomingRinging — acceptCall não ativou mídia?");
                }
                false
            }
        };
        if promoted {
            self.emit_state();
            tracing::info!("[MEDIA] RTP while Ringing (outgoing) → remote_accepted + media");
        }
        self.ensure_media_flow();
    }

    fn start_media_flow(&self) {
        {
            let mut st = self.st();
            if st.media_active {
                return;
            }
            st.media_active = true;
        }
        tracing::info!(
            "[MEDIA] startMediaFlow: audio={} ext={} srtp={} sctp={} PT=120 clock=16kHz ts_delta={MLOW_FRAME_SAMPLES}",
            self.audio_engine.has_audio(),
            self.audio_engine.is_external_mode(),
            self.md().srtp.is_some(),
            self.sctp.has_connection()
        );
        self.start_capture();
    }

    fn spawn_capture_loop(&self, silence: bool) -> JoinHandle<()> {
        let weak = self.me.clone();
        let interval_ms = self.audio_engine.config().interval_ms;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(m) = weak.upgrade() else {
                    return;
                };
                let chunk = if silence {
                    m.audio_engine.silence_chunk()
                } else {
                    m.audio_engine.next_capture_chunk()
                };
                for packet in m.encode_captured_audio(chunk) {
                    m.sctp.broadcast(Bytes::from(packet)).await;
                }
            }
        })
    }

    /// `startSilenceCapture`.
    fn start_silence_capture(&self) {
        let mut cap = lock(&self.capture);
        if cap.is_some() {
            return;
        }
        self.audio_engine.set_silence_mode(true);
        *cap = Some(CaptureLoop {
            handle: self.spawn_capture_loop(true),
            silence: true,
        });
    }

    /// `startCapture` — troca o warmup pela captura real (arquivo ou ao vivo).
    fn start_capture(&self) {
        let mut cap = lock(&self.capture);
        if let Some(current) = cap.as_ref() {
            if !current.silence {
                return;
            }
            current.handle.abort();
            *cap = None;
        }
        self.audio_engine.begin_capture();
        *cap = Some(CaptureLoop {
            handle: self.spawn_capture_loop(false),
            silence: false,
        });
    }

    fn stop_capture(&self) {
        if let Some(c) = lock(&self.capture).take() {
            c.handle.abort();
        }
    }

    fn reset_encode_state(&self) {
        let mut md = self.md();
        md.encode_buf.clear();
        md.real_audio_send_count = 0;
    }

    /// `sendCapturedAudio` + `sendOpusFrame`: acumula 960 amostras, codifica
    /// em MLow e devolve os pacotes SRTP prontos para o broadcast.
    fn encode_captured_audio(&self, mut data: Vec<f32>) -> Vec<Vec<u8>> {
        let media_active = self.st().media_active;
        if !media_active && !self.audio_engine.is_silence_mode() {
            return Vec::new();
        }
        let has_relay = self.sctp.has_connection();

        let mut md = self.md();
        if md.rtp.is_none() || md.srtp.is_none() || md.encoder.is_none() || !has_relay {
            let missing: Vec<&str> = [
                md.rtp.is_none().then_some("rtpSession"),
                md.srtp.is_none().then_some("srtpSession"),
                md.encoder.is_none().then_some("opusCodec"),
                (!has_relay).then_some("relayConnection"),
            ]
            .into_iter()
            .flatten()
            .collect();
            drop(md);
            let mut st = self.st();
            st.stats.audio_drop += 1;
            let n = st.stats.audio_drop;
            if n == 1 || n % 500 == 0 {
                tracing::info!("[CallManager] audio dropped #{n} — missing: {}", missing.join(", "));
            }
            return Vec::new();
        }

        for s in data.iter_mut() {
            if !s.is_finite() {
                *s = 0.0;
            }
        }
        md.encode_buf.extend_from_slice(&data);

        let mut packets = Vec::new();
        while md.encode_buf.len() >= MLOW_FRAME_SAMPLES {
            let frame: Vec<f32> = md.encode_buf.drain(..MLOW_FRAME_SAMPLES).collect();
            let encoded = match md.encoder.as_ref().map(|e| e.encode(&frame)) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => {
                    tracing::error!("[ENCODE] error: {e}");
                    continue;
                }
                None => break,
            };
            if md.real_audio_send_count < 3 {
                let config = encoded.first().map(|t| (t >> 3) & 0x1f).unwrap_or(0);
                tracing::info!(
                    "[ENCODE] #{}: {}B cfg={config} (60ms)",
                    md.real_audio_send_count + 1,
                    encoded.len()
                );
            }
            md.real_audio_send_count += 1;

            let marker = !md.first_packet_sent;
            let Some(rtp) = md.rtp.as_mut() else {
                break;
            };
            let mut packet = rtp.create_packet_with_duration(encoded, MLOW_FRAME_SAMPLES as u32, marker);
            packet.header.extension = true;
            packet.header.extension_profile = 0xDEBE;
            packet.header.extension_data = Vec::new();
            if !md.first_packet_sent {
                md.first_packet_sent = true;
                tracing::info!("[SEND] first packet marker=true debe=true ts_delta={MLOW_FRAME_SAMPLES}");
            }
            match md.srtp.as_mut().map(|s| s.protect(&packet)) {
                Some(Ok(srtp)) => packets.push(srtp),
                Some(Err(e)) => tracing::error!("[CallManager] error sending audio: {e}"),
                None => break,
            }
        }
        drop(md);

        if !packets.is_empty() {
            let mut st = self.st();
            for p in &packets {
                st.stats.audio_send += 1;
                let n = st.stats.audio_send;
                if n == 1 || n % 500 == 0 {
                    tracing::info!(
                        "[SEND] #{n}: SRTP={}B SCTP({}){}",
                        p.len(),
                        self.sctp.connected_count(),
                        if media_active { "" } else { " (silence)" }
                    );
                }
            }
        }
        packets
    }

    /// `onRelayData` — STUN/RTP do relay → SRTP → decode isolado → `Audio`.
    async fn on_relay_data(&self, data: Vec<u8>, ip: Option<&str>, port: Option<u16>) {
        if !self.st().media_active {
            if is_rtp_packet(&data) {
                self.try_activate_media_from_incoming_rtp();
            }
            let mut st = self.st();
            if !st.media_active {
                if !st.media_inactive_drop_logged {
                    st.media_inactive_drop_logged = true;
                    let state = st.call.as_ref().map(|c| c.state_data.state.as_str()).unwrap_or("none");
                    tracing::warn!(
                        "[MEDIA] dropping relay packets — inactive state={state} sctp={}",
                        self.sctp.has_connection()
                    );
                }
                return;
            }
        }
        self.st().stats.relay_packets += 1;

        if is_stun_packet(&data) {
            self.st().stats.stun_responses += 1;
            return;
        }
        if !is_rtp_packet(&data) || data.len() < 12 {
            return;
        }
        if data[1] & 0x7f != 120 {
            return;
        }
        {
            let md = self.md();
            if md.srtp.is_none() || md.encoder.is_none() {
                return;
            }
        }

        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let mut learned_device: Option<String> = None;
        let mut resubscribe: Option<u32> = None;
        {
            let mut st = self.st();
            if let (Some(ip), Some(port)) = (ip, port) {
                let key = format!("{ip}:{port}");
                match st.pinned_rtp_relay.clone() {
                    None => {
                        tracing::info!("[RECV] pinned RTP relay {key}");
                        st.pinned_rtp_relay = Some(key);
                    }
                    Some(pinned) if pinned != key => return,
                    _ => {}
                }
            }
            if ssrc == st.self_ssrc {
                st.stats.self_echo += 1;
                let n = st.stats.self_echo;
                if n <= 3 || n % 200 == 0 {
                    tracing::info!("[RECV] skipping self-echo #{n}: ssrc=0x{ssrc:08x} ({}B)", data.len());
                }
                return;
            }
            if !st.ssrc_resubscribed && st.actual_peer_ssrc.is_none() {
                st.actual_peer_ssrc = Some(ssrc);
                st.ssrc_resubscribed = true;
                let dev = st.peer_ssrc_to_device.get(&ssrc).cloned();
                tracing::info!(
                    "[RECV] *** SSRC REAL DO PEER = 0x{ssrc:08x} device={} ***",
                    dev.as_deref().unwrap_or("?")
                );
                st.peer_ssrcs = vec![ssrc];
                resubscribe = Some(ssrc);
                if let Some(d) = dev {
                    st.accepted_by_jid = Some(d.clone());
                    learned_device = Some(d);
                }
            }
            if st.stats.audio_recv == 0 {
                tracing::info!(
                    "[RECV] first RTP: {}B ssrc=0x{ssrc:08x} selfSsrc=0x{:08x} peerSsrcs={:?}",
                    data.len(),
                    st.self_ssrc,
                    st.peer_ssrcs.iter().map(|s| format!("0x{s:08x}")).collect::<Vec<_>>()
                );
            }
        }
        if let Some(ssrc) = resubscribe {
            self.sctp.set_subscription_ssrc(ssrc);
            self.sctp.resend_subscriptions();
        }
        if let Some(dev) = learned_device {
            self.reinit_recv_srtp_for_device(&dev);
        }

        let unprotected = match self.md().srtp.as_mut() {
            Some(s) => s.unprotect(&data),
            None => return,
        };
        let (payload, seq) = match unprotected {
            Ok(p) => (p.payload, p.header.sequence_number),
            Err(e) => {
                let mut st = self.st();
                st.stats.srtp_errors += 1;
                if st.stats.srtp_errors <= 5 {
                    tracing::info!(
                        "[RECV] SRTP err #{}: {e} ssrc=0x{ssrc:08x} size={}B",
                        st.stats.srtp_errors,
                        data.len()
                    );
                }
                return;
            }
        };
        if payload.is_empty() {
            return;
        }

        let (recv_count, call_id) = {
            let mut st = self.st();
            st.stats.audio_recv += 1;
            if let Some(last) = st.last_recv_seq {
                let delta = seq.wrapping_sub(last);
                if delta == 0 || delta > 32768 {
                    st.stats.recv_dup_drops += 1;
                    let n = st.stats.recv_dup_drops;
                    if n <= 10 || n % 100 == 0 {
                        tracing::info!("[RECV] drop duplicate/old seq={seq} last={last} (x{n})");
                    }
                    return;
                }
                if delta > 1 {
                    st.stats.recv_seq_gaps += (delta - 1) as u64;
                    if st.stats.audio_recv <= 20 || st.stats.recv_seq_gaps <= 10 {
                        tracing::info!(
                            "[RECV] seq gap: expected={} got={seq} ({} packets lost)",
                            last.wrapping_add(1),
                            delta - 1
                        );
                    }
                }
            }
            st.last_recv_seq = Some(seq);
            if payload.len() <= 2 {
                st.stats.recv_dtx += 1;
            } else {
                st.stats.recv_real += 1;
            }
            (
                st.stats.audio_recv,
                st.call.as_ref().map(|c| c.call_id.clone()).unwrap_or_default(),
            )
        };

        let pcm = {
            let mut guard = self.decoder.lock().await;
            if !self.st().media_active {
                return;
            }
            let Some(decoder) = guard.as_mut() else {
                return;
            };
            decoder.decode(Some(&payload)).await
        };

        let n = pcm.len();
        if !matches!(n, 0 | 160 | 320 | 480 | 640 | 960 | 1920 | 2880) {
            tracing::warn!("[RECV] unexpected samples={n} seq={seq} — skip");
            return;
        }
        if recv_count <= 30 {
            tracing::info!(
                "[RECV] #{recv_count}: {}B opus={}B seq={seq} {} samples={n}",
                data.len(),
                payload.len(),
                if payload.len() <= 2 { "DTX" } else { "REAL" }
            );
        }
        if recv_count % 100 == 0 {
            let st = self.st();
            tracing::info!(
                "[RECV] #{recv_count}: real={} dtx={} seqLost={} dupDrop={} echoSkip={}",
                st.stats.recv_real,
                st.stats.recv_dtx,
                st.stats.recv_seq_gaps,
                st.stats.recv_dup_drops,
                st.stats.self_echo
            );
        }
        if n > 0 && !call_id.is_empty() {
            self.emit(CallEvent::Audio { call_id, pcm });
        }
    }

    /// `cleanupMedia`.
    fn cleanup_media(&self) {
        let stats = {
            let mut st = self.st();
            st.media_active = false;
            st.media_inactive_drop_logged = false;
            std::mem::take(&mut st.stats)
        };
        tracing::info!(
            "[CALL-STATS] Relay: {} | Recv: {} ok, {} srtpErr, {} seqLost, {} echoSkip | Sent: {} (drop: {})",
            stats.relay_packets,
            stats.audio_recv,
            stats.srtp_errors,
            stats.recv_seq_gaps,
            stats.self_echo,
            stats.audio_send,
            stats.audio_drop
        );

        self.stop_capture();
        self.audio_engine.set_silence_mode(false);
        self.audio_engine.reset_playback_buffer();
        self.sctp.cleanup();

        *self.md() = Media::default();
        match self.decoder.try_lock() {
            Ok(mut guard) => {
                if let Some(mut d) = guard.take() {
                    d.destroy();
                }
            }
            Err(_) => {
                let weak = self.me.clone();
                tokio::spawn(async move {
                    if let Some(m) = weak.upgrade() {
                        let mut guard = m.decoder.lock().await;
                        if !m.st().media_active {
                            if let Some(mut d) = guard.take() {
                                d.destroy();
                            }
                        }
                    }
                });
            }
        }

        let mut st = self.st();
        st.last_recv_seq = None;
        st.actual_peer_ssrc = None;
        st.ssrc_resubscribed = false;
        st.pinned_rtp_relay = None;
        st.initial_transport_sent = false;
        st.outgoing_preaccept_sent = false;
        st.peer_ssrc_to_device.clear();
    }

    /// `finishCallLocal` — mídia + libera a chamada atual.
    fn finish_call_local(&self) {
        let ended_id = self.st().call.as_ref().map(|c| c.call_id.clone());
        self.cleanup_media();
        {
            let mut st = self.st();
            st.accepted_by_jid = None;
            st.accept_in_progress = false;
            st.call = None;
        }
        if let Some(id) = ended_id {
            mark_call_ended(&id);
        }
    }

    /// `resolvePeerLid`.
    async fn resolve_peer_lid(&self, peer_jid: &str) -> String {
        if peer_jid.contains("@lid") {
            return peer_jid.to_string();
        }
        self.socket
            .get_lid(peer_jid.to_string())
            .await
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| peer_jid.to_string())
    }
}

impl Drop for NativeCallManager {
    fn drop(&mut self) {
        self.stop_capture();
        self.sctp.cleanup();
    }
}

/// `buildPeerCandidates` — assina só devices conhecidos do peer (1 quando o
/// device exato é conhecido, até 3 do ACK); o lookup 0..`max_device` fica
/// em `peer_ssrc_to_device` para identificar o 1º RTP.
fn build_peer_candidates(
    st: &mut Inner,
    call_id: &str,
    raw_peer: &str,
    max_device: u32,
    extra_device_jids: &[String],
) -> Vec<u32> {
    let base = jid_base(raw_peer);
    let Some(at) = base.find('@') else {
        return Vec::new();
    };
    st.peer_ssrc_to_device.clear();
    let (user, server) = base.split_at(at);
    for d in 0..=max_device {
        let jid = format!("{user}:{d}{server}");
        st.peer_ssrc_to_device.insert(generate_secure_ssrc(call_id, &jid, 0), jid);
    }

    let mut preferred: Vec<String> = Vec::new();
    let mut add = |jid: &str, st: &mut Inner| {
        if !jid.contains('@') || jid_base(jid) != base {
            return;
        }
        let dj = ensure_device_jid(jid);
        if !preferred.contains(&dj) {
            preferred.push(dj.clone());
        }
        st.peer_ssrc_to_device.insert(generate_secure_ssrc(call_id, &dj, 0), dj);
    };
    add(raw_peer, st);
    for j in extra_device_jids {
        add(j, st);
    }

    let raw_exact = has_device(raw_peer).then(|| ensure_device_jid(raw_peer));
    preferred.sort_by(|a, b| {
        if let Some(exact) = &raw_exact {
            if a == exact {
                return std::cmp::Ordering::Less;
            }
            if b == exact {
                return std::cmp::Ordering::Greater;
            }
        }
        device_num(b).cmp(&device_num(a))
    });

    let only_exact = raw_exact.is_some() && extra_device_jids.is_empty() && preferred.len() <= 1;
    let max_sub = if only_exact { 1 } else { 3 };
    let mut sub_jids: Vec<String> = preferred.into_iter().take(max_sub).collect();
    if sub_jids.is_empty() {
        sub_jids.push(format!("{user}:0{server}"));
    }
    let out: Vec<u32> = sub_jids
        .iter()
        .map(|j| generate_secure_ssrc(call_id, j, 0))
        .collect();
    tracing::info!(
        "[SSRC] subscribe {} peer(s) devices={:?} lookup={} base={base}",
        out.len(),
        sub_jids.iter().map(|j| device_num(j)).collect::<Vec<_>>(),
        st.peer_ssrc_to_device.len()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jid_device_helpers() {
        assert!(has_device("123:7@lid"));
        assert!(!has_device("123@lid"));
        assert_eq!(device_num("123:60@s.whatsapp.net"), 60);
        assert_eq!(device_num("123@s.whatsapp.net"), 0);
        assert_eq!(server_of("123@lid"), "lid");
        assert_eq!(server_of("123@s.whatsapp.net"), "s.whatsapp.net");
        assert_eq!(usync_device_jid("123", 0, "lid"), "123@lid");
        assert_eq!(usync_device_jid("123", 5, "lid"), "123:5@lid");
    }

    #[test]
    fn peer_candidates_single_when_device_known() {
        let mut st = Inner::default();
        let subs = build_peer_candidates(&mut st, "CALL", "555:60@lid", 24, &[]);
        assert_eq!(subs, vec![generate_secure_ssrc("CALL", "555:60@lid", 0)]);
        assert!(st.peer_ssrc_to_device.len() >= 25);
    }

    #[test]
    fn peer_candidates_prefers_highest_devices() {
        let mut st = Inner::default();
        let extras = vec!["555:59@lid".to_string(), "555:2@lid".to_string(), "555:60@lid".to_string()];
        let subs = build_peer_candidates(&mut st, "CALL", "555@lid", 24, &extras);
        assert_eq!(subs.len(), 3);
        assert_eq!(subs[0], generate_secure_ssrc("CALL", "555:60@lid", 0));
        assert_eq!(subs[1], generate_secure_ssrc("CALL", "555:59@lid", 0));
    }

    #[test]
    fn ended_registry_ttl() {
        assert!(!is_call_recently_ended("X-1"));
        mark_call_ended("X-1");
        assert!(is_call_recently_ended("X-1"));
        assert!(!was_terminate_webhook_sent("X-1"));
        note_terminate_webhook_sent("X-1");
        assert!(was_terminate_webhook_sent("X-1"));
    }
}
