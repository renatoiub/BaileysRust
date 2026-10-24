//! Relays de mídia via WebRTC (DTLS/SCTP DataChannel) — port de
//! `services/call/sctp-relay.ts` (`NodeSctpRelayManager`).
//!
//! Para cada relay: `RTCPeerConnection` com um DataChannel `wa-web-call`
//! (unordered), oferta local e uma "resposta" fabricada a partir da própria
//! oferta (SDP munge: `setup:passive`, ufrag = auth token, pwd = relay key,
//! fingerprint fixa e um candidato host no relay). Ao abrir o canal envia as
//! subscriptions STUN (v1–v4 + retries) e o ping de keepalive do WhatsApp.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use crate::stun::{
    build_allocate_for_relay, build_binding_request_with_subs, build_sender_subscriptions,
    build_ssrc_subscription_list, build_whatsapp_ping, parse_stun_response,
};
use crate::types::WA_DTLS_FINGERPRINT;

const TRUE_WEB_CLIENT_RELAY_PORT: u16 = 3480;
const CONNECTION_TIMEOUT: Duration = Duration::from_millis(20_000);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(1100);
const REGISTRATION_SCHEDULE_MS: [(&str, u64); 5] = [
    ("initial", 0),
    ("retry-50ms", 50),
    ("retry-150ms", 150),
    ("retry-500ms", 500),
    ("retry-3000ms", 3000),
];

/// Relay a conectar (já com a porta WebRTC do WhatsApp).
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub ip: String,
    pub port: u16,
    pub token: String,
    pub auth_token: Option<String>,
    pub raw_auth_token: Option<Vec<u8>>,
    pub raw_token: Option<Vec<u8>>,
    pub key: String,
    pub relay_id: u32,
    pub name: String,
    pub auth_token_id: Option<String>,
}

/// Eventos do gerenciador de relays (`relay:connected` / `relay:receive`).
#[derive(Debug)]
pub enum RelayEvent {
    Connected { ip: String, port: u16 },
    Receive { ip: String, port: u16, data: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    Connecting,
    Open,
    Closed,
    Failed,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Conn {
    id: String,
    relay: RelayInfo,
    state: Mutex<ConnState>,
    pc: Mutex<Option<Arc<RTCPeerConnection>>>,
    channel: Mutex<Option<Arc<RTCDataChannel>>>,
    /// Canais além do principal: o de escuta negociado (sid 1) e os que o
    /// relay abrir (`on_data_channel`).
    incoming_channels: Mutex<Vec<Arc<RTCDataChannel>>>,
    local_ufrag: Mutex<String>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    first_packet: AtomicBool,
    first_via: Mutex<std::collections::HashSet<String>>,
    sent_packets: AtomicU64,
    received_packets: AtomicU64,
}

impl Conn {
    fn new(id: String, relay: RelayInfo) -> Self {
        Self {
            id,
            relay,
            state: Mutex::new(ConnState::Connecting),
            pc: Mutex::new(None),
            channel: Mutex::new(None),
            incoming_channels: Mutex::new(Vec::new()),
            local_ufrag: Mutex::new(String::new()),
            tasks: Mutex::new(Vec::new()),
            first_packet: AtomicBool::new(false),
            first_via: Mutex::new(std::collections::HashSet::new()),
            sent_packets: AtomicU64::new(0),
            received_packets: AtomicU64::new(0),
        }
    }

    fn state(&self) -> ConnState {
        *lock(&self.state)
    }

    fn set_state(&self, s: ConnState) {
        *lock(&self.state) = s;
    }

    fn channel(&self) -> Option<Arc<RTCDataChannel>> {
        lock(&self.channel).clone()
    }

    fn is_open(&self) -> bool {
        self.state() == ConnState::Open
            && self
                .channel()
                .map(|c| c.ready_state() == RTCDataChannelState::Open)
                .unwrap_or(false)
    }

    fn push_task(&self, task: JoinHandle<()>) {
        lock(&self.tasks).push(task);
    }

    /// Para timers e fecha canais/peer connection (assíncrono, sem bloquear).
    fn shutdown(&self) {
        for t in lock(&self.tasks).drain(..) {
            t.abort();
        }
        let channel = lock(&self.channel).take();
        let incoming: Vec<_> = lock(&self.incoming_channels).drain(..).collect();
        let pc = lock(&self.pc).take();
        if channel.is_none() && incoming.is_empty() && pc.is_none() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            if let Some(ch) = channel {
                let _ = ch.close().await;
            }
            for ch in incoming {
                let _ = ch.close().await;
            }
            if let Some(pc) = pc {
                let _ = pc.close().await;
            }
        });
    }
}

#[derive(Default)]
struct Subscriptions {
    audio_ssrc: u32,
    subscription_ssrc: u32,
    subscription_ssrcs: Vec<u32>,
    self_pid: u32,
    peer_pid: u32,
}

struct Shared {
    conns: Mutex<HashMap<String, Arc<Conn>>>,
    relay_map: Mutex<Vec<(String, RelayInfo)>>,
    subs: Mutex<Subscriptions>,
    events: mpsc::UnboundedSender<RelayEvent>,
    sdp_logged: AtomicBool,
    send_count: AtomicU64,
    pong_count: AtomicU64,
    rtp_recv_count: AtomicU64,
}

/// Gerenciador dos relays WebRTC de uma chamada.
pub struct SctpRelayManager {
    shared: Arc<Shared>,
}

fn make_connection_id(ip: &str, port: u16, auth_token_id: Option<&str>) -> String {
    let base = if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    };
    match auth_token_id {
        Some(id) if !id.is_empty() => format!("{base}#{id}"),
        _ => base,
    }
}

/// Remove linhas `a=<prefix>...` (com o fim de linha).
fn strip_lines(sdp: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        if !line.trim_start().starts_with(prefix) {
            out.push_str(line);
        }
    }
    out
}

/// Substitui o valor de todas as linhas `a=<attr>:...`.
fn replace_attr(sdp: &str, attr: &str, value: &str) -> String {
    let prefix = format!("a={attr}:");
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        if line.starts_with(&prefix) {
            let eol = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            out.push_str(&prefix);
            out.push_str(value);
            out.push_str(eol);
        } else {
            out.push_str(line);
        }
    }
    out
}

fn add_relay_candidate(sdp: &str, ip: &str, port: u16) -> String {
    let mut modified = strip_lines(sdp, "a=candidate:");
    modified = strip_lines(&modified, "a=end-of-candidates");
    if !modified.ends_with('\n') {
        modified.push_str("\r\n");
    }
    modified.push_str(&format!("a=candidate:2 1 udp 2122262783 {ip} {port} typ host\r\n"));
    modified.push_str("a=end-of-candidates\r\n");
    modified
}

fn modify_sdp_for_relay(sdp: &str, relay: &RelayInfo) -> String {
    let mut modified = sdp.replace("a=setup:actpass", "a=setup:passive");
    let ice_ufrag = relay
        .auth_token
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| relay.token.clone());
    modified = replace_attr(&modified, "ice-ufrag", &ice_ufrag);
    modified = replace_attr(&modified, "ice-pwd", &relay.key);
    modified = replace_attr(&modified, "fingerprint", WA_DTLS_FINGERPRINT);
    modified = replace_attr(&modified, "max-message-size", "1500");
    modified = strip_lines(&modified, "a=ice-options:");
    add_relay_candidate(&modified, &relay.ip, relay.port)
}

fn local_ufrag_of(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

async fn send_to_channel(shared: &Shared, conn: &Conn, data: &Bytes) -> bool {
    let Some(channel) = conn.channel() else {
        return false;
    };
    if channel.ready_state() != RTCDataChannelState::Open {
        return false;
    }
    match channel.send(data).await {
        Ok(_) => {
            conn.sent_packets.fetch_add(1, Ordering::Relaxed);
            let n = shared.send_count.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 10 || n % 100 == 0 {
                let kind = match (data.first().copied().unwrap_or(0) & 0xC0) >> 6 {
                    0 => "STUN",
                    2 => "RTP/SRTP",
                    _ => "OTHER",
                };
                tracing::debug!("[SCTP] send #{n} {kind} {}B → {}", data.len(), conn.id);
            }
            true
        }
        Err(e) => {
            tracing::debug!("[SCTP] send error {}: {e}", conn.id);
            false
        }
    }
}

fn fail_connection(shared: &Shared, conn: &Arc<Conn>, reason: &str) {
    if conn.state() == ConnState::Failed {
        return;
    }
    tracing::info!("[SCTP] connection failed: {} reason={reason}", conn.id);
    conn.set_state(ConnState::Failed);
    conn.shutdown();
    let mut conns = lock(&shared.conns);
    if conns.get(&conn.id).map(|c| Arc::ptr_eq(c, conn)).unwrap_or(false) {
        conns.remove(&conn.id);
    }
}

fn close_connection(shared: &Shared, conn: &Arc<Conn>) {
    let removed = {
        let mut conns = lock(&shared.conns);
        if conns.get(&conn.id).map(|c| Arc::ptr_eq(c, conn)).unwrap_or(false) {
            conns.remove(&conn.id);
            true
        } else {
            false
        }
    };
    if !removed {
        return;
    }
    conn.set_state(ConnState::Closed);
    conn.shutdown();
}

/// Uma rodada de subscriptions (v1/v2 binding ICE, v3 sem MI, v4 allocate).
async fn send_registration(shared: &Shared, conn: &Conn, label: &str) {
    if !conn.is_open() {
        return;
    }
    let relay = &conn.relay;
    let remote_ufrag = relay
        .auth_token
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| relay.token.clone());
    let local_ufrag = lock(&conn.local_ufrag).clone();
    let hmac_key = relay.key.as_bytes().to_vec();

    let (self_ssrc, peer_ssrc, peer_list) = {
        let s = lock(&shared.subs);
        (s.audio_ssrc, s.subscription_ssrc, s.subscription_ssrcs.clone())
    };
    let ssrc = if peer_ssrc != 0 { peer_ssrc } else { self_ssrc };
    if ssrc == 0 {
        tracing::info!("[STUN] registration({label}) skipped, no SSRC: {}", conn.id);
        return;
    }
    let subs = build_sender_subscriptions(ssrc);

    if !local_ufrag.is_empty() {
        let username = format!("{remote_ufrag}:{local_ufrag}");
        let v1 = build_binding_request_with_subs(
            Some(username.as_bytes()),
            Some(hmac_key.as_slice()),
            Some(subs.as_slice()),
            true,
            true,
        );
        send_to_channel(shared, conn, &Bytes::from(v1)).await;
    }

    if !relay.token.is_empty() && relay.token != remote_ufrag && !local_ufrag.is_empty() {
        let username = format!("{}:{local_ufrag}", relay.token);
        let v2 = build_binding_request_with_subs(
            Some(username.as_bytes()),
            Some(hmac_key.as_slice()),
            Some(subs.as_slice()),
            true,
            true,
        );
        send_to_channel(shared, conn, &Bytes::from(v2)).await;
    }

    let v3 = build_binding_request_with_subs(None, None, Some(subs.as_slice()), false, false);
    send_to_channel(shared, conn, &Bytes::from(v3)).await;

    if let Some(raw_token) = relay.raw_token.as_ref().filter(|t| !t.is_empty()) {
        let peer_ssrcs = if !peer_list.is_empty() {
            peer_list
        } else if peer_ssrc != 0 {
            vec![peer_ssrc]
        } else {
            Vec::new()
        };
        let ssrc_list = build_ssrc_subscription_list(&[self_ssrc], &peer_ssrcs, 0, 0, false);
        let v4 = build_allocate_for_relay(
            raw_token,
            &ssrc_list,
            &hmac_key,
            Some(relay.ip.as_str()),
            Some(relay.port),
        );
        send_to_channel(shared, conn, &Bytes::from(v4)).await;
        tracing::info!(
            "[STUN] subscriptions ({label}) → {} self=0x{self_ssrc:08x} peers={:?}",
            conn.id,
            peer_ssrcs.iter().map(|s| format!("0x{s:08x}")).collect::<Vec<_>>()
        );
    }
}

/// `sendStunAllocateOnOpen` — registro inicial + retries 50/150/500/3000 ms.
fn send_stun_allocate_on_open(shared: &Arc<Shared>, conn: &Arc<Conn>) {
    let remote_ufrag = conn
        .relay
        .auth_token
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| conn.relay.token.clone());
    if remote_ufrag.is_empty() {
        tracing::info!("[STUN] registration skipped, no ufrag: {}", conn.id);
        return;
    }
    let ws = Arc::downgrade(shared);
    let wc = Arc::downgrade(conn);
    let task = tokio::spawn(async move {
        let mut elapsed = 0u64;
        for (label, at) in REGISTRATION_SCHEDULE_MS {
            if at > elapsed {
                tokio::time::sleep(Duration::from_millis(at - elapsed)).await;
                elapsed = at;
            }
            let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) else {
                return;
            };
            if c.state() != ConnState::Open {
                return;
            }
            send_registration(&s, &c, label).await;
        }
    });
    conn.push_task(task);
}

fn start_keepalive(shared: &Arc<Shared>, conn: &Arc<Conn>) {
    let ws = Arc::downgrade(shared);
    let wc = Arc::downgrade(conn);
    let task = tokio::spawn(async move {
        let mut first = true;
        let mut keepalives = 0u64;
        loop {
            if !first {
                tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            }
            let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) else {
                return;
            };
            if !c.is_open() {
                return;
            }
            send_to_channel(&s, &c, &Bytes::from(build_whatsapp_ping())).await;
            if first {
                tracing::info!("[KEEPALIVE] first ping sent to {}", c.id);
                first = false;
            }
            keepalives += 1;
            if keepalives % 3 == 0 {
                log_diag(&s, &c, keepalives).await;
            }
        }
    });
    conn.push_task(task);
}

/// `[DIAG]` do Node: estado da conexão, contadores e o que o webrtc recebeu.
async fn log_diag(shared: &Shared, conn: &Conn, keepalives: u64) {
    use webrtc::stats::StatsReportType;

    let pc = lock(&conn.pc).clone();
    let dc_state = conn
        .channel()
        .map(|c| c.ready_state().to_string())
        .unwrap_or_else(|| "none".into());
    let (ice, pc_state) = pc
        .as_ref()
        .map(|p| (p.ice_connection_state().to_string(), p.connection_state().to_string()))
        .unwrap_or_else(|| ("none".into(), "none".into()));

    let mut channels = Vec::new();
    let mut accepted = 0u32;
    let mut pair = String::from("none");
    if let Some(pc) = pc {
        let report = pc.get_stats().await;
        for stat in report.reports.values() {
            match stat {
                StatsReportType::DataChannel(d) => channels.push(format!(
                    "{}#{} {} msgs_in={} bytes_in={} msgs_out={}",
                    d.label, d.data_channel_identifier, d.state, d.messages_received, d.bytes_received, d.messages_sent
                )),
                StatsReportType::PeerConnection(p) => accepted = p.data_channels_accepted,
                StatsReportType::CandidatePair(p) if p.nominated => {
                    pair = format!(
                        "pkts_in={} bytes_in={} pkts_out={} bytes_out={}",
                        p.packets_received, p.bytes_received, p.packets_sent, p.bytes_sent
                    );
                }
                _ => {}
            }
        }
    }

    tracing::info!(
        "[DIAG] {} keepalives={keepalives} dc={dc_state} ice={ice} pc={pc_state} sent={} recv={} pongs={} rtp_recv={} accepted_dcs={accepted} pair[{pair}] channels={:?}",
        conn.id,
        conn.sent_packets.load(Ordering::Relaxed),
        conn.received_packets.load(Ordering::Relaxed),
        shared.pong_count.load(Ordering::Relaxed),
        shared.rtp_recv_count.load(Ordering::Relaxed),
        channels
    );
}

fn handle_relay_message(shared: &Shared, conn: &Conn, data: Vec<u8>, via: &str, sid: u16) {
    if data.is_empty() {
        return;
    }
    let received = conn.received_packets.fetch_add(1, Ordering::Relaxed) + 1;
    if !conn.first_packet.swap(true, Ordering::Relaxed) {
        tracing::info!("[SCTP] first packet from {} ({}B)", conn.id, data.len());
    }
    if lock(&conn.first_via).insert(format!("{via}#{sid}")) {
        tracing::info!(
            "[SCTP] first packet from {} via {via} sid={sid} ({}B)",
            conn.id,
            data.len()
        );
    }

    let two_bits = (data[0] & 0xC0) >> 6;
    if two_bits == 0 {
        match parse_stun_response(&data) {
            Some(info) if info.method == "wa-pong" => {
                let n = shared.pong_count.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 3 || n % 20 == 0 {
                    tracing::debug!("[PONG] #{n} from {}", conn.id);
                }
            }
            Some(info) => {
                tracing::info!(
                    "[STUN] response from {}: method={} class={} success={} error={:?} {:?}",
                    conn.id,
                    info.method,
                    info.stun_class,
                    info.is_success,
                    info.error_code,
                    info.error_reason
                );
            }
            None => {
                tracing::debug!("[SCTP] unparseable STUN-like {}B from {}", data.len(), conn.id);
            }
        }
    } else if two_bits == 2 {
        let n = shared.rtp_recv_count.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 3 || n % 500 == 0 {
            let pt = data.get(1).map(|b| b & 0x7f).unwrap_or(0);
            tracing::info!(
                "[RTP-RECV] #{n} PT={pt} {}B from {} (pkts={received})",
                data.len(),
                conn.id
            );
        }
    }

    let _ = shared.events.send(RelayEvent::Receive {
        ip: conn.relay.ip.clone(),
        port: conn.relay.port,
        data,
    });
}

fn on_message_handler(
    ws: Weak<Shared>,
    wc: Weak<Conn>,
    via: &'static str,
    channel: Weak<RTCDataChannel>,
) -> Box<
    dyn FnMut(DataChannelMessage) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
> {
    Box::new(move |msg: DataChannelMessage| {
        if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
            let sid = channel.upgrade().map(|ch| ch.id()).unwrap_or(u16::MAX);
            handle_relay_message(&s, &c, msg.data.to_vec(), via, sid);
        }
        Box::pin(async {})
    })
}

async fn setup_peer(shared: &Arc<Shared>, conn: &Arc<Conn>) -> Result<(), String> {
    let api = APIBuilder::new().build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .map_err(|e| e.to_string())?,
    );
    *lock(&conn.pc) = Some(pc.clone());

    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(conn);
        pc.on_ice_connection_state_change(Box::new(move |st: RTCIceConnectionState| {
            if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
                tracing::info!("[ICE] {} iceConnection: {st}", c.id);
                if st == RTCIceConnectionState::Failed || st == RTCIceConnectionState::Disconnected {
                    fail_connection(&s, &c, "ice_connection_failed");
                }
            }
            Box::pin(async {})
        }));
    }
    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(conn);
        pc.on_peer_connection_state_change(Box::new(move |st: RTCPeerConnectionState| {
            if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
                tracing::info!("[PC] {} connectionState: {st}", c.id);
                if st == RTCPeerConnectionState::Failed {
                    fail_connection(&s, &c, "connection_state_failed");
                }
            }
            Box::pin(async {})
        }));
    }
    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(conn);
        pc.on_data_channel(Box::new(move |incoming: Arc<RTCDataChannel>| {
            if let Some(c) = wc.upgrade() {
                tracing::info!(
                    "[SCTP] incoming DataChannel from relay: \"{}\" id={}",
                    incoming.label(),
                    incoming.id()
                );
                incoming.on_message(on_message_handler(
                    ws.clone(),
                    wc.clone(),
                    "incoming",
                    Arc::downgrade(&incoming),
                ));
                lock(&c.incoming_channels).push(incoming);
            }
            Box::pin(async {})
        }));
    }

    let channel = pc
        .create_data_channel(
            "wa-web-call",
            Some(RTCDataChannelInit {
                ordered: Some(false),
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| e.to_string())?;
    *lock(&conn.channel) = Some(channel.clone());

    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(conn);
        channel.on_open(Box::new(move || {
            if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
                tracing::info!(
                    "[SCTP] DataChannel open: {} sid={}",
                    c.id,
                    c.channel().map(|ch| ch.id()).unwrap_or(u16::MAX)
                );
                c.set_state(ConnState::Open);
                send_stun_allocate_on_open(&s, &c);
                start_keepalive(&s, &c);
                let _ = s.events.send(RelayEvent::Connected {
                    ip: c.relay.ip.clone(),
                    port: c.relay.port,
                });
            }
            Box::pin(async {})
        }));
    }
    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(conn);
        channel.on_close(Box::new(move || {
            if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
                tracing::info!("[SCTP] DataChannel closed: {}", c.id);
                close_connection(&s, &c);
            }
            Box::pin(async {})
        }));
    }
    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(conn);
        channel.on_error(Box::new(move |err: webrtc::Error| {
            if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
                tracing::info!("[SCTP] DataChannel error {}: {err}", c.id);
                fail_connection(&s, &c, "data_channel_error");
            }
            Box::pin(async {})
        }));
    }
    channel.on_message(on_message_handler(
        Arc::downgrade(shared),
        Arc::downgrade(conn),
        "main",
        Arc::downgrade(&channel),
    ));

    // Escuta no sid de paridade oposta (negociado, sem DCEP e sem envio): o
    // laço de aceite do webrtc-rs descarta em silêncio dados de um stream
    // desconhecido que não comecem com DATA_CHANNEL_OPEN.
    let rx_channel = pc
        .create_data_channel(
            "wa-web-call-rx",
            Some(RTCDataChannelInit {
                ordered: Some(false),
                negotiated: Some(1),
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| e.to_string())?;
    rx_channel.on_message(on_message_handler(
        Arc::downgrade(shared),
        Arc::downgrade(conn),
        "rx",
        Arc::downgrade(&rx_channel),
    ));
    lock(&conn.incoming_channels).push(rx_channel);

    let offer = pc.create_offer(None).await.map_err(|e| e.to_string())?;
    pc.set_local_description(offer.clone())
        .await
        .map_err(|e| e.to_string())?;
    *lock(&conn.local_ufrag) = local_ufrag_of(&offer.sdp);

    let modified = modify_sdp_for_relay(&offer.sdp, &conn.relay);
    tracing::info!(
        "[SDP] candidate={}:{} (host) localUfrag={} authToken={}",
        conn.relay.ip,
        conn.relay.port,
        lock(&conn.local_ufrag),
        conn.relay
            .raw_auth_token
            .as_ref()
            .map(|t| format!("{}B", t.len()))
            .unwrap_or_else(|| "none".into())
    );
    if !shared.sdp_logged.swap(true, Ordering::Relaxed) {
        tracing::debug!("[SDP] modified SDP (first relay):\n{modified}");
    }

    let answer = RTCSessionDescription::answer(modified).map_err(|e| e.to_string())?;
    pc.set_remote_description(answer)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("[SCTP] relay {} configured, waiting for ICE...", conn.id);
    Ok(())
}

async fn connect_to_relay(shared: &Arc<Shared>, relay: RelayInfo) -> Option<Arc<Conn>> {
    let id = make_connection_id(&relay.ip, relay.port, relay.auth_token_id.as_deref());
    tracing::info!("[SCTP] connecting to relay {id} ({})", relay.name);

    if let Some(existing) = lock(&shared.conns).get(&id).cloned() {
        if existing.state() == ConnState::Open {
            return Some(existing);
        }
    }

    let conn = Arc::new(Conn::new(id.clone(), relay));
    lock(&shared.conns).insert(id.clone(), conn.clone());

    {
        let ws = Arc::downgrade(shared);
        let wc = Arc::downgrade(&conn);
        conn.push_task(tokio::spawn(async move {
            tokio::time::sleep(CONNECTION_TIMEOUT).await;
            if let (Some(s), Some(c)) = (ws.upgrade(), wc.upgrade()) {
                if c.state() == ConnState::Connecting {
                    tracing::info!("[SCTP] connection timeout: {}", c.id);
                    fail_connection(&s, &c, "connection_timeout");
                }
            }
        }));
    }

    match setup_peer(shared, &conn).await {
        Ok(()) => Some(conn),
        Err(e) => {
            tracing::info!("[SCTP] error connecting to {id}: {e}");
            fail_connection(shared, &conn, "connection_error");
            None
        }
    }
}

impl SctpRelayManager {
    /// Cria o gerenciador e o canal de eventos (`relay:connected`/`relay:receive`).
    pub fn new() -> (Self, mpsc::UnboundedReceiver<RelayEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                shared: Arc::new(Shared {
                    conns: Mutex::new(HashMap::new()),
                    relay_map: Mutex::new(Vec::new()),
                    subs: Mutex::new(Subscriptions::default()),
                    events: tx,
                    sdp_logged: AtomicBool::new(false),
                    send_count: AtomicU64::new(0),
                    pong_count: AtomicU64::new(0),
                    rtp_recv_count: AtomicU64::new(0),
                }),
            },
            rx,
        )
    }

    pub fn set_ssrc(&self, ssrc: u32) {
        lock(&self.shared.subs).audio_ssrc = ssrc;
        tracing::info!("[SCTP] our SSRC set: 0x{ssrc:08x}");
    }

    pub fn set_subscription_ssrc(&self, ssrc: u32) {
        let mut s = lock(&self.shared.subs);
        s.subscription_ssrc = ssrc;
        if ssrc != 0 && !s.subscription_ssrcs.contains(&ssrc) {
            s.subscription_ssrcs.insert(0, ssrc);
        }
        tracing::info!("[SCTP] subscription SSRC set (peer): 0x{ssrc:08x}");
    }

    pub fn set_subscription_ssrcs(&self, ssrcs: &[u32]) {
        let mut s = lock(&self.shared.subs);
        s.subscription_ssrcs = ssrcs.iter().copied().filter(|v| *v != 0).collect();
        s.subscription_ssrc = s.subscription_ssrcs.first().copied().unwrap_or(0);
        tracing::info!(
            "[SCTP] subscription SSRCs (peer): {:?}",
            s.subscription_ssrcs.iter().map(|v| format!("0x{v:08x}")).collect::<Vec<_>>()
        );
    }

    pub fn set_pids(&self, self_pid: u32, peer_pid: u32) {
        let mut s = lock(&self.shared.subs);
        s.self_pid = self_pid;
        s.peer_pid = peer_pid;
    }

    /// Reenvia as subscriptions em todas as conexões abertas.
    pub fn resend_subscriptions(&self) {
        let open: Vec<Arc<Conn>> = lock(&self.shared.conns)
            .values()
            .filter(|c| c.is_open())
            .cloned()
            .collect();
        for conn in open {
            send_stun_allocate_on_open(&self.shared, &conn);
            tracing::info!("[SCTP] re-sent subscriptions to {}", conn.id);
        }
    }

    /// `configureRelays` — registra e conecta (não espera o DataChannel abrir).
    pub async fn configure_relays(&self, relays: Vec<RelayInfo>) {
        tracing::info!("[SCTP] configuring {} relays...", relays.len());
        {
            let mut map = lock(&self.shared.relay_map);
            for mut relay in relays {
                if relay.port == 0 {
                    relay.port = TRUE_WEB_CLIENT_RELAY_PORT;
                }
                let id = make_connection_id(&relay.ip, relay.port, relay.auth_token_id.as_deref());
                match map.iter_mut().find(|(k, _)| *k == id) {
                    Some(slot) => slot.1 = relay,
                    None => map.push((id, relay)),
                }
            }
        }

        let pending: Vec<RelayInfo> = {
            let map = lock(&self.shared.relay_map);
            let conns = lock(&self.shared.conns);
            map.iter()
                .filter(|(id, _)| !conns.contains_key(id))
                .map(|(_, r)| r.clone())
                .collect()
        };

        let futures = pending
            .into_iter()
            .map(|relay| connect_to_relay(&self.shared, relay));
        futures_util::future::join_all(futures).await;

        tracing::info!("[SCTP] relay config done, {} connected", self.connected_count());
    }

    /// Envia para todas as conexões abertas (mídia SRTP).
    pub async fn broadcast(&self, data: Bytes) {
        let open: Vec<Arc<Conn>> = lock(&self.shared.conns)
            .values()
            .filter(|c| c.state() == ConnState::Open)
            .cloned()
            .collect();
        for conn in open {
            send_to_channel(&self.shared, &conn, &data).await;
        }
    }

    pub fn has_connection(&self) -> bool {
        lock(&self.shared.conns)
            .values()
            .any(|c| c.state() == ConnState::Open)
    }

    pub fn connected_count(&self) -> usize {
        lock(&self.shared.conns)
            .values()
            .filter(|c| c.state() == ConnState::Open)
            .count()
    }

    pub fn cleanup(&self) {
        let conns: Vec<Arc<Conn>> = lock(&self.shared.conns).drain().map(|(_, c)| c).collect();
        tracing::info!("[SCTP] cleaning up {} connections...", conns.len());
        for conn in conns {
            conn.set_state(ConnState::Closed);
            conn.shutdown();
        }
        lock(&self.shared.relay_map).clear();
        *lock(&self.shared.subs) = Subscriptions::default();
        self.shared.pong_count.store(0, Ordering::Relaxed);
        self.shared.rtp_recv_count.store(0, Ordering::Relaxed);
        self.shared.send_count.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> RelayInfo {
        RelayInfo {
            ip: "1.2.3.4".into(),
            port: 3478,
            token: "tok".into(),
            auth_token: Some("auth".into()),
            raw_auth_token: None,
            raw_token: None,
            key: "relaykey".into(),
            relay_id: 1,
            name: "gru1".into(),
            auth_token_id: Some("1".into()),
        }
    }

    #[test]
    fn sdp_munge_matches_node() {
        let sdp = "v=0\r\na=ice-ufrag:abcd\r\na=ice-pwd:xyz\r\na=ice-options:trickle\r\na=fingerprint:sha-256 AA\r\na=setup:actpass\r\na=max-message-size:262144\r\na=candidate:1 1 udp 1 10.0.0.1 5000 typ host\r\n";
        let out = modify_sdp_for_relay(sdp, &relay());
        assert!(out.contains("a=ice-ufrag:auth\r\n"));
        assert!(out.contains("a=ice-pwd:relaykey\r\n"));
        assert!(out.contains("a=setup:passive"));
        assert!(out.contains(&format!("a=fingerprint:{WA_DTLS_FINGERPRINT}")));
        assert!(out.contains("a=max-message-size:1500"));
        assert!(!out.contains("ice-options"));
        assert!(!out.contains("10.0.0.1"));
        assert!(out.ends_with("a=candidate:2 1 udp 2122262783 1.2.3.4 3478 typ host\r\na=end-of-candidates\r\n"));
        assert_eq!(local_ufrag_of(sdp), "abcd");
    }

    #[test]
    fn connection_id_includes_auth_token_id() {
        assert_eq!(make_connection_id("1.2.3.4", 3478, Some("2")), "1.2.3.4:3478#2");
        assert_eq!(make_connection_id("1.2.3.4", 3478, None), "1.2.3.4:3478");
    }
}
