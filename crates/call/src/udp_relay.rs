//! UDP relay transport (port de `services/call/udp-relay.ts`).
//!
//! Conecta sockets UDP4 aos relays do WhatsApp e faz a troca STUN
//! (binding/allocate com sender-subscriptions) + keepalive WA ping.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{self, Duration};

use crate::stun::{
    build_allocate_for_relay, build_binding_request_with_subs, build_minimal_binding_with_subs,
    build_sender_subscriptions, build_ssrc_subscription_list, build_whatsapp_ping, is_rtp_packet,
    is_stun_packet, parse_stun_response,
};

const KEEPALIVE_INTERVAL_MS: u64 = 1100;
/// Retries de subscription: inicial + offsets (espelha Go).
const SUBSCRIPTION_RETRY_OFFSETS_MS: [u64; 4] = [50, 150, 500, 3000];

/// Config de um relay UDP.
#[derive(Debug, Clone)]
pub struct UdpRelayConfig {
    pub ip: String,
    pub port: u16,
    pub raw_token: Vec<u8>,
    pub raw_auth_token: Option<Vec<u8>>,
    pub relay_key: Vec<u8>,
    pub relay_key_string: String,
    pub relay_id: u32,
    pub relay_name: String,
    pub self_ssrc: u32,
    pub peer_ssrcs: Vec<u32>,
    pub self_pid: Option<u32>,
    pub peer_pid: Option<u32>,
    pub self_video_ssrc: Option<u32>,
    pub peer_video_ssrcs: Vec<u32>,
    pub self_aux_ssrcs: Vec<u32>,
    pub mode: UdpRelayMode,
}

/// Modo de conexão UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRelayMode {
    Allocate,
    Binding,
}

/// Evento emitido pelo transport.
#[derive(Debug, Clone)]
pub enum UdpRelayEvent {
    Connected { ip: String, port: u16 },
    Data { ip: String, port: u16, data: Vec<u8> },
}

/// Estado de uma conexão UDP.
struct UdpConnection {
    socket: Arc<UdpSocket>,
    config: UdpRelayConfig,
    connected: bool,
    allocate_success: bool,
    binding_success: bool,
    stable_routing_conn_id: u64,
    stats: ConnStats,
}

#[derive(Debug, Default, Clone)]
struct ConnStats {
    #[allow(dead_code)]
    sent_packets: u64,
    #[allow(dead_code)]
    received_packets: u64,
    #[allow(dead_code)]
    rtp_sent: u64,
    #[allow(dead_code)]
    rtp_recv: u64,
}

/// Transport UDP relay.
pub struct UdpRelayTransport {
    connections: Arc<Mutex<HashMap<String, UdpConnection>>>,
    events: tokio::sync::broadcast::Sender<UdpRelayEvent>,
    keepalive: Mutex<Option<tokio::task::JoinHandle<()>>>,
    debug: bool,
}

impl UdpRelayTransport {
    pub fn new(debug: bool) -> Self {
        let (events, _) = tokio::sync::broadcast::channel(256);
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            events,
            keepalive: Mutex::new(None),
            debug,
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<UdpRelayEvent> {
        self.events.subscribe()
    }

    fn make_id(ip: &str, port: u16) -> String {
        format!("{ip}:{port}")
    }

    /// Conecta a todos os relays (deduplicados).
    pub async fn connect_all(&self, configs: &[UdpRelayConfig]) -> usize {
        let mut unique: HashMap<String, UdpRelayConfig> = HashMap::new();
        for config in configs {
            if config.ip.contains(':') {
                continue;
            }
            let id = Self::make_id(&config.ip, config.port);
            unique.entry(id).or_insert_with(|| config.clone());
        }

        self.start_keepalives().await;

        let mut success = 0usize;
        for (_, config) in unique {
            if self.connect_single(config).await {
                success += 1;
            }
        }
        success
    }

    async fn connect_single(&self, config: UdpRelayConfig) -> bool {
        let id = Self::make_id(&config.ip, config.port);
        if self.connections.lock().await.contains_key(&id) {
            return true;
        }

        let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
            Ok(s) => Arc::new(s),
            Err(_) => return false,
        };

        let conn = UdpConnection {
            socket: socket.clone(),
            config: config.clone(),
            connected: true,
            allocate_success: false,
            binding_success: false,
            stable_routing_conn_id: 0,
            stats: ConnStats::default(),
        };
        self.connections.lock().await.insert(id.clone(), conn);

        // Subscription inicial + retries + ping.
        self.send_subscriptions(&id, "initial").await;
        for offset in SUBSCRIPTION_RETRY_OFFSETS_MS {
            let tx = self.clone_weak();
            let id = id.clone();
            tokio::spawn(async move {
                time::sleep(Duration::from_millis(offset)).await;
                tx.send_subscriptions(&id, &format!("retry-{offset}ms")).await;
            });
        }

        let ping = build_whatsapp_ping();
        let _ = socket
            .send_to(&ping, (config.ip.as_str(), config.port))
            .await;

        let _ = self.events.send(UdpRelayEvent::Connected {
            ip: config.ip.clone(),
            port: config.port,
        });

        // Receiver loop.
        let this = self.clone_weak();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        this.handle_packet(&id, addr, &buf[..len]).await;
                    }
                    Err(_) => break,
                }
            }
        });

        true
    }

    fn clone_weak(&self) -> UdpRelayHandle {
        UdpRelayHandle {
            connections: self.connections.clone(),
            events: self.events.clone(),
            debug: self.debug,
        }
    }

    async fn send_subscriptions(&self, id: &str, label: &str) {
        let cfg = {
            let mut conns = self.connections.lock().await;
            let Some(conn) = conns.get_mut(id) else {
                return;
            };
            conn.config.clone()
        };
        let peer_ssrcs = cfg.peer_ssrcs.clone();
        let self_ssrc = cfg.self_ssrc;

        let ssrc = if !peer_ssrcs.is_empty() && peer_ssrcs[0] != 0 {
            peer_ssrcs[0]
        } else {
            self_ssrc
        };
        if ssrc == 0 {
            return;
        }

        let subs = build_sender_subscriptions(ssrc);
        let hmac_key = cfg.relay_key.clone();

        // v1: authToken-preferred username.
        let username_v1: Vec<u8> = if let Some(a) = &cfg.raw_auth_token {
            if !a.is_empty() {
                a.clone()
            } else {
                cfg.raw_token.clone()
            }
        } else {
            cfg.raw_token.clone()
        };

        let mut sends: Vec<(String, Vec<u8>)> = Vec::new();
        if !username_v1.is_empty() {
            sends.push((
                "v1".to_string(),
                build_binding_request_with_subs(
                    Some(&username_v1),
                    Some(&hmac_key),
                    Some(&subs),
                    true,
                    true,
                ),
            ));
        }
        if !cfg.raw_token.is_empty() && cfg.raw_token != username_v1 {
            sends.push((
                "v2".to_string(),
                build_binding_request_with_subs(
                    Some(&cfg.raw_token),
                    Some(&hmac_key),
                    Some(&subs),
                    true,
                    true,
                ),
            ));
        }
        sends.push((
            "v3".to_string(),
            build_minimal_binding_with_subs(&subs, false),
        ));

        // v4: Allocate com sender-subs + SSRC list.
        let mut all_self = vec![self_ssrc];
        if let Some(v) = cfg.self_video_ssrc {
            all_self.push(v);
        }
        all_self.extend(cfg.self_aux_ssrcs.iter().copied());
        let mut all_peer = peer_ssrcs.clone();
        all_peer.extend(cfg.peer_video_ssrcs.iter().copied());
        let ssrc_list = build_ssrc_subscription_list(
            &all_self,
            &all_peer,
            cfg.self_pid.unwrap_or(0),
            cfg.peer_pid.unwrap_or(0),
            false,
        );
        sends.push((
            "v4-alloc".to_string(),
            build_allocate_for_relay(
                &cfg.raw_token,
                &ssrc_list,
                &hmac_key,
                Some(&cfg.ip),
                Some(cfg.port),
            ),
        ));

        let socket = {
            let conns = self.connections.lock().await;
            let Some(conn) = conns.get(id) else {
                return;
            };
            conn.socket.clone()
        };
        let dest = (cfg.ip.clone(), cfg.port);
        for (_variant, payload) in sends {
            let _ = socket.send_to(&payload, dest.clone()).await;
        }
        if self.debug {
            tracing::debug!(%label, relay = %cfg.relay_name, "subscriptions enviadas");
        }
    }

    /// Envia dados a um relay específico.
    pub async fn send(&self, ip: &str, port: u16, data: &[u8]) -> bool {
        let id = Self::make_id(ip, port);
        let (socket, dest) = {
            let conns = self.connections.lock().await;
            let Some(conn) = conns.get(&id) else {
                return false;
            };
            if !conn.connected {
                return false;
            }
            (conn.socket.clone(), (conn.config.ip.clone(), conn.config.port))
        };
        let _ = socket.send_to(data, dest).await;
        true
    }

    /// Broadcast a todos os relays conectados.
    pub async fn broadcast(&self, data: &[u8]) -> usize {
        let conns = self.connections.lock().await;
        let mut sent = 0;
        for conn in conns.values() {
            if conn.connected {
                if conn
                    .socket
                    .send_to(data, (conn.config.ip.as_str(), conn.config.port))
                    .await
                    .is_ok()
                {
                    sent += 1;
                }
            }
        }
        sent
    }

    pub async fn has_connection(&self) -> bool {
        self.connections
            .lock()
            .await
            .values()
            .any(|c| c.connected)
    }

    pub async fn get_connected_count(&self) -> usize {
        self.connections
            .lock()
            .await
            .values()
            .filter(|c| c.connected)
            .count()
    }

    pub async fn update_subscriptions(&self, self_ssrc: u32, peer_ssrcs: Vec<u32>) {
        let ids: Vec<String> = {
            let mut conns = self.connections.lock().await;
            for conn in conns.values_mut() {
                conn.config.self_ssrc = self_ssrc;
                conn.config.peer_ssrcs = peer_ssrcs.clone();
            }
            conns.keys().cloned().collect()
        };
        for id in ids {
            self.send_subscriptions(&id, "update").await;
        }
    }

    async fn start_keepalives(&self) {
        let mut keepalive = self.keepalive.lock().await;
        if keepalive.is_some() {
            return;
        }
        let handle = self.clone_weak();
        *keepalive = Some(tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_millis(KEEPALIVE_INTERVAL_MS)).await;
                let ids: Vec<String> = handle.connections.lock().await.keys().cloned().collect();
                for id in ids {
                    let (connected, socket, dest) = {
                        let conns = handle.connections.lock().await;
                        let Some(conn) = conns.get(&id) else {
                            continue;
                        };
                        (
                            conn.connected,
                            conn.socket.clone(),
                            (conn.config.ip.clone(), conn.config.port),
                        )
                    };
                    if connected {
                        let ping = build_whatsapp_ping();
                        let _ = socket.send_to(&ping, dest).await;
                    }
                }
            }
        }));
    }

    pub async fn cleanup(&self) {
        if let Some(handle) = self.keepalive.lock().await.take() {
            handle.abort();
        }
        let mut conns = self.connections.lock().await;
        for conn in conns.values_mut() {
            conn.connected = false;
        }
        conns.clear();
    }
}

/// Handle compartilhável (clone fraco).
struct UdpRelayHandle {
    connections: Arc<Mutex<HashMap<String, UdpConnection>>>,
    events: tokio::sync::broadcast::Sender<UdpRelayEvent>,
    debug: bool,
}

impl UdpRelayHandle {
    async fn send_subscriptions(&self, id: &str, label: &str) {
        let cfg = {
            let mut conns = self.connections.lock().await;
            let Some(conn) = conns.get_mut(id) else {
                return;
            };
            conn.config.clone()
        };
        let ssrc = if !cfg.peer_ssrcs.is_empty() && cfg.peer_ssrcs[0] != 0 {
            cfg.peer_ssrcs[0]
        } else {
            cfg.self_ssrc
        };
        if ssrc == 0 {
            return;
        }

        let subs = build_sender_subscriptions(ssrc);
        let hmac_key = cfg.relay_key.clone();
        let username_v1: Vec<u8> = if let Some(a) = &cfg.raw_auth_token {
            if !a.is_empty() {
                a.clone()
            } else {
                cfg.raw_token.clone()
            }
        } else {
            cfg.raw_token.clone()
        };

        let mut sends: Vec<(String, Vec<u8>)> = Vec::new();
        if !username_v1.is_empty() {
            sends.push((
                "v1".to_string(),
                build_binding_request_with_subs(
                    Some(&username_v1),
                    Some(&hmac_key),
                    Some(&subs),
                    true,
                    true,
                ),
            ));
        }
        if !cfg.raw_token.is_empty() && cfg.raw_token != username_v1 {
            sends.push((
                "v2".to_string(),
                build_binding_request_with_subs(
                    Some(&cfg.raw_token),
                    Some(&hmac_key),
                    Some(&subs),
                    true,
                    true,
                ),
            ));
        }
        sends.push((
            "v3".to_string(),
            build_minimal_binding_with_subs(&subs, false),
        ));

        let mut all_self = vec![cfg.self_ssrc];
        if let Some(v) = cfg.self_video_ssrc {
            all_self.push(v);
        }
        all_self.extend(cfg.self_aux_ssrcs.iter().copied());
        let mut all_peer = cfg.peer_ssrcs.clone();
        all_peer.extend(cfg.peer_video_ssrcs.iter().copied());
        let ssrc_list = build_ssrc_subscription_list(
            &all_self,
            &all_peer,
            cfg.self_pid.unwrap_or(0),
            cfg.peer_pid.unwrap_or(0),
            false,
        );
        sends.push((
            "v4-alloc".to_string(),
            build_allocate_for_relay(
                &cfg.raw_token,
                &ssrc_list,
                &hmac_key,
                Some(&cfg.ip),
                Some(cfg.port),
            ),
        ));

        let socket = {
            let conns = self.connections.lock().await;
            let Some(conn) = conns.get(id) else {
                return;
            };
            conn.socket.clone()
        };
        let dest = (cfg.ip.clone(), cfg.port);
        for (_v, payload) in sends {
            let _ = socket.send_to(&payload, dest.clone()).await;
        }
        if self.debug {
            tracing::debug!(%label, relay = %cfg.relay_name, "subscriptions (handle)");
        }
    }

    async fn handle_packet(&self, id: &str, _addr: SocketAddr, data: &[u8]) {
        let mut conns = self.connections.lock().await;
        let Some(conn) = conns.get_mut(id) else {
            return;
        };
        conn.stats.received_packets += 1;

        if is_stun_packet(data) && data.len() >= 20 {
            if let Some(info) = parse_stun_response(data) {
                if info.is_success && info.method == "allocate" {
                    conn.allocate_success = true;
                }
                if info.is_success && info.method == "binding" {
                    conn.binding_success = true;
                }
                if let Some(cid) = info.stable_routing_conn_id {
                    if conn.stable_routing_conn_id == 0 {
                        conn.stable_routing_conn_id = cid;
                    }
                }
            }
            return;
        }

        if is_rtp_packet(data) {
            conn.stats.rtp_recv += 1;
            let ip = conn.config.ip.clone();
            let port = conn.config.port;
            let data = data.to_vec();
            drop(conns);
            let _ = self.events.send(UdpRelayEvent::Data { ip, port, data });
        }
    }
}
