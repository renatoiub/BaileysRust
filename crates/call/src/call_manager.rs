//! `NativeCallManager` — orquestração da chamada (port de
//! `services/call/call-manager.ts`).
//!
//! Fase 4: fluxo completo de signaling + mídia (SRTP/relays/codec). O socket
//! WhatsApp é abstraído por [`CallSocket`], permitindo que a Fase 5 (container)
//! injete o `Client` real.

use std::sync::Arc;
use tokio::sync::Mutex;

use baileys_core::BinaryNode;

use crate::audio::AudioEngine;
use crate::encryption::{derive_per_jid_srtp_key, generate_call_key, generate_secure_ssrc};
use crate::mlow::MlowCodec;
use crate::rtp::RtpSession;
use crate::signaling::{
    build_accept_stanza, build_accepted_elsewhere_stanza, build_mute_v2_stanza,
    build_offer_stanza, build_preaccept_stanza, build_reject_stanza, build_relay_latency_stanza,
    build_terminate_stanza, build_transport_stanza, encode_call_message, extract_node_info,
    extract_relay_endpoints, generate_call_id, needs_decryption,
};
use crate::srtp::SrtpSession;
use crate::state::{CallInfo, CallTransition};
use crate::types::{
    CallMediaType, CallOfferOptions, CallState, EndCallReason, RelayEndpoint,
    RelayData, SRTP_AUTH_TAG_LEN,
};
use crate::udp_relay::{UdpRelayConfig, UdpRelayMode, UdpRelayTransport};

/// Abstração do socket WhatsApp para o CallManager.
///
/// O container implementa isto em cima do `baileys_socket::Client`.
pub trait CallSocket: Send + Sync {
    fn me_id(&self) -> String;
    fn me_lid(&self) -> Option<String>;
    fn account_bytes(&self) -> Option<Vec<u8>>;
    /// Envia um nó (fire-and-forget).
    fn send_node(&self, node: &BinaryNode) -> Result<(), String>;
    /// Criptografa mensagem E2E para um JID (retorna (type, ciphertext)).
    fn encrypt_message(&self, jid: &str, data: &[u8]) -> Result<(String, Vec<u8>), String>;
    /// Descriptografa mensagem E2E de um JID.
    fn decrypt_message(&self, jid: &str, enc_type: &str, ciphertext: &[u8])
        -> Result<Vec<u8>, String>;
    /// Busca o LID de um JID (opcional; retorna None se indisponível).
    fn get_lid(&self, jid: &str) -> Option<String>;
}

/// Erros do call manager.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("a call is already in progress")]
    CallInProgress,
    #[error("no call with id {0}")]
    NoSuchCall(String),
    #[error("call {0} cannot be accepted in state {1}")]
    CannotAccept(String, String),
    #[error("call {0} cannot be rejected in state {1}")]
    CannotReject(String, String),
    #[error("no incoming call")]
    NoIncomingCall,
    #[error("socket: {0}")]
    Socket(String),
    #[error("codec: {0}")]
    Codec(#[from] crate::mlow::MlowError),
    #[error("srtp: {0}")]
    Srtp(#[from] crate::srtp::SrtpError),
    #[error("state: {0}")]
    State(#[from] crate::state::InvalidTransition),
    #[error("no call key — impossível aceitar")]
    NoCallKey,
    #[error("no relay endpoints")]
    NoRelayEndpoints,
}

/// Eventos emitidos pelo CallManager.
#[derive(Debug, Clone)]
pub enum CallEvent {
    StateChanged { call_id: String, state: CallState },
    AudioData { call_id: String, pcm: Vec<f32> },
    Error { message: String },
    /// Nó de signaling a enviar (emitido para o container encaminhar).
    SendNode(BinaryNode),
}

/// Gerenciador nativo de chamada.
pub struct NativeCallManager {
    socket: Arc<dyn CallSocket>,
    debug: bool,

    current_call: Mutex<Option<CallInfo>>,
    rtp_session: Mutex<Option<RtpSession>>,
    srtp_session: Mutex<Option<SrtpSession>>,
    codec: Mutex<Option<MlowCodec>>,

    udp_relay: Arc<UdpRelayTransport>,
    audio_engine: Arc<AudioEngine>,

    self_ssrc: Mutex<u32>,
    peer_ssrcs: Mutex<Vec<u32>>,

    events: tokio::sync::broadcast::Sender<CallEvent>,
}

impl NativeCallManager {
    pub fn new(socket: Arc<dyn CallSocket>, debug: bool) -> Self {
        let (events, _) = tokio::sync::broadcast::channel(512);
        Self {
            socket,
            debug,
            current_call: Mutex::new(None),
            rtp_session: Mutex::new(None),
            srtp_session: Mutex::new(None),
            codec: Mutex::new(None),
            udp_relay: Arc::new(UdpRelayTransport::new(debug)),
            audio_engine: Arc::new(AudioEngine::new(Default::default())),
            self_ssrc: Mutex::new(0),
            peer_ssrcs: Mutex::new(Vec::new()),
            events,
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CallEvent> {
        self.events.subscribe()
    }

    pub fn audio_engine(&self) -> &Arc<AudioEngine> {
        &self.audio_engine
    }

    pub fn udp_relay(&self) -> &Arc<UdpRelayTransport> {
        &self.udp_relay
    }

    pub async fn current_call(&self) -> Option<CallInfo> {
        self.current_call.lock().await.clone()
    }

    /// Inicia uma chamada (outgoing).
    pub async fn start_call(&self, options: CallOfferOptions) -> Result<String, CallError> {
        {
            let cur = self.current_call.lock().await;
            if let Some(c) = cur.as_ref() {
                if !c.is_ended() {
                    return Err(CallError::CallInProgress);
                }
            }
        }

        let call_id = generate_call_id();
        let media_type = if options.is_video {
            CallMediaType::Video
        } else {
            CallMediaType::Audio
        };

        let me_lid = self.socket.me_lid();
        let me_id = self.socket.me_id();
        let call_creator = crate::signaling::ensure_device_jid(&me_lid.unwrap_or_else(|| me_id.clone()));

        let call_key = generate_call_key();
        let self_device = call_creator.clone();
        let ssrc = generate_secure_ssrc(&call_id, &self_device, 0);
        let peer_ssrc = generate_secure_ssrc(&call_id, &crate::signaling::ensure_device_jid(&options.peer_jid), 0);

        *self.self_ssrc.lock().await = ssrc;
        *self.peer_ssrcs.lock().await = vec![peer_ssrc];
        *self.rtp_session.lock().await = Some(RtpSession::whatsapp_opus(ssrc));

        // Codec MLow (a lib nativa pode não existir em ambiente de teste —
        // nesse caso seguimos sem codec e o fluxo de mídia é injetado depois).
        match MlowCodec::new(Default::default()) {
            Ok(codec) => {
                *self.codec.lock().await = Some(codec);
            }
            Err(_) => {
                if self.debug {
                    tracing::debug!("libopus_mlow indisponível; codec será injetado depois");
                }
            }
        }

        let mut call = CallInfo::new_outgoing(
            call_id.clone(),
            options.peer_jid.clone(),
            call_creator.clone(),
            media_type,
        );
        call.encryption_key = Some(call_key.clone());

        // Build offer: destinations vazio por ora (a Fase 5 resolve devices).
        let offer = build_offer_stanza(
            &call_id,
            &call_key,
            &options.peer_jid,
            &call_creator,
            options.is_video,
            Some(&me_id),
            Vec::new(),
            false,
            self.socket.account_bytes(),
            None,
        );
        self.socket.send_node(&offer).map_err(CallError::Socket)?;

        call.apply_transition(CallTransition::OfferSent)?;
        *self.current_call.lock().await = Some(call.clone());
        let _ = self.events.send(CallEvent::StateChanged {
            call_id: call_id.clone(),
            state: CallState::Ringing,
        });

        Ok(call_id)
    }

    /// Aceita uma chamada (incoming).
    pub async fn accept_call(&self, call_id: &str) -> Result<(), CallError> {
        let mut cur = self.current_call.lock().await;
        let Some(call) = cur.as_mut() else {
            return Err(CallError::NoSuchCall(call_id.to_string()));
        };
        if call.call_id != call_id {
            return Err(CallError::NoSuchCall(call_id.to_string()));
        }
        if !call.can_accept() {
            return Err(CallError::CannotAccept(
                call_id.to_string(),
                call.state_data.state.as_str().to_string(),
            ));
        }

        let call_key = call
            .encryption_key
            .clone()
            .ok_or(CallError::NoCallKey)?;
        let call_creator = call.call_creator.clone();
        let peer_jid = call.peer_jid.clone();
        let is_video = call.media_type == CallMediaType::Video;

        call.apply_transition(CallTransition::LocalAccepted)?;

        // 1) Accept cifrado para o device do caller.
        let target_device = crate::signaling::ensure_device_jid(&call_creator);
        let bytes = encode_call_message(&call_key);
        let (enc_type, ciphertext) = self
            .socket
            .encrypt_message(&target_device, &bytes)
            .map_err(CallError::Socket)?;
        let enc_node = baileys_core::BinaryNode::new("enc")
            .with_attr("v", "2")
            .with_attr("type", &enc_type)
            .with_bytes(ciphertext);

        let to_jid = crate::signaling::jid_base(&call_creator);
        let accept = build_accept_stanza(
            &call.call_id,
            &call_creator,
            &to_jid,
            is_video,
            enc_node,
            enc_type == "pkmsg",
            self.socket.account_bytes(),
        );
        self.socket.send_node(&accept).map_err(CallError::Socket)?;

        // 2) Deriva SRTP.
        self.init_srtp_keys(&call_key, &target_device).await?;

        // 3) Conecta relays da oferta.
        if let Some(relay_data) = &call.relay_data {
            if !relay_data.endpoints.is_empty() {
                self.connect_relays(relay_data.endpoints.clone()).await?;
            }
        }
        // 4) Sinais pós-accept.
        self.send_post_accept_signals(&peer_jid, &call.call_id, &call_creator)
            .await?;

        let _ = self.events.send(CallEvent::StateChanged {
            call_id: call.call_id.clone(),
            state: CallState::Connecting,
        });

        Ok(())
    }

    /// Rejeita uma chamada.
    pub async fn reject_call(&self, call_id: &str) -> Result<(), CallError> {
        let mut cur = self.current_call.lock().await;
        let Some(call) = cur.as_mut() else {
            return Err(CallError::NoSuchCall(call_id.to_string()));
        };
        if call.call_id != call_id || !call.can_reject() {
            return Err(CallError::CannotReject(
                call_id.to_string(),
                call.state_data.state.as_str().to_string(),
            ));
        }

        let stanza = build_reject_stanza(&call.peer_jid, &call.call_id, &call.call_creator);
        self.socket.send_node(&stanza).map_err(CallError::Socket)?;
        call.apply_transition(CallTransition::LocalRejected {
            reason: EndCallReason::Declined,
        })?;
        let _ = self.events.send(CallEvent::StateChanged {
            call_id: call.call_id.clone(),
            state: CallState::Ended,
        });
        Ok(())
    }

    /// Encerra uma chamada ativa.
    pub async fn end_call(&self, call_id: &str) -> Result<(), CallError> {
        let mut cur = self.current_call.lock().await;
        let Some(call) = cur.as_mut() else {
            return Err(CallError::NoSuchCall(call_id.to_string()));
        };
        if call.call_id != call_id || call.is_ended() {
            return Ok(());
        }

        let stanza = build_terminate_stanza(&call.peer_jid, &call.call_id, &call.call_creator);
        self.socket.send_node(&stanza).map_err(CallError::Socket)?;
        call.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })?;
        let _ = self.events.send(CallEvent::StateChanged {
            call_id: call.call_id.clone(),
            state: CallState::Ended,
        });
        Ok(())
    }

    /// Processa um nó de call recebido do socket (offer/accept/terminate/...).
    pub async fn dispatch_call_node(&self, node: &BinaryNode) -> Result<(), CallError> {
        let Some(info) = extract_node_info(node) else {
            return Ok(());
        };

        match info.tag.as_str() {
            "offer" => self.handle_offer(node, &info).await,
            "accept" => self.handle_accept(node, &info).await,
            "terminate" => self.handle_terminate(&info).await,
            "reject" => self.handle_reject(&info).await,
            "preaccept" => {
                let ack = crate::signaling::create_call_ack(
                    node.attr("id").unwrap_or_default(),
                    &info.peer_jid,
                    "preaccept",
                );
                self.socket.send_node(&ack).map_err(CallError::Socket)?;
                Ok(())
            }
            "relaylatency" => Ok(()),
            "transport" => Ok(()),
            "mute_v2" => Ok(()),
            _ => Ok(()),
        }
    }

    async fn handle_offer(&self, node: &BinaryNode, info: &crate::types::NodeInfo) -> Result<(), CallError> {
        // Extrai relays do nó `<offer>` (inner), não do wrapper `<call>`.
        let relays = extract_relay_endpoints(&info.inner_node);
        let call_id = info.call_id.clone();
        let call_creator = info.inner_node.attr("call-creator").unwrap_or(&info.peer_jid).to_string();

        let is_video = info
            .inner_node
            .children("video")
            .first()
            .is_some();

        let mut call = CallInfo::new_incoming(
            call_id.clone(),
            info.peer_jid.clone(),
            call_creator,
            None,
            if is_video {
                CallMediaType::Video
            } else {
                CallMediaType::Audio
            },
        );
        call.relay_data = Some(RelayData {
            endpoints: relays,
            ..Default::default()
        });

        // Decrypt do callKey se o nó tiver enc.
        if let Some(decrypted) = self.decrypt_call_key(node, &info.peer_jid).await {
            call.encryption_key = Some(decrypted);
        }

        *self.current_call.lock().await = Some(call.clone());
        let _ = self.events.send(CallEvent::StateChanged {
            call_id,
            state: CallState::IncomingRinging,
        });
        Ok(())
    }

    async fn handle_accept(&self, node: &BinaryNode, info: &crate::types::NodeInfo) -> Result<(), CallError> {
        let call_id = info.call_id.clone();
        let mut cur = self.current_call.lock().await;
        let Some(call) = cur.as_mut() else {
            return Ok(());
        };
        if call.call_id != call_id {
            return Ok(());
        }

        if needs_decryption("accept") {
            if let Some(decrypted) = self.decrypt_call_key(node, &info.peer_jid).await {
                // A chave do accept deve coincidir com a da oferta.
                if call.encryption_key.is_none() {
                    call.encryption_key = Some(decrypted);
                }
            }
        }

        call.apply_transition(CallTransition::RemoteAccepted)?;

        // Deriva SRTP e conecta relays.
        if let Some(key) = call.encryption_key.clone() {
            let peer_device = crate::signaling::ensure_device_jid(&call.call_creator);
            self.init_srtp_keys(&key, &peer_device).await?;
        }

        let _ = self.events.send(CallEvent::StateChanged {
            call_id,
            state: CallState::Connecting,
        });
        Ok(())
    }

    async fn handle_terminate(&self, info: &crate::types::NodeInfo) -> Result<(), CallError> {
        let call_id = info.call_id.clone();
        let mut cur = self.current_call.lock().await;
        if let Some(call) = cur.as_mut() {
            if call.call_id == call_id && !call.is_ended() {
                let reason = match info.inner_node.attr("reason") {
                    Some("accepted_elsewhere") => EndCallReason::AcceptedElsewhere,
                    Some("busy") => EndCallReason::Busy,
                    Some("declined") => EndCallReason::Declined,
                    Some("timeout") => EndCallReason::Timeout,
                    _ => EndCallReason::Unknown,
                };
                let _ = call.apply_transition(CallTransition::Terminated { reason });
            }
        }
        let _ = self.events.send(CallEvent::StateChanged {
            call_id,
            state: CallState::Ended,
        });
        Ok(())
    }

    async fn handle_reject(&self, info: &crate::types::NodeInfo) -> Result<(), CallError> {
        let call_id = info.call_id.clone();
        let mut cur = self.current_call.lock().await;
        if let Some(call) = cur.as_mut() {
            if call.call_id == call_id && !call.is_ended() {
                let _ = call.apply_transition(CallTransition::RemoteRejected {
                    reason: EndCallReason::Declined,
                });
            }
        }
        let _ = self.events.send(CallEvent::StateChanged {
            call_id,
            state: CallState::Ended,
        });
        Ok(())
    }

    async fn decrypt_call_key(&self, node: &BinaryNode, peer_jid: &str) -> Option<Vec<u8>> {
        let socket = self.socket.clone();
        let decrypt = move |jid: &str, enc_type: &str, data: &[u8]| {
            socket.decrypt_message(jid, enc_type, data)
        };
        crate::signaling::decrypt_call_key_in_node(&decrypt, node, peer_jid)
            .ok()
            .map(|(_, key)| key)
    }

    async fn init_srtp_keys(&self, call_key: &[u8], device_jid: &str) -> Result<(), CallError> {
        let keying = derive_per_jid_srtp_key(call_key, device_jid)
            .map_err(|_| CallError::Srtp(crate::srtp::SrtpError::InvalidKeying))?;
        // send = recv (chave por JID; o WA usa o mesmo material nos dois sentidos
        // para o fluxo básico). O TS usa o mesmo derivePerJidSrtpKey para ambos.
        let session = SrtpSession::new(
            &keying,
            &keying,
            Some(SRTP_AUTH_TAG_LEN),
            Some(SRTP_AUTH_TAG_LEN),
        )?;
        *self.srtp_session.lock().await = Some(session);
        Ok(())
    }

    async fn connect_relays(&self, endpoints: Vec<RelayEndpoint>) -> Result<(), CallError> {
        let self_ssrc = *self.self_ssrc.lock().await;
        let peer_ssrcs = self.peer_ssrcs.lock().await.clone();

        let configs: Vec<UdpRelayConfig> = endpoints
            .into_iter()
            .map(|e| UdpRelayConfig {
                ip: e.ip,
                port: e.port,
                raw_token: e.token.as_bytes().to_vec(),
                raw_auth_token: e.auth_token.map(|t| t.as_bytes().to_vec()),
                relay_key: e.key.as_bytes().to_vec(),
                relay_key_string: e.key,
                relay_id: e.relay_id,
                relay_name: e.relay_name.unwrap_or_default(),
                self_ssrc,
                peer_ssrcs: peer_ssrcs.clone(),
                self_pid: None,
                peer_pid: None,
                self_video_ssrc: None,
                peer_video_ssrcs: Vec::new(),
                self_aux_ssrcs: Vec::new(),
                mode: UdpRelayMode::Allocate,
            })
            .collect();

        if configs.is_empty() {
            return Err(CallError::NoRelayEndpoints);
        }

        self.udp_relay.connect_all(&configs).await;
        Ok(())
    }

    async fn send_post_accept_signals(
        &self,
        peer_jid: &str,
        call_id: &str,
        call_creator: &str,
    ) -> Result<(), CallError> {
        let me_id = self.socket.me_id();

        // Transport.
        let transport = build_transport_stanza(peer_jid, call_id, call_creator, Some(&me_id));
        self.socket.send_node(&transport).map_err(CallError::Socket)?;

        // Mute off (mute-state 0 = unmuted).
        let mute = build_mute_v2_stanza(
            &crate::signaling::ensure_device_jid(call_creator),
            call_id,
            call_creator,
            0,
            Some(&me_id),
        );
        self.socket.send_node(&mute).map_err(CallError::Socket)?;
        Ok(())
    }

    /// Notifica irmãos da mesma conta (accepted_elsewhere).
    pub async fn notify_own_devices_accepted_elsewhere(
        &self,
        call_id: &str,
        devices: &[String],
    ) -> Result<(), CallError> {
        let cur = self.current_call.lock().await;
        let Some(call) = cur.as_ref() else {
            return Ok(());
        };
        for device in devices {
            let stanza = build_accepted_elsewhere_stanza(device, call_id, &call.call_creator);
            self.socket.send_node(&stanza).map_err(CallError::Socket)?;
        }
        Ok(())
    }

    /// Envia relaylatency (após eleger relays).
    pub async fn send_relay_latency(
        &self,
        peer_jid: &str,
        call_id: &str,
        call_creator: &str,
        relays: &[(String, u32)],
    ) -> Result<(), CallError> {
        let me_id = self.socket.me_id();
        let data: Vec<(String, u32, Option<Vec<u8>>)> = relays
            .iter()
            .map(|(name, latency)| (name.clone(), *latency, None))
            .collect();
        let stanza = build_relay_latency_stanza(
            peer_jid,
            call_id,
            call_creator,
            &data,
            &[],
            Some(&me_id),
        );
        self.socket.send_node(&stanza).map_err(CallError::Socket)?;
        Ok(())
    }

    /// Pré-aceite (caller envia preaccept ao receber relaylatency).
    pub async fn send_preaccept(
        &self,
        peer_jid: &str,
        call_id: &str,
        call_creator: &str,
    ) -> Result<(), CallError> {
        let stanza = build_preaccept_stanza(peer_jid, call_id, call_creator);
        self.socket.send_node(&stanza).map_err(CallError::Socket)?;
        Ok(())
    }

    pub async fn is_call_active(&self) -> bool {
        match self.current_call.lock().await.as_ref() {
            Some(c) => c.is_active(),
            None => false,
        }
    }

    /// `setExternalAudioMode` — alimenta o áudio via WS do player (não arquivo).
    pub fn set_external_audio_mode(&self, enabled: bool) {
        self.audio_engine.set_external_mode(enabled);
    }

    /// `feedLiveAudio` — injeta PCM f32 (do WS binário do player).
    pub fn feed_live_audio(&self, samples: &[f32]) {
        self.audio_engine.feed_external_audio(samples);
    }

    /// `setMute` — muta/desmuta a chamada ativa (silence mode + mute_v2).
    pub async fn set_mute(&self, muted: bool) -> Result<(), CallError> {
        {
            let mut cur = self.current_call.lock().await;
            let Some(call) = cur.as_mut() else {
                return Ok(());
            };
            if !call.is_active() {
                return Ok(());
            }
            if let Err(e) = call.apply_transition(CallTransition::AudioMuteChanged { muted }) {
                // Não propaga transição inválida — o player tolera.
                let _ = e;
            }
        }

        self.audio_engine.set_silence_mode(muted);

        // Envia `mute_v2` para o peer (paridade `setMute` do TS).
        let (peer_jid, call_id, call_creator) = {
            let cur = self.current_call.lock().await;
            match cur.as_ref() {
                Some(c) => (c.peer_jid.clone(), c.call_id.clone(), c.call_creator.clone()),
                None => return Ok(()),
            }
        };
        let me_id = self.socket.me_id();
        let stanza = build_mute_v2_stanza(
            &crate::signaling::ensure_device_jid(&call_creator),
            &call_id,
            &call_creator,
            if muted { 1 } else { 0 },
            Some(&me_id),
        );
        self.socket.send_node(&stanza).map_err(CallError::Socket)?;

        let _ = self.events.send(CallEvent::StateChanged {
            call_id,
            state: CallState::Active,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CallDirection;

    struct TestSocket {
        me_id: String,
    }

    impl CallSocket for TestSocket {
        fn me_id(&self) -> String {
            self.me_id.clone()
        }
        fn me_lid(&self) -> Option<String> {
            None
        }
        fn account_bytes(&self) -> Option<Vec<u8>> {
            None
        }
        fn send_node(&self, _node: &BinaryNode) -> Result<(), String> {
            Ok(())
        }
        fn encrypt_message(&self, _jid: &str, data: &[u8]) -> Result<(String, Vec<u8>), String> {
            Ok(("msg".to_string(), data.to_vec()))
        }
        fn decrypt_message(
            &self,
            _jid: &str,
            _enc_type: &str,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, String> {
            Ok(ciphertext.to_vec())
        }
        fn get_lid(&self, _jid: &str) -> Option<String> {
            None
        }
    }

    #[tokio::test]
    async fn start_call_sends_offer() {
        let socket = Arc::new(TestSocket {
            me_id: "5511999999999:0@s.whatsapp.net".to_string(),
        });
        let mgr = NativeCallManager::new(socket, false);
        let id = mgr
            .start_call(CallOfferOptions {
                peer_jid: "5511888888888@s.whatsapp.net".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(id.len(), 32);
        let call = mgr.current_call().await.unwrap();
        assert_eq!(call.direction, CallDirection::Outgoing);
        assert_eq!(call.state_data.state, CallState::Ringing);
    }

    #[tokio::test]
    async fn dispatch_offer_creates_incoming() {
        let socket = Arc::new(TestSocket {
            me_id: "5511999999999:0@s.whatsapp.net".to_string(),
        });
        let mgr = NativeCallManager::new(socket, false);

        let offer = BinaryNode::new("call")
            .with_attr("from", "5511888888888@s.whatsapp.net")
            .with_attr("id", "MSG-1")
            .with_children(vec![
                BinaryNode::new("offer")
                    .with_attr("call-id", "CALLID")
                    .with_attr("call-creator", "5511888888888:0@s.whatsapp.net")
                    .with_children(vec![
                        BinaryNode::new("audio").with_attr("enc", "opus").with_attr("rate", "16000"),
                        BinaryNode::new("net").with_attr("medium", "3"),
                    ]),
            ]);

        mgr.dispatch_call_node(&offer).await.unwrap();
        let call = mgr.current_call().await.unwrap();
        assert_eq!(call.direction, CallDirection::Incoming);
        assert_eq!(call.state_data.state, CallState::IncomingRinging);
    }
}
