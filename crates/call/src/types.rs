//! Tipos e constantes de chamada (port de `services/call/types.ts`).

use baileys_core::BinaryNode;

/// Estado de uma chamada em andamento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Initiating,
    Ringing,
    IncomingRinging,
    Connecting,
    Active,
    OnHold,
    Ended,
}

impl CallState {
    pub fn as_str(self) -> &'static str {
        match self {
            CallState::Initiating => "initiating",
            CallState::Ringing => "ringing",
            CallState::IncomingRinging => "incoming_ringing",
            CallState::Connecting => "connecting",
            CallState::Active => "active",
            CallState::OnHold => "on_hold",
            CallState::Ended => "ended",
        }
    }
}

/// Direção da chamada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    Outgoing,
    Incoming,
}

impl CallDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            CallDirection::Outgoing => "outgoing",
            CallDirection::Incoming => "incoming",
        }
    }
}

/// Tipo de mídia da chamada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMediaType {
    Audio,
    Video,
}

impl CallMediaType {
    pub fn as_str(self) -> &'static str {
        match self {
            CallMediaType::Audio => "audio",
            CallMediaType::Video => "video",
        }
    }
}

/// Motivo de término.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndCallReason {
    UserEnded,
    Declined,
    Timeout,
    Busy,
    Cancelled,
    Failed,
    DoNotDisturb,
    /// Atendida noutro device da mesma conta — siblings devem parar de tocar.
    AcceptedElsewhere,
    Unknown,
}

impl EndCallReason {
    pub fn as_str(self) -> &'static str {
        match self {
            EndCallReason::UserEnded => "user_ended",
            EndCallReason::Declined => "declined",
            EndCallReason::Timeout => "timeout",
            EndCallReason::Busy => "busy",
            EndCallReason::Cancelled => "cancelled",
            EndCallReason::Failed => "failed",
            EndCallReason::DoNotDisturb => "do_not_disturb",
            EndCallReason::AcceptedElsewhere => "accepted_elsewhere",
            EndCallReason::Unknown => "unknown",
        }
    }
}

/// Material de chaveamento SRTP.
#[derive(Debug, Clone)]
pub struct SrtpKeyingMaterial {
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
}

/// Payload types usados.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    WhatsAppOpus = 120,
}

/// Configuração RTP.
#[derive(Debug, Clone)]
pub struct RtpConfig {
    pub ssrc: u32,
    pub payload_type: u8,
    pub sample_rate: u32,
    pub samples_per_packet: u32,
}

/// Info de relay (nó `<relay>`).
#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    pub ip: String,
    pub port: u16,
    pub token: String,
    pub auth_token: Option<String>,
    pub raw_auth_token: Option<Vec<u8>>,
    pub raw_token: Option<Vec<u8>>,
    pub key: String,
    pub relay_id: u32,
    pub protocol: Option<u32>,
    pub c2r_rtt: Option<u32>,
    pub relay_name: Option<String>,
    pub address_bytes: Option<Vec<u8>>,
    pub auth_token_id: Option<String>,
}

/// Dados de relay agregados de uma oferta.
#[derive(Debug, Clone, Default)]
pub struct RelayData {
    pub endpoints: Vec<RelayEndpoint>,
    pub participant_jids: Vec<String>,
    pub uuid: Option<String>,
    pub self_pid: Option<u32>,
    pub peer_pid: Option<u32>,
    pub hbh_key: Option<Vec<u8>>,
}

/// Info extraída de um nó de call (`extractNodeInfo`).
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub tag: String,
    pub peer_jid: String,
    pub call_id: String,
    pub peer_platform: String,
    pub peer_app_version: String,
    pub epoch_id: Option<String>,
    pub timestamp: Option<String>,
    pub inner_node: BinaryNode,
}

/// Opções para iniciar chamada.
#[derive(Debug, Clone, Default)]
pub struct CallOfferOptions {
    pub peer_jid: String,
    pub is_video: bool,
    pub audio_file: Option<String>,
    pub peer_devices: Vec<String>,
}

/// Constantes SRTP.
pub const SRTP_SEND_AUTH_TAG_LEN: usize = 4;
pub const SRTP_RECV_AUTH_TAG_LEN: usize = 4;
/// WhatsApp usa 32-bit (4-byte) SRTP auth tags.
pub const SRTP_AUTH_TAG_LEN: usize = 4;

/// Rótulos de derivação SRTP (RFC 3711 §4.3.1).
pub const SRTP_LABEL_ENCRYPTION: u8 = 0x00;
pub const SRTP_LABEL_AUTH: u8 = 0x01;
pub const SRTP_LABEL_SALT: u8 = 0x02;

/// Porta de relay do web client verdadeiro.
pub const WA_RELAY_PORT: u16 = 3480;

/// Fingerprint DTLS fixa do relay do WhatsApp.
pub const WA_DTLS_FINGERPRINT: &str =
    "sha-256 F9:CA:0C:98:A3:CC:71:D6:42:CE:5A:E2:53:D2:15:20:D3:1B:BA:D8:57:A4:F0:AF:BE:0B:FB:F3:6B:0C:A0:68";

/// Configuração padrão do AudioEngine.
#[derive(Debug, Clone)]
pub struct AudioEngineConfig {
    pub sample_rate: usize,
    pub capture_chunk_size: usize,
    pub playback_output_size: usize,
    pub max_buffer_size: usize,
    pub interval_ms: u64,
}

impl Default for AudioEngineConfig {
    fn default() -> Self {
        Self {
            sample_rate: 16000,
            capture_chunk_size: 320,
            playback_output_size: 256,
            max_buffer_size: 1600,
            interval_ms: 20,
        }
    }
}
