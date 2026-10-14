//! STUN — builders/parsers (port de `services/call/stun.ts`).

use rand::RngCore;

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_FINGERPRINT_XOR: u32 = 0x5354554E;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_ALLOCATE_REQUEST: u16 = 0x0003;
const WHATSAPP_PING: u16 = 0x0801;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_PRIORITY: u16 = 0x0024;
const ATTR_SENDER_SUBSCRIPTIONS: u16 = 0x4000;
const ATTR_SSRC_LIST: u16 = 0x4024;
const ATTR_ICE_CONTROLLED: u16 = 0x8029;
const ATTR_ICE_CONTROLLING: u16 = 0x802A;
const ATTR_FINGERPRINT: u16 = 0x8028;

const DEFAULT_ICE_PRIORITY: u32 = 16_777_215;

fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

fn encode_attribute(attr_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() + 3);
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    let padding = (4 - (data.len() % 4)) % 4;
    out.extend(std::iter::repeat(0u8).take(padding));
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    (crc ^ 0xFFFFFFFF) as u32
}

fn build_stun_message(
    msg_type: u16,
    attrs: Vec<u8>,
    transaction_id: [u8; 12],
    integrity_key: Option<&[u8]>,
    include_fingerprint: bool,
) -> Vec<u8> {
    let mut attrs_data = attrs;

    if let Some(key) = integrity_key {
        let msg_len_for_hmac = (attrs_data.len() + 24) as u16;
        let mut hmac_header = Vec::with_capacity(20);
        hmac_header.extend_from_slice(&msg_type.to_be_bytes());
        hmac_header.extend_from_slice(&msg_len_for_hmac.to_be_bytes());
        hmac_header.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        hmac_header.extend_from_slice(&transaction_id);

        let mut hmac_input = hmac_header;
        hmac_input.extend_from_slice(&attrs_data);

        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_from_slice(key).expect("hmac key");
        mac.update(&hmac_input);
        let digest = mac.finalize().into_bytes().to_vec();

        let mi_attr = encode_attribute(ATTR_MESSAGE_INTEGRITY, &digest);
        attrs_data.extend_from_slice(&mi_attr);
    }

    if include_fingerprint {
        let msg_len_for_crc = (attrs_data.len() + 8) as u16;
        let mut crc_header = Vec::with_capacity(20);
        crc_header.extend_from_slice(&msg_type.to_be_bytes());
        crc_header.extend_from_slice(&msg_len_for_crc.to_be_bytes());
        crc_header.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        crc_header.extend_from_slice(&transaction_id);

        let mut crc_input = crc_header;
        crc_input.extend_from_slice(&attrs_data);

        let fingerprint = crc32(&crc_input) ^ STUN_FINGERPRINT_XOR;
        let fp_attr = encode_attribute(ATTR_FINGERPRINT, &fingerprint.to_be_bytes());
        attrs_data.extend_from_slice(&fp_attr);
    }

    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&msg_type.to_be_bytes());
    header.extend_from_slice(&(attrs_data.len() as u16).to_be_bytes());
    header.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    header.extend_from_slice(&transaction_id);

    header.extend_from_slice(&attrs_data);
    header
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value > 0x7F {
        bytes.push(((value & 0x7F) | 0x80) as u8);
        value >>= 7;
    }
    bytes.push((value & 0x7F) as u8);
    bytes
}

fn encode_protobuf_varint_field(field_number: u32, value: u32) -> Vec<u8> {
    let mut out = encode_varint(((field_number << 3) | 0) as u64);
    out.extend_from_slice(&encode_varint(value as u64));
    out
}

fn encode_protobuf_length_delimited(field_number: u32, data: &[u8]) -> Vec<u8> {
    let mut out = encode_varint(((field_number << 3) | 2) as u64);
    out.extend_from_slice(&encode_varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

/// `buildSenderSubscriptions` — protobuf: {1: {3: ssrc, 5: 0, 6: 0}}.
pub fn build_sender_subscriptions(ssrc: u32) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&encode_protobuf_varint_field(3, ssrc));
    inner.extend_from_slice(&encode_protobuf_varint_field(5, 0));
    inner.extend_from_slice(&encode_protobuf_varint_field(6, 0));
    encode_protobuf_length_delimited(1, &inner)
}

/// `buildSSRCSubscriptionList`.
pub fn build_ssrc_subscription_list(
    self_ssrcs: &[u32],
    peer_ssrcs: &[u32],
    self_pid: u32,
    peer_pid: u32,
    peer_pid_wildcard: bool,
) -> Vec<u8> {
    let mut entries: Vec<u8> = Vec::new();

    for &ssrc in self_ssrcs {
        if ssrc == 0 {
            continue;
        }
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_protobuf_varint_field(1, self_pid));
        inner.extend_from_slice(&encode_protobuf_varint_field(2, 1));
        inner.extend_from_slice(&encode_protobuf_varint_field(3, ssrc));
        entries.extend_from_slice(&encode_protobuf_length_delimited(1, &inner));
    }

    if peer_pid_wildcard {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_protobuf_varint_field(1, peer_pid));
        inner.extend_from_slice(&encode_protobuf_varint_field(2, 1));
        entries.extend_from_slice(&encode_protobuf_length_delimited(1, &inner));
    }

    for &ssrc in peer_ssrcs {
        if ssrc == 0 {
            continue;
        }
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_protobuf_varint_field(1, peer_pid));
        inner.extend_from_slice(&encode_protobuf_varint_field(2, 1));
        inner.extend_from_slice(&encode_protobuf_varint_field(3, ssrc));
        entries.extend_from_slice(&encode_protobuf_length_delimited(1, &inner));
    }

    entries
}

fn encode_xor_relayed_address(ip: &str, port: u16) -> Vec<u8> {
    let mut data = vec![0u8; 8];
    data[0] = 0x00;
    data[1] = 0x01;
    data[2..4].copy_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());

    let parts: Vec<u32> = ip
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    if parts.len() == 4 {
        let ip_num = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        data[4..8].copy_from_slice(&(ip_num ^ STUN_MAGIC_COOKIE).to_be_bytes());
    }
    data
}

/// `buildAllocateForRelay`.
pub fn build_allocate_for_relay(
    sender_subscriptions: &[u8],
    ssrc_list: &[u8],
    hmac_key: &[u8],
    relay_ip: Option<&str>,
    relay_port: Option<u16>,
) -> Vec<u8> {
    let transaction_id = generate_transaction_id();
    let mut parts: Vec<u8> = Vec::new();

    parts.extend_from_slice(&encode_attribute(
        ATTR_SENDER_SUBSCRIPTIONS,
        sender_subscriptions,
    ));
    parts.extend_from_slice(&encode_attribute(ATTR_SSRC_LIST, ssrc_list));

    if let (Some(ip), Some(port)) = (relay_ip, relay_port) {
        parts.extend_from_slice(&encode_attribute(
            ATTR_XOR_RELAYED_ADDRESS,
            &encode_xor_relayed_address(ip, port),
        ));
    }

    build_stun_message(STUN_ALLOCATE_REQUEST, parts, transaction_id, Some(hmac_key), false)
}

/// Opções para `buildBindingRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    None,
    Controlling,
    Controlled,
}

/// `buildBindingRequest`.
pub fn build_binding_request(
    username: Option<&[u8]>,
    hmac_key: Option<&[u8]>,
    sender_subscriptions: Option<&[u8]>,
    ice_role: IceRole,
    include_priority: bool,
    include_username: bool,
    include_fingerprint: bool,
) -> Vec<u8> {
    let transaction_id = generate_transaction_id();
    let mut parts: Vec<u8> = Vec::new();

    if include_username {
        if let Some(u) = username {
            parts.extend_from_slice(&encode_attribute(ATTR_USERNAME, u));
        }
    }

    if include_priority {
        parts.extend_from_slice(&encode_attribute(
            ATTR_PRIORITY,
            &DEFAULT_ICE_PRIORITY.to_be_bytes(),
        ));
    }

    if ice_role == IceRole::Controlling || ice_role == IceRole::Controlled {
        let mut tie_breaker = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut tie_breaker);
        let attr_type = if ice_role == IceRole::Controlled {
            ATTR_ICE_CONTROLLED
        } else {
            ATTR_ICE_CONTROLLING
        };
        parts.extend_from_slice(&encode_attribute(attr_type, &tie_breaker));
    }

    if let Some(subs) = sender_subscriptions {
        if !subs.is_empty() {
            parts.extend_from_slice(&encode_attribute(ATTR_SENDER_SUBSCRIPTIONS, subs));
        }
    }

    build_stun_message(
        STUN_BINDING_REQUEST,
        parts,
        transaction_id,
        hmac_key,
        include_fingerprint,
    )
}

/// `buildBindingRequestWithSubs` — variante com subs e ICE controlling.
pub fn build_binding_request_with_subs(
    username: Option<&[u8]>,
    hmac_key: Option<&[u8]>,
    sender_subscriptions: Option<&[u8]>,
    include_ice_controlling: bool,
    include_fingerprint: bool,
) -> Vec<u8> {
    let ice_role = if include_ice_controlling {
        IceRole::Controlling
    } else {
        IceRole::None
    };
    build_binding_request(
        username,
        hmac_key,
        sender_subscriptions,
        ice_role,
        true,
        true,
        include_fingerprint,
    )
}

/// `buildMinimalBindingWithSubs`.
pub fn build_minimal_binding_with_subs(
    sender_subscriptions: &[u8],
    include_fingerprint: bool,
) -> Vec<u8> {
    let transaction_id = generate_transaction_id();
    let attrs = encode_attribute(ATTR_SENDER_SUBSCRIPTIONS, sender_subscriptions);
    build_stun_message(
        STUN_BINDING_REQUEST,
        attrs,
        transaction_id,
        None,
        include_fingerprint,
    )
}

/// `buildMinimalAllocateWithSubs`.
pub fn build_minimal_allocate_with_subs(
    sender_subscriptions: &[u8],
    include_fingerprint: bool,
) -> Vec<u8> {
    let transaction_id = generate_transaction_id();
    let attrs = encode_attribute(ATTR_SENDER_SUBSCRIPTIONS, sender_subscriptions);
    build_stun_message(
        STUN_ALLOCATE_REQUEST,
        attrs,
        transaction_id,
        None,
        include_fingerprint,
    )
}

/// `buildAllocateRequest`.
pub fn build_allocate_request(
    username: &[u8],
    hmac_key: &[u8],
    lifetime: u32,
) -> Vec<u8> {
    let transaction_id = generate_transaction_id();
    let mut parts: Vec<u8> = Vec::new();

    parts.extend_from_slice(&encode_attribute(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]));
    parts.extend_from_slice(&encode_attribute(ATTR_USERNAME, username));
    parts.extend_from_slice(&encode_attribute(ATTR_LIFETIME, &lifetime.to_be_bytes()));

    build_stun_message(
        STUN_ALLOCATE_REQUEST,
        parts,
        transaction_id,
        Some(hmac_key),
        true,
    )
}

/// `buildWhatsAppPing`.
pub fn build_whatsapp_ping() -> Vec<u8> {
    let transaction_id = generate_transaction_id();
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&WHATSAPP_PING.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes());
    header.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    header.extend_from_slice(&transaction_id);
    header
}

/// `isStunPacket`.
pub fn is_stun_packet(data: &[u8]) -> bool {
    data.len() >= 2 && (data[0] & 0xC0) == 0
}

/// `isRtpPacket`.
pub fn is_rtp_packet(data: &[u8]) -> bool {
    data.len() >= 2 && (data[0] & 0xC0) == 0x80
}

/// Atributo STUN parseado.
#[derive(Debug, Clone)]
pub struct StunAttribute {
    pub attr_type: u16,
    pub type_name: String,
    pub length: u16,
    pub data: Vec<u8>,
}

/// Resposta STUN parseada.
#[derive(Debug, Clone)]
pub struct StunResponseInfo {
    pub raw_type: u16,
    pub method: String,
    pub stun_class: String,
    pub is_success: bool,
    pub is_error: bool,
    pub error_code: Option<u16>,
    pub error_reason: Option<String>,
    pub stable_routing_conn_id: Option<u64>,
    pub transaction_id: String,
    pub length: usize,
    pub attributes: Vec<StunAttribute>,
}

fn attr_name(attr_type: u16) -> &'static str {
    match attr_type {
        0x0001 => "MAPPED-ADDRESS",
        0x0006 => "USERNAME",
        0x0008 => "MESSAGE-INTEGRITY",
        0x0009 => "ERROR-CODE",
        0x000A => "UNKNOWN-ATTRIBUTES",
        0x0014 => "REALM",
        0x0015 => "NONCE",
        0x0019 => "REQUESTED-TRANSPORT",
        0x0020 => "XOR-MAPPED-ADDRESS",
        0x0024 => "PRIORITY",
        0x0025 => "USE-CANDIDATE",
        0x4000 => "SENDER-SUBSCRIPTIONS",
        0x4001 => "RECEIVER-SUBSCRIPTION",
        0x4002 => "SUBSCRIPTION-ACK",
        0x8022 => "SOFTWARE",
        0x8028 => "FINGERPRINT",
        0x8029 => "ICE-CONTROLLED",
        0x802A => "ICE-CONTROLLING",
        0x4033 => "STABLE-ROUTING-CONN-ID",
        _ => "UNKNOWN",
    }
}

/// `parseStunResponse`.
pub fn parse_stun_response(data: &[u8]) -> Option<StunResponseInfo> {
    if data.len() < 20 {
        return None;
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type == 0x0801 || msg_type == 0x0802 {
            return Some(StunResponseInfo {
                raw_type: msg_type,
                method: if msg_type == 0x0801 {
                    "wa-ping".to_string()
                } else {
                    "wa-pong".to_string()
                },
                stun_class: "indication".to_string(),
                is_success: false,
                is_error: false,
                error_code: None,
                error_reason: None,
                stable_routing_conn_id: None,
                transaction_id: hex(&data[8..20]),
                length: data.len(),
                attributes: Vec::new(),
            });
        }
        return None;
    }

    let raw_type = u16::from_be_bytes([data[0], data[1]]);
    let msg_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let transaction_id = hex(&data[8..20]);

    let c0 = (raw_type >> 4) & 0x1;
    let c1 = (raw_type >> 8) & 0x1;
    let stun_class_num = (c1 << 1) | c0;
    let stun_class = ["request", "indication", "success", "error"]
        .get(stun_class_num as usize)
        .copied()
        .unwrap_or("unknown")
        .to_string();

    let method_bits =
        ((raw_type & 0x3E00) >> 2) | ((raw_type & 0x00E0) >> 1) | (raw_type & 0x000F);
    let mut method = match method_bits {
        0x001 => "binding",
        0x003 => "allocate",
        0x004 => "refresh",
        0x006 => "send",
        0x007 => "data",
        0x008 => "create-permission",
        0x009 => "channel-bind",
        _ => "unknown",
    }
    .to_string();
    if raw_type == 0x0801 {
        method = "wa-ping".to_string();
    }
    if raw_type == 0x0802 {
        method = "wa-pong".to_string();
    }

    let mut attributes: Vec<StunAttribute> = Vec::new();
    let mut error_code: Option<u16> = None;
    let mut error_reason: Option<String> = None;
    let mut stable_routing_conn_id: Option<u64> = None;
    let mut offset = 20usize;

    while offset + 4 <= 20 + msg_length && offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let attr_end = offset + 4 + attr_length;

        if attr_end > data.len() {
            break;
        }

        let attr_data = data[offset + 4..attr_end].to_vec();
        attributes.push(StunAttribute {
            attr_type,
            type_name: attr_name(attr_type).to_string(),
            length: attr_length as u16,
            data: attr_data.clone(),
        });

        if attr_type == 0x0009 && attr_length >= 4 {
            let error_class = (attr_data[2] & 0x07) as u16;
            let error_number = attr_data[3] as u16;
            error_code = Some(error_class * 100 + error_number);
            if attr_length > 4 {
                error_reason = std::str::from_utf8(&attr_data[4..])
                    .ok()
                    .map(|s| s.to_string());
            }
        }

        if attr_type == 0x4033 && stun_class == "success" && attr_length == 8 {
            stable_routing_conn_id = Some(u64::from_be_bytes([
                attr_data[0], attr_data[1], attr_data[2], attr_data[3], attr_data[4],
                attr_data[5], attr_data[6], attr_data[7],
            ]));
        }

        offset = attr_end + ((4 - (attr_length % 4)) % 4);
    }

    Some(StunResponseInfo {
        raw_type,
        method,
        is_success: stun_class == "success",
        is_error: stun_class == "error",
        stun_class,
        error_code,
        error_reason,
        stable_routing_conn_id,
        transaction_id,
        length: data.len(),
        attributes,
    })
}

/// Classifica um pacote para log/diagnóstico.
pub fn classify_packet(data: &[u8]) -> String {
    if data.len() < 2 {
        return format!("tiny({}B)", data.len());
    }

    let first_byte = data[0];
    let two_bits = (first_byte & 0xC0) >> 6;

    if two_bits == 0 {
        if let Some(info) = parse_stun_response(data) {
            return format!(
                "STUN {} {} (0x{:04X}, {}B)",
                info.method, info.stun_class, info.raw_type, info.length
            );
        }
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        return format!("STUN? 0x{msg_type:04x} ({}B)", data.len());
    }

    if two_bits == 2 {
        let pt = data[1] & 0x7F;
        let marker = (data[1] >> 7) & 1;
        let seq = if data.len() >= 4 {
            u16::from_be_bytes([data[2], data[3]])
        } else {
            0
        };
        return format!("RTP/SRTP PT={pt} M={marker} seq={seq} ({}B)", data.len());
    }

    if two_bits == 1 {
        return format!("DTLS? 0x{first_byte:02x} ({}B)", data.len());
    }

    format!("unknown 0x{first_byte:02x} ({}B)", data.len())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatsapp_ping_layout() {
        let ping = build_whatsapp_ping();
        assert_eq!(ping.len(), 20);
        assert_eq!(u16::from_be_bytes([ping[0], ping[1]]), 0x0801);
        assert_eq!(u32::from_be_bytes([ping[4], ping[5], ping[6], ping[7]]), STUN_MAGIC_COOKIE);
        assert!(is_stun_packet(&ping));
    }

    #[test]
    fn binding_request_has_fingerprint() {
        let req = build_binding_request_with_subs(
            Some(b"user"),
            Some(b"0123456789abcdefghij"),
            Some(&build_sender_subscriptions(0x12345678)),
            true,
            true,
        );
        assert!(is_stun_packet(&req));
        // Deve conter FINGERPRINT no final.
        assert!(req.windows(2).any(|w| u16::from_be_bytes([w[0], w[1]]) == ATTR_FINGERPRINT));
    }

    #[test]
    fn parse_ping() {
        let ping = build_whatsapp_ping();
        let info = parse_stun_response(&ping).unwrap();
        assert_eq!(info.method, "wa-ping");
    }

    #[test]
    fn sender_subscriptions_encodes_ssrc() {
        let subs = build_sender_subscriptions(0x12345678);
        // field 3 = varint: 0x18 (tag) + varint(ssrc)
        assert!(subs.len() >= 6);
    }
}
