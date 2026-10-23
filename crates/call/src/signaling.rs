//! Signaling de chamada (port de `services/call/signaling.ts`).
//!
//! Contém os builders puros de nós (`buildOfferStanza`, `buildAcceptStanza`,
//! `buildTerminateStanza`, etc.) e o parser `extractRelayEndpoints`.
//! As variantes que precisam do socket/`Client` (encrypt/decrypt) ficam
//! assinadas recebendo `&Client` — a Fase 5 liga isto ao container.

use baileys_core::ids::{generate_message_id_v2, unpad_random_max16};
use baileys_core::{BinaryContent, BinaryNode};
use baileys_proto::proto as wa;
use prost::Message;

use crate::types::{NodeInfo, RelayData, RelayEndpoint};

/// `generateCallId` — 16 bytes hex maiúsculo.
pub fn generate_call_id() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// `generateCallStanzaId` — 16 bytes hex maiúsculo.
pub fn generate_call_stanza_id() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// `extractNodeInfo`.
pub fn extract_node_info(node: &BinaryNode) -> Option<NodeInfo> {
    let children = match &node.content {
        Some(BinaryContent::Children(c)) => c,
        _ => return None,
    };
    let inner = children.first()?;

    Some(NodeInfo {
        tag: inner.tag.clone(),
        peer_jid: node.attr("from").unwrap_or_default().to_string(),
        call_id: inner.attr("call-id").unwrap_or_default().to_string(),
        peer_platform: node.attr("platform").unwrap_or_default().to_string(),
        peer_app_version: node.attr("version").unwrap_or_default().to_string(),
        epoch_id: inner.attr("e").map(String::from),
        timestamp: inner.attr("t").map(String::from),
        inner_node: inner.clone(),
    })
}

/// `encodeNodeToBase64`.
pub fn encode_node_to_base64(node: &BinaryNode) -> String {
    use base64::Engine;
    let bytes = baileys_codec::encode_binary_node(node);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `extractRelayEndpoints` — parse de `<relay>` e `<relays>`.
pub fn extract_relay_endpoints(node: &BinaryNode) -> Vec<RelayEndpoint> {
    let mut relays: Vec<RelayEndpoint> = Vec::new();
    let Some(BinaryContent::Children(children)) = &node.content else {
        return relays;
    };

    let push = |relay: &BinaryNode, relays: &mut Vec<RelayEndpoint>| {
        let ip = relay.attr("ip").unwrap_or_default().to_string();
        let port: u16 = relay
            .attr("port")
            .and_then(|p| p.parse().ok())
            .unwrap_or(3480);
        let token = relay.attr("token").unwrap_or_default().to_string();
        let key = relay
            .attr("relay-key")
            .or_else(|| relay.attr("key"))
            .unwrap_or_default()
            .to_string();
        let relay_id: u32 = relay
            .attr("relay-id")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let c2r_rtt = relay.attr("c2r-rtt").and_then(|v| v.parse().ok());

        if !ip.is_empty() && !token.is_empty() {
            relays.push(RelayEndpoint {
                ip,
                port,
                token,
                auth_token: relay.attr("auth-token").map(String::from),
                raw_auth_token: None,
                raw_token: None,
                key,
                relay_id,
                protocol: relay.attr("protocol").and_then(|v| v.parse().ok()),
                c2r_rtt,
                relay_name: relay.attr("name").map(String::from),
                address_bytes: match &relay.content {
                    Some(BinaryContent::Bytes(b)) => Some(b.clone()),
                    _ => None,
                },
                auth_token_id: relay.attr("auth-token-id").map(String::from),
            });
        }
    };

    for child in children {
        match child.tag.as_str() {
            "relay" => push(child, &mut relays),
            "relays" => {
                if let Some(BinaryContent::Children(sub)) = &child.content {
                    for r in sub {
                        if r.tag == "relay" {
                            push(r, &mut relays);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    relays.sort_by_key(|r| r.c2r_rtt.unwrap_or(u32::MAX));
    relays
}

/// Bytes de um nó (binário ou texto).
fn node_bytes(node: &BinaryNode) -> Option<Vec<u8>> {
    match &node.content {
        Some(BinaryContent::Bytes(b)) => Some(b.clone()),
        Some(BinaryContent::String(s)) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

fn node_children(node: &BinaryNode) -> &[BinaryNode] {
    match &node.content {
        Some(BinaryContent::Children(c)) => c.as_slice(),
        _ => &[],
    }
}

/// `parseRelayFromAck` do `call-manager.ts`: relays, participantes, uuid,
/// PIDs e `hbh_key` no formato do ack/oferta (`relay` → `token`/`auth_token`
/// binários por id, `key`, `hbh_key`, `te2` com endereço de 6 bytes).
pub fn parse_relay_from_ack(ack_node: &BinaryNode) -> RelayData {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut data = RelayData::default();
    let mut participant_seen = std::collections::HashSet::new();

    for child in node_children(ack_node) {
        if child.tag == "user" {
            for device in node_children(child) {
                if device.tag == "device" {
                    if let Some(jid) = device.attr("jid") {
                        if participant_seen.insert(jid.to_string()) {
                            data.participant_jids.push(jid.to_string());
                        }
                    }
                }
            }
        }

        if child.tag != "relay" {
            continue;
        }

        data.uuid = Some(child.attr("uuid").unwrap_or_default().to_string());
        if let Some(pid) = child.attr("self_pid").and_then(|v| v.parse().ok()) {
            data.self_pid = Some(pid);
        }
        if let Some(pid) = child.attr("peer_pid").and_then(|v| v.parse().ok()) {
            data.peer_pid = Some(pid);
        }
        let relay_content = node_children(child);

        for rc in relay_content {
            if rc.tag == "participant" {
                if let Some(jid) = rc.attr("jid") {
                    if participant_seen.insert(jid.to_string()) {
                        data.participant_jids.push(jid.to_string());
                    }
                }
            }
        }

        let mut relay_key = String::new();
        let mut tokens: std::collections::HashMap<String, String> = Default::default();
        let mut auth_tokens: std::collections::HashMap<String, String> = Default::default();
        let mut raw_tokens: std::collections::HashMap<String, Vec<u8>> = Default::default();
        let mut raw_auth_tokens: std::collections::HashMap<String, Vec<u8>> = Default::default();

        for rc in relay_content {
            match rc.tag.as_str() {
                "key" => {
                    if let Some(bytes) = node_bytes(rc) {
                        relay_key = String::from_utf8_lossy(&bytes).to_string();
                    }
                }
                "hbh_key" => {
                    let raw = match &rc.content {
                        Some(BinaryContent::Bytes(b)) => Some(b.clone()),
                        Some(BinaryContent::String(s)) => b64.decode(s).ok(),
                        _ => None,
                    };
                    if let Some(raw) = raw {
                        if raw.len() == 30 {
                            data.hbh_key = Some(raw);
                        } else if raw.len() > 30 {
                            let as_b64 = String::from_utf8_lossy(&raw).trim().to_string();
                            if let Ok(decoded) = b64.decode(as_b64) {
                                if decoded.len() == 30 {
                                    data.hbh_key = Some(decoded);
                                }
                            }
                        }
                    }
                }
                "token" => {
                    let id = rc.attr("id").unwrap_or("0").to_string();
                    match &rc.content {
                        Some(BinaryContent::Bytes(b)) => {
                            tokens.insert(id.clone(), b64.encode(b));
                            raw_tokens.insert(id, b.clone());
                        }
                        Some(BinaryContent::String(s)) => {
                            tokens.insert(id, s.clone());
                        }
                        _ => {}
                    }
                }
                "auth_token" => {
                    let id = rc.attr("id").unwrap_or("0").to_string();
                    match &rc.content {
                        Some(BinaryContent::Bytes(b)) => {
                            auth_tokens.insert(id.clone(), b64.encode(b));
                            raw_auth_tokens.insert(id, b.clone());
                        }
                        Some(BinaryContent::String(s)) => {
                            auth_tokens.insert(id, s.clone());
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        for rc in relay_content {
            if rc.tag != "te2" {
                continue;
            }
            let token_id = rc.attr("token_id").unwrap_or("0").to_string();
            let auth_token_id = rc.attr("auth_token_id").unwrap_or_default().to_string();
            let Some(BinaryContent::Bytes(addr)) = &rc.content else {
                continue;
            };
            if addr.len() != 6 {
                continue;
            }
            let ip = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
            let port = ((addr[4] as u16) << 8) | addr[5] as u16;
            data.endpoints.push(RelayEndpoint {
                ip,
                port,
                token: tokens.get(&token_id).cloned().unwrap_or_default(),
                auth_token: (!auth_token_id.is_empty())
                    .then(|| auth_tokens.get(&auth_token_id).cloned())
                    .flatten(),
                raw_auth_token: (!auth_token_id.is_empty())
                    .then(|| raw_auth_tokens.get(&auth_token_id).cloned())
                    .flatten(),
                raw_token: raw_tokens.get(&token_id).cloned(),
                key: relay_key.clone(),
                relay_id: rc.attr("relay_id").and_then(|v| v.parse().ok()).unwrap_or(0),
                protocol: Some(rc.attr("protocol").and_then(|v| v.parse().ok()).unwrap_or(0)),
                c2r_rtt: rc.attr("c2r_rtt").and_then(|v| v.parse().ok()),
                relay_name: Some(rc.attr("relay_name").unwrap_or_default().to_string()),
                address_bytes: Some(addr.clone()),
                auth_token_id: Some(if auth_token_id.is_empty() { token_id.clone() } else { auth_token_id.clone() }),
            });
        }
    }

    data.endpoints.sort_by_key(|r| r.c2r_rtt.unwrap_or(u32::MAX));
    data
}

/// `ensureDeviceJid` — bare user JID → `user:0@…`.
pub fn ensure_device_jid(jid: &str) -> String {
    if jid.is_empty() {
        return jid.to_string();
    }
    let Some(at) = jid.find('@') else {
        return jid.to_string();
    };
    let (user, server) = jid.split_at(at);
    if user.contains(':') {
        return jid.to_string();
    }
    format!("{user}:0{server}")
}

/// Bare JID (remove device).
pub fn jid_base(jid: &str) -> String {
    let Some(at) = jid.find('@') else {
        return jid.to_string();
    };
    let (user, server) = jid.split_at(at);
    let user = match user.rsplit_once(':') {
        Some((before, after)) if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) => {
            before
        }
        _ => user,
    };
    format!("{user}{server}")
}

/// Capability bytes capturados do web client real (selecionam MLow no PT 120).
pub const CAPABILITY_OFFER: [u8; 7] = [0x01, 0x05, 0xf7, 0x09, 0xe4, 0xbb, 0x07];
pub const CAPABILITY_PREACCEPT: [u8; 7] = [0x01, 0x05, 0xff, 0x09, 0xe4, 0xbb, 0x07];

/// Constroi o stanza `<call><offer>`.
pub fn build_offer_stanza(
    call_id: &str,
    call_key: &[u8],
    peer_jid: &str,
    call_creator: &str,
    is_video: bool,
    me_id: Option<&str>,
    destinations: Vec<BinaryNode>,
    should_include_device_identity: bool,
    account_bytes: Option<Vec<u8>>,
    privacy_token: Option<Vec<u8>>,
) -> BinaryNode {
    let call_creator = ensure_device_jid(call_creator);

    let mut offer_content: Vec<BinaryNode> = Vec::new();

    if let Some(token) = privacy_token {
        offer_content.push(BinaryNode::new("privacy").with_bytes(token));
    }

    // Order matches the original client: 8000 then 16000.
    offer_content.push(BinaryNode::new("audio").with_attr("enc", "opus").with_attr("rate", "8000"));
    offer_content.push(BinaryNode::new("audio").with_attr("enc", "opus").with_attr("rate", "16000"));

    if is_video {
        offer_content.push(
            BinaryNode::new("video")
                .with_attr("enc", "vp8")
                .with_attr("dec", "vp8")
                .with_attr("orientation", "0")
                .with_attr("screen_width", "1920")
                .with_attr("screen_height", "1080")
                .with_attr("device_orientation", "0"),
        );
    }

    offer_content.push(BinaryNode::new("net").with_attr("medium", "3"));

    offer_content.push(
        BinaryNode::new("capability")
            .with_attr("ver", "1")
            .with_bytes(CAPABILITY_OFFER.to_vec()),
    );

    offer_content.push(BinaryNode::new("destination").with_children(destinations));

    offer_content.push(BinaryNode::new("encopt").with_attr("keygen", "2"));

    if should_include_device_identity {
        if let Some(bytes) = account_bytes {
            offer_content.push(BinaryNode::new("device-identity").with_bytes(bytes));
        }
    }

    let id = generate_message_id_v2(me_id);
    let _ = call_key;

    BinaryNode::new("call")
        .with_attr("to", peer_jid)
        .with_attr("id", &id)
        .with_children(vec![
            BinaryNode::new("offer")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", &call_creator)
                .with_children(offer_content),
        ])
}

/// `buildAcceptStanza` (formato Zapo: um único `<enc>` cifrado ao caller).
pub fn build_accept_stanza(
    call_id: &str,
    call_creator: &str,
    to_jid: &str,
    is_video: bool,
    enc_node: BinaryNode,
    should_include_device_identity: bool,
    account_bytes: Option<Vec<u8>>,
) -> BinaryNode {
    let mut accept_content: Vec<BinaryNode> = vec![
        BinaryNode::new("audio").with_attr("enc", "opus").with_attr("rate", "16000"),
        BinaryNode::new("net").with_attr("medium", "3"),
        enc_node,
        BinaryNode::new("encopt").with_attr("keygen", "2"),
    ];

    if should_include_device_identity {
        if let Some(bytes) = account_bytes {
            accept_content.push(BinaryNode::new("device-identity").with_bytes(bytes));
        }
    }

    if is_video {
        accept_content.push(BinaryNode::new("video").with_attr("enc", "vp8"));
    }

    BinaryNode::new("call")
        .with_attr("to", to_jid)
        .with_attr("id", generate_call_stanza_id())
        .with_children(vec![
            BinaryNode::new("accept")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator)
                .with_children(accept_content),
        ])
}

/// `buildTerminateStanza`.
pub fn build_terminate_stanza(peer_jid: &str, call_id: &str, call_creator: &str) -> BinaryNode {
    BinaryNode::new("call")
        .with_attr("to", jid_base(peer_jid))
        .with_attr("id", generate_call_stanza_id())
        .with_children(vec![
            BinaryNode::new("terminate")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator),
        ])
}

/// `buildTerminateToDeviceStanza`.
pub fn build_terminate_to_device_stanza(
    device_jid: &str,
    call_id: &str,
    call_creator: &str,
    reason: Option<&str>,
) -> BinaryNode {
    let mut terminate = BinaryNode::new("terminate")
        .with_attr("call-id", call_id)
        .with_attr("call-creator", call_creator);
    if let Some(reason) = reason {
        terminate = terminate.with_attr("reason", reason);
    }

    BinaryNode::new("call")
        .with_attr("to", device_jid)
        .with_attr("id", generate_call_stanza_id())
        .with_children(vec![terminate])
}

/// `buildAcceptedElsewhereStanza`.
pub fn build_accepted_elsewhere_stanza(
    device_jid: &str,
    call_id: &str,
    call_creator: &str,
) -> BinaryNode {
    build_terminate_to_device_stanza(device_jid, call_id, call_creator, Some("accepted_elsewhere"))
}

/// `buildRejectStanza`.
pub fn build_reject_stanza(peer_jid: &str, call_id: &str, call_creator: &str) -> BinaryNode {
    BinaryNode::new("call")
        .with_attr("to", jid_base(peer_jid))
        .with_attr("id", generate_call_stanza_id())
        .with_children(vec![
            BinaryNode::new("reject")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator),
        ])
}

/// `buildPreacceptStanza`.
pub fn build_preaccept_stanza(peer_jid: &str, call_id: &str, call_creator: &str) -> BinaryNode {
    BinaryNode::new("call")
        .with_attr("to", peer_jid)
        .with_attr("id", generate_call_stanza_id())
        .with_children(vec![
            BinaryNode::new("preaccept")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator)
                .with_children(vec![
                    BinaryNode::new("audio").with_attr("enc", "opus").with_attr("rate", "16000"),
                    BinaryNode::new("encopt").with_attr("keygen", "2"),
                    BinaryNode::new("capability")
                        .with_attr("ver", "1")
                        .with_bytes(CAPABILITY_PREACCEPT.to_vec()),
                ]),
        ])
}

/// `createCallAck`.
pub fn create_call_ack(node_id: &str, peer_jid: &str, ack_type: &str) -> BinaryNode {
    BinaryNode::new("ack")
        .with_attr("id", node_id)
        .with_attr("to", peer_jid)
        .with_attr("class", "call")
        .with_attr("type", ack_type)
}

/// `buildRelayLatencyStanza`.
pub fn build_relay_latency_stanza(
    peer_jid: &str,
    call_id: &str,
    call_creator: &str,
    relays: &[(String, u32, Option<Vec<u8>>)],
    destination_jids: &[String],
    me_id: Option<&str>,
) -> BinaryNode {
    let mut seen = std::collections::HashSet::new();
    let mut te_nodes: Vec<BinaryNode> = Vec::new();
    for (name, latency, address_bytes) in relays {
        if name.is_empty() || !seen.insert(name.clone()) {
            continue;
        }
        let encoded_latency = 0x2000000 + (*latency as u64);
        let mut node = BinaryNode::new("te")
            .with_attr("latency", encoded_latency.to_string())
            .with_attr("relay_name", name);
        if let Some(bytes) = address_bytes {
            node = node.with_bytes(bytes.clone());
        }
        te_nodes.push(node);
    }

    let mut content = te_nodes;
    if !destination_jids.is_empty() {
        content.push(BinaryNode::new("destination").with_children(
            destination_jids
                .iter()
                .map(|jid| BinaryNode::new("to").with_attr("jid", jid))
                .collect(),
        ));
    }

    BinaryNode::new("call")
        .with_attr("to", jid_base(peer_jid))
        .with_attr("id", generate_message_id_v2(me_id))
        .with_children(vec![
            BinaryNode::new("relaylatency")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator)
                .with_children(content),
        ])
}

/// `buildTransportStanza`.
pub fn build_transport_stanza(
    peer_jid: &str,
    call_id: &str,
    call_creator: &str,
    me_id: Option<&str>,
) -> BinaryNode {
    BinaryNode::new("call")
        .with_attr("to", jid_base(peer_jid))
        .with_attr("id", generate_message_id_v2(me_id))
        .with_children(vec![
            BinaryNode::new("transport")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator)
                .with_attr("transport-message-type", "0")
                .with_attr("p2p-cand-round", "0")
                .with_children(vec![
                    BinaryNode::new("net").with_attr("medium", "2").with_attr("protocol", "0"),
                ]),
        ])
}

/// `buildMuteV2Stanza`.
pub fn build_mute_v2_stanza(
    peer_device_jid: &str,
    call_id: &str,
    call_creator: &str,
    mute_state: u32,
    me_id: Option<&str>,
) -> BinaryNode {
    BinaryNode::new("call")
        .with_attr("to", peer_device_jid)
        .with_attr("id", generate_message_id_v2(me_id))
        .with_children(vec![
            BinaryNode::new("mute_v2")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator)
                .with_attr("mute-state", mute_state.to_string()),
        ])
}

/// `buildAcceptReceiptStanza`.
pub fn build_accept_receipt_stanza(
    peer_device_jid: &str,
    accept_msg_id: &str,
    call_id: &str,
    call_creator: &str,
    our_jid: &str,
) -> BinaryNode {
    BinaryNode::new("receipt")
        .with_attr("to", peer_device_jid)
        .with_attr("id", accept_msg_id)
        .with_attr("from", our_jid)
        .with_children(vec![
            BinaryNode::new("accept")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator),
        ])
}

/// Tags criptografadas de call (precisa decrypt no callee).
pub const ENCRYPTED_TAGS: [&str; 2] = ["preaccept", "accept"];

/// `needsDecryption`.
pub fn needs_decryption(tag: &str) -> bool {
    ENCRYPTED_TAGS.contains(&tag)
}

/// Codifica uma mensagem `Message { call: { callKey } }` com padding.
pub fn encode_call_message(call_key: &[u8]) -> Vec<u8> {
    let message = wa::Message {
        call: Some(Box::new(wa::message::Call {
            call_key: Some(call_key.to_vec()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let bytes = message.encode_to_vec();
    baileys_core::ids::write_random_pad_max16(&bytes)
}

/// `decryptCallKeyInNode` — tenta cada `<enc>` (raiz e `destination/to`),
/// preferindo o `to` endereçado a um dos `our_device_jids`; o primeiro que
/// descriptografar vira `<enc v=2>callKey</enc>` no nó clonado.
///
/// `decrypt` recebe `(jid, type, ciphertext)` e devolve o plaintext com padding.
pub fn decrypt_call_key_in_node(
    decrypt: &dyn Fn(&str, &str, &[u8]) -> Result<Vec<u8>, String>,
    node: &BinaryNode,
    peer_jid: &str,
    our_device_jids: &[String],
) -> Result<(BinaryNode, Vec<u8>), String> {
    #[derive(Clone, Copy)]
    enum Path {
        Root(usize),
        Dest(usize, usize, usize),
    }

    let mut cloned = node.clone();
    let Some(BinaryContent::Children(children)) = &cloned.content else {
        return Err("no content".to_string());
    };

    let mut candidates: Vec<(Path, Option<String>)> = Vec::new();
    for (i, child) in children.iter().enumerate() {
        if child.tag == "enc" && child.attr("type").is_some() {
            candidates.push((Path::Root(i), None));
        }
    }
    if let Some(dest_idx) = children.iter().position(|c| c.tag == "destination") {
        for (ti, to_node) in node_children(&children[dest_idx]).iter().enumerate() {
            if to_node.tag != "to" {
                continue;
            }
            let to_jid = to_node.attr("jid").map(String::from);
            for (ei, enc) in node_children(to_node).iter().enumerate() {
                if enc.tag == "enc" && enc.attr("type").is_some() {
                    candidates.push((Path::Dest(dest_idx, ti, ei), to_jid.clone()));
                }
            }
        }
    }
    if candidates.is_empty() {
        return Err("no enc candidates".to_string());
    }

    let mut ours: std::collections::HashSet<String> = std::collections::HashSet::new();
    for jid in our_device_jids.iter().filter(|j| !j.is_empty()) {
        ours.insert(ensure_device_jid(jid));
        ours.insert(jid_base(jid));
    }
    let rank = |to: &Option<String>| -> u8 {
        match to {
            Some(j) if ours.contains(j) || ours.contains(&ensure_device_jid(j)) || ours.contains(&jid_base(j)) => 0,
            Some(_) => 1,
            None => 2,
        }
    };
    candidates.sort_by_key(|(_, to)| rank(to));

    let enc_at = |root: &BinaryNode, path: Path| -> Option<BinaryNode> {
        let children = node_children(root);
        match path {
            Path::Root(i) => children.get(i).cloned(),
            Path::Dest(d, t, e) => node_children(children.get(d)?)
                .get(t)
                .and_then(|to| node_children(to).get(e).cloned()),
        }
    };

    let mut last_err = String::from("no candidates");
    let total = candidates.len();
    for (path, to_jid) in candidates {
        let Some(enc) = enc_at(&cloned, path) else {
            continue;
        };
        let Some(BinaryContent::Bytes(ciphertext)) = &enc.content else {
            continue;
        };
        let enc_type = enc.attr("type").unwrap_or("msg").to_string();

        let attempt = decrypt(peer_jid, &enc_type, ciphertext).and_then(|decrypted| {
            let unpadded = unpad_random_max16(&decrypted).map_err(|e| e.to_string())?;
            let message = wa::Message::decode(unpadded.as_slice()).map_err(|e| e.to_string())?;
            let call_key = message.call.and_then(|c| c.call_key).unwrap_or_default();
            if call_key.len() != 32 {
                return Err(format!("invalid callKey: expected 32 bytes, got {}", call_key.len()));
            }
            Ok(call_key)
        });

        match attempt {
            Ok(call_key) => {
                let replacement = BinaryNode::new("enc").with_attr("v", "2").with_bytes(call_key.clone());
                if let Some(BinaryContent::Children(children)) = &mut cloned.content {
                    match path {
                        Path::Root(i) => children[i] = replacement,
                        Path::Dest(d, t, e) => {
                            if let Some(BinaryContent::Children(tos)) = &mut children[d].content {
                                if let Some(BinaryContent::Children(encs)) = &mut tos[t].content {
                                    encs[e] = replacement;
                                }
                            }
                        }
                    }
                }
                tracing::info!(
                    "[Signaling] callKey decrypt OK peer={peer_jid} to={}",
                    to_jid.as_deref().unwrap_or("root-enc")
                );
                return Ok((cloned, call_key));
            }
            Err(e) => last_err = e,
        }
    }

    tracing::error!("[Signaling] decrypt error (tried {total} enc): {last_err}");
    Err(last_err)
}

/// Transport pós-accept (`transport-message-type=1`, `p2p-cand-round=1`),
/// endereçado ao device que atendeu.
pub fn build_post_accept_transport_stanza(
    to_jid: &str,
    call_id: &str,
    call_creator: &str,
    me_id: Option<&str>,
) -> BinaryNode {
    BinaryNode::new("call")
        .with_attr("to", to_jid)
        .with_attr("id", generate_message_id_v2(me_id))
        .with_children(vec![
            BinaryNode::new("transport")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_creator)
                .with_attr("transport-message-type", "1")
                .with_attr("p2p-cand-round", "1")
                .with_children(vec![
                    BinaryNode::new("net").with_attr("medium", "2").with_attr("protocol", "0"),
                ]),
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_call_id_is_32_hex() {
        let id = generate_call_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn extract_relays_parses_single_and_nested() {
        let node = BinaryNode::new("offer").with_children(vec![
            BinaryNode::new("relay")
                .with_attr("ip", "1.2.3.4")
                .with_attr("port", "3480")
                .with_attr("token", "tok1")
                .with_attr("relay-key", "key1")
                .with_attr("relay-id", "1")
                .with_attr("c2r-rtt", "50"),
            BinaryNode::new("relays").with_children(vec![
                BinaryNode::new("relay")
                    .with_attr("ip", "5.6.7.8")
                    .with_attr("port", "3480")
                    .with_attr("token", "tok2")
                    .with_attr("relay-key", "key2")
                    .with_attr("relay-id", "2")
                    .with_attr("c2r-rtt", "10"),
            ]),
        ]);

        let relays = extract_relay_endpoints(&node);
        assert_eq!(relays.len(), 2);
        // Ordenado por c2r-rtt.
        assert_eq!(relays[0].ip, "5.6.7.8");
        assert_eq!(relays[1].ip, "1.2.3.4");
    }

    #[test]
    fn ensure_device_jid_adds_device_zero() {
        assert_eq!(ensure_device_jid("5511@s.whatsapp.net"), "5511:0@s.whatsapp.net");
        assert_eq!(ensure_device_jid("5511:12@s.whatsapp.net"), "5511:12@s.whatsapp.net");
        assert_eq!(ensure_device_jid(""), "");
    }

    #[test]
    fn jid_base_strips_device() {
        assert_eq!(jid_base("5511:12@s.whatsapp.net"), "5511@s.whatsapp.net");
        assert_eq!(jid_base("5511@s.whatsapp.net"), "5511@s.whatsapp.net");
    }

    #[test]
    fn offer_stanza_structure() {
        let stanza = build_offer_stanza(
            "CALL-ID",
            &[0u8; 32],
            "peer@s.whatsapp.net",
            "me:0@s.whatsapp.net",
            false,
            Some("me:0@s.whatsapp.net"),
            vec![BinaryNode::new("to").with_attr("jid", "peer:0@s.whatsapp.net")],
            false,
            None,
            None,
        );
        assert_eq!(stanza.tag, "call");
        let offer = stanza.child("offer").unwrap();
        assert_eq!(offer.attr("call-id"), Some("CALL-ID"));
        assert_eq!(offer.attr("call-creator"), Some("me:0@s.whatsapp.net"));
        assert!(offer.child("destination").is_some());
        assert!(offer.child("encopt").is_some());
    }

    #[test]
    fn decrypt_call_key_roundtrip() {
        // Cria um nó com enc contendo Message{call{callKey}} padded.
        // O decrypt mock reverte o padding (como o Signal repo real) para
        // expor a Message, e o parser re-faz o unpad + decode.
        let call_key = vec![0xCDu8; 32];
        let encoded = encode_call_message(&call_key);
        let node = BinaryNode::new("accept")
            .with_children(vec![
                BinaryNode::new("enc").with_attr("v", "2").with_attr("type", "msg").with_bytes(encoded),
            ]);

        let result = decrypt_call_key_in_node(
            &|_jid, _type, data| Ok(data.to_vec()),
            &node,
            "peer",
            &[],
        )
        .unwrap();
        assert_eq!(result.1, call_key);
        assert_eq!(result.1.len(), 32);
    }

    #[test]
    fn decrypt_prefers_enc_addressed_to_our_device() {
        let call_key = vec![0x11u8; 32];
        let good = encode_call_message(&call_key);
        let node = BinaryNode::new("accept").with_children(vec![BinaryNode::new("destination")
            .with_children(vec![
                BinaryNode::new("to").with_attr("jid", "other:3@lid").with_children(vec![
                    BinaryNode::new("enc").with_attr("type", "msg").with_bytes(vec![0xFF; 8]),
                ]),
                BinaryNode::new("to").with_attr("jid", "me:7@lid").with_children(vec![
                    BinaryNode::new("enc").with_attr("type", "msg").with_bytes(good),
                ]),
            ])]);
        let tried = std::cell::RefCell::new(Vec::new());
        let result = decrypt_call_key_in_node(
            &|_jid, _type, data| {
                tried.borrow_mut().push(data.len());
                Ok(data.to_vec())
            },
            &node,
            "peer",
            &["me:7@lid".to_string()],
        )
        .unwrap();
        assert_eq!(result.1, call_key);
        assert_eq!(tried.borrow().len(), 1);
    }

    #[test]
    fn parse_relay_from_ack_reads_te2_tokens_and_participants() {
        let node = BinaryNode::new("ack").with_children(vec![
            BinaryNode::new("user").with_children(vec![
                BinaryNode::new("device").with_attr("jid", "peer:5@lid"),
            ]),
            BinaryNode::new("relay")
                .with_attr("uuid", "U")
                .with_attr("self_pid", "1")
                .with_attr("peer_pid", "2")
                .with_children(vec![
                    BinaryNode::new("participant").with_attr("jid", "me:7@lid"),
                    BinaryNode::new("key").with_bytes(b"relaykey".to_vec()),
                    BinaryNode::new("token").with_attr("id", "0").with_bytes(vec![1, 2, 3]),
                    BinaryNode::new("auth_token").with_attr("id", "0").with_bytes(vec![4, 5]),
                    BinaryNode::new("te2")
                        .with_attr("relay_name", "gru1")
                        .with_attr("token_id", "0")
                        .with_attr("auth_token_id", "0")
                        .with_attr("c2r_rtt", "30")
                        .with_bytes(vec![10, 0, 0, 1, 0x0D, 0x96]),
                ]),
        ]);
        let data = parse_relay_from_ack(&node);
        assert_eq!(data.participant_jids, vec!["peer:5@lid", "me:7@lid"]);
        assert_eq!(data.self_pid, Some(1));
        assert_eq!(data.peer_pid, Some(2));
        assert_eq!(data.endpoints.len(), 1);
        let ep = &data.endpoints[0];
        assert_eq!(ep.ip, "10.0.0.1");
        assert_eq!(ep.port, 3478);
        assert_eq!(ep.key, "relaykey");
        assert_eq!(ep.raw_token.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(ep.raw_auth_token.as_deref(), Some(&[4u8, 5][..]));
        assert_eq!(ep.relay_name.as_deref(), Some("gru1"));
    }
}
