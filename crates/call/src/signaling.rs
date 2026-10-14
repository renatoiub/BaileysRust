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

use crate::types::{NodeInfo, RelayEndpoint};

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

/// `decryptCallKeyInNode` — descriptografa um `<enc>` e substitui o conteúdo
/// pelo callKey puro (32 bytes), retornando o nó clonado e o callKey.
pub fn decrypt_call_key_in_node(
    decrypt: &dyn Fn(&str, &str, &[u8]) -> Result<Vec<u8>, String>,
    node: &BinaryNode,
    peer_jid: &str,
) -> Result<(BinaryNode, Vec<u8>), String> {
    let mut cloned = node.clone();

    // Coleciona candidatos (enc, parent-index).
    let mut candidates: Vec<(usize, usize)> = Vec::new();
    // (child_idx, parent_idx) — parent é o índice do `to` dentro do destination.
    let Some(BinaryContent::Children(children)) = &cloned.content else {
        return Err("no content".to_string());
    };

    for (i, child) in children.iter().enumerate() {
        if child.tag == "enc" && child.attr("type").is_some() {
            candidates.push((i, usize::MAX));
        }
    }

    let mut destination_idx = None;
    if let Some(pos) = children.iter().position(|c| c.tag == "destination") {
        destination_idx = Some(pos);
    }

    if let Some(dest_idx) = destination_idx {
        let mut to_candidates: Vec<(usize, usize)> = Vec::new();
        if let Some(BinaryContent::Children(to_nodes)) = &children[dest_idx].content {
            for (ti, to_node) in to_nodes.iter().enumerate() {
                if let Some(BinaryContent::Children(enc_nodes)) = &to_node.content {
                    for (ei, enc) in enc_nodes.iter().enumerate() {
                        if enc.tag == "enc" && enc.attr("type").is_some() {
                            to_candidates.push((ei, ti));
                        }
                    }
                }
            }
        }
        // Preferir `to` do nosso device — aqui tentamos na ordem inversa
        // (o último é geralmente o destinado ao device atual).
        to_candidates.reverse();
        candidates = to_candidates
            .into_iter()
            .chain(candidates)
            .collect();
    }

    let mut last_err = String::from("no candidates");
    for (child_idx, parent_idx) in candidates {
        let enc_content: Vec<u8> = {
            let children = match &cloned.content {
                Some(BinaryContent::Children(c)) => c,
                _ => return Err("no content".to_string()),
            };
            if parent_idx == usize::MAX {
                match &children[child_idx].content {
                    Some(BinaryContent::Bytes(b)) => b.clone(),
                    _ => continue,
                }
            } else {
                let dest_idx = destination_idx.unwrap();
                match &children[dest_idx].content {
                    Some(BinaryContent::Children(to_nodes)) => {
                        match &to_nodes[parent_idx].content {
                            Some(BinaryContent::Children(enc_nodes)) => {
                                match &enc_nodes[child_idx].content {
                                    Some(BinaryContent::Bytes(b)) => b.clone(),
                                    _ => continue,
                                }
                            }
                            _ => continue,
                        }
                    }
                    _ => continue,
                }
            }
        };

        let enc_type = {
            let children = match &cloned.content {
                Some(BinaryContent::Children(c)) => c,
                _ => return Err("no content".to_string()),
            };
            if parent_idx == usize::MAX {
                children[child_idx].attr("type").unwrap_or("msg").to_string()
            } else {
                let dest_idx = destination_idx.unwrap();
                match &children[dest_idx].content {
                    Some(BinaryContent::Children(to_nodes)) => match &to_nodes[parent_idx].content {
                        Some(BinaryContent::Children(enc_nodes)) => {
                            enc_nodes[child_idx].attr("type").unwrap_or("msg").to_string()
                        }
                        _ => "msg".to_string(),
                    },
                    _ => "msg".to_string(),
                }
            }
        };

        match decrypt(peer_jid, &enc_type, &enc_content) {
            Ok(decrypted) => {
                let unpadded = unpad_random_max16(&decrypted).map_err(|e| e.to_string())?;
                let message = wa::Message::decode(unpadded.as_slice())
                    .map_err(|e| e.to_string())?;
                let call_key = message
                    .call
                    .and_then(|c| c.call_key)
                    .ok_or_else(|| "no call key".to_string())?;
                if call_key.len() != 32 {
                    return Err(format!(
                        "invalid callKey: expected 32 bytes, got {}",
                        call_key.len()
                    ));
                }

                // Substitui o conteúdo do enc pelo callKey puro.
                let children = match &mut cloned.content {
                    Some(BinaryContent::Children(c)) => c,
                    _ => return Err("no content".to_string()),
                };
                if parent_idx == usize::MAX {
                    children[child_idx] = BinaryNode::new("enc")
                        .with_attr("v", "2")
                        .with_bytes(call_key.clone());
                } else {
                    let dest_idx = destination_idx.unwrap();
                    if let Some(BinaryContent::Children(to_nodes)) = &mut children[dest_idx].content {
                        if let Some(BinaryContent::Children(enc_nodes)) = &mut to_nodes[parent_idx].content {
                            enc_nodes[child_idx] = BinaryNode::new("enc")
                                .with_attr("v", "2")
                                .with_bytes(call_key.clone());
                        }
                    }
                }

                return Ok((cloned, call_key));
            }
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
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
        )
        .unwrap();
        assert_eq!(result.1, call_key);
        assert_eq!(result.1.len(), 32);
    }
}
