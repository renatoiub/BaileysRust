//! Reporting token — port de `Utils/reporting-utils.js` do Hineken.
//!
//! `shouldIncludeReportingToken` decide se a mensagem ganha `messageSecret`
//! (em `generateWAMessageContent`) e `getMessageReportingToken` monta o nó
//! `<reporting><reporting_token v="2">` anexado ao stanza fora de retry.

use std::collections::BTreeMap;

use baileys_core::BinaryNode;
use baileys_proto::proto as wa;

const ENC_SECRET_REPORT_TOKEN: &str = "Report Token";

const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_BYTES: u32 = 2;
const WIRE_FIXED32: u32 = 5;

#[derive(Default)]
struct FieldCfg {
    m: bool,
    children: Option<BTreeMap<u32, FieldCfg>>,
}

fn leaf() -> FieldCfg {
    FieldCfg::default()
}

fn msg_leaf() -> FieldCfg {
    FieldCfg { m: true, children: None }
}

fn node(children: Vec<(u32, FieldCfg)>) -> FieldCfg {
    FieldCfg { m: false, children: Some(children.into_iter().collect()) }
}

fn ctx_21_22() -> FieldCfg {
    node(vec![(21, leaf()), (22, leaf())])
}

fn pair_1_2() -> FieldCfg {
    node(vec![(1, leaf()), (2, leaf())])
}

fn interactive_like() -> FieldCfg {
    node(vec![(2, leaf()), (3, pair_1_2()), (5, ctx_21_22()), (8, pair_1_2())])
}

/// `reportingFields` do Hineken (mesma árvore de campos).
fn reporting_fields() -> BTreeMap<u32, FieldCfg> {
    vec![
        (1, leaf()),
        (3, node(vec![(2, leaf()), (3, leaf()), (8, leaf()), (11, leaf()), (17, ctx_21_22()), (25, leaf())])),
        (4, node(vec![(1, leaf()), (16, leaf()), (17, ctx_21_22())])),
        (5, node(vec![(3, leaf()), (4, leaf()), (5, leaf()), (16, leaf()), (17, ctx_21_22())])),
        (6, node(vec![(1, leaf()), (17, ctx_21_22()), (30, leaf())])),
        (7, node(vec![(2, leaf()), (7, leaf()), (10, leaf()), (17, ctx_21_22()), (20, leaf())])),
        (8, node(vec![(2, leaf()), (7, leaf()), (9, leaf()), (17, ctx_21_22()), (21, leaf())])),
        (9, node(vec![(2, leaf()), (6, leaf()), (7, leaf()), (13, leaf()), (17, ctx_21_22()), (20, leaf())])),
        (12, node(vec![(1, leaf()), (2, leaf()), (14, msg_leaf()), (15, leaf())])),
        (18, node(vec![(6, leaf()), (16, leaf()), (17, ctx_21_22())])),
        (26, node(vec![(4, leaf()), (5, leaf()), (8, leaf()), (13, leaf()), (17, ctx_21_22())])),
        (28, node(vec![(1, leaf()), (2, leaf()), (4, leaf()), (5, leaf()), (6, leaf()), (7, ctx_21_22())])),
        (37, node(vec![(1, msg_leaf())])),
        (49, interactive_like()),
        (53, node(vec![(1, msg_leaf())])),
        (55, node(vec![(1, msg_leaf())])),
        (58, node(vec![(1, msg_leaf())])),
        (59, node(vec![(1, msg_leaf())])),
        (60, interactive_like()),
        (64, interactive_like()),
        (66, node(vec![(2, leaf()), (6, leaf()), (7, leaf()), (13, leaf()), (17, ctx_21_22()), (20, leaf())])),
        (74, node(vec![(1, msg_leaf())])),
        (87, node(vec![(1, msg_leaf())])),
        (88, node(vec![(1, leaf()), (2, node(vec![(1, leaf())])), (3, ctx_21_22())])),
        (92, node(vec![(1, msg_leaf())])),
        (93, node(vec![(1, msg_leaf())])),
        (94, node(vec![(1, msg_leaf())])),
    ]
    .into_iter()
    .collect()
}

/// `shouldIncludeReportingToken`.
pub fn should_include_reporting_token(message: &wa::Message) -> bool {
    message.reaction_message.is_none()
        && message.enc_reaction_message.is_none()
        && message.enc_event_response_message.is_none()
        && message.poll_update_message.is_none()
}

/// Tail de `generateWAMessageContent`: `messageContextInfo.messageSecret`
/// aleatório (32 bytes) quando a mensagem leva reporting token.
pub fn ensure_message_secret(message: &mut wa::Message) {
    use rand::RngCore;
    if !should_include_reporting_token(message) {
        return;
    }
    let info = message.message_context_info.get_or_insert_with(Default::default);
    if info.message_secret.as_ref().map_or(true, |s| s.is_empty()) {
        let mut secret = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        info.message_secret = Some(secret);
    }
}

/// Resultado de `decodeVarint` (`value`, `bytes`).
fn decode_varint(buffer: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut value: u32 = 0;
    let mut bytes = 0usize;
    let mut shift = 0u32;
    while offset + bytes < buffer.len() {
        let current = buffer[offset + bytes];
        value |= ((current & 0x7f) as u32).wrapping_shl(shift);
        bytes += 1;
        if current & 0x80 == 0 {
            return Some((value, bytes));
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    None
}

fn encode_varint(value: u32) -> Vec<u8> {
    let mut parts = Vec::new();
    let mut remaining = value;
    while remaining > 0x7f {
        parts.push(((remaining & 0x7f) | 0x80) as u8);
        remaining >>= 7;
    }
    parts.push(remaining as u8);
    parts
}

/// `extractReportingTokenContent`.
fn extract_reporting_token_content(data: &[u8], cfg: &BTreeMap<u32, FieldCfg>) -> Option<Vec<u8>> {
    let empty = BTreeMap::new();
    let mut out: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let (tag_value, tag_bytes) = decode_varint(data, i)?;
        let field_num = tag_value >> 3;
        let wire_type = tag_value & 0x7;
        let field_start = i;
        i += tag_bytes;
        let field_cfg = cfg.get(&field_num);

        let fixed_end = match wire_type {
            WIRE_VARINT => {
                let (_, v_bytes) = decode_varint(data, i)?;
                Some(i + v_bytes)
            }
            WIRE_FIXED64 => Some(i + 8),
            WIRE_FIXED32 => Some(i + 4),
            WIRE_BYTES => None,
            _ => return None,
        };

        if let Some(end) = fixed_end {
            if end > data.len() {
                return None;
            }
            if field_cfg.is_some() {
                out.push((field_num, data[field_start..end].to_vec()));
            }
            i = end;
            continue;
        }

        let (len, len_bytes) = decode_varint(data, i)?;
        let val_start = i + len_bytes;
        let val_end = val_start + len as usize;
        if val_end > data.len() {
            return None;
        }
        let Some(field_cfg) = field_cfg else {
            i = val_end;
            continue;
        };
        if field_cfg.m || field_cfg.children.is_some() {
            let sub = extract_reporting_token_content(
                &data[val_start..val_end],
                field_cfg.children.as_ref().unwrap_or(&empty),
            )?;
            if !sub.is_empty() {
                let mut bytes = encode_varint(tag_value);
                bytes.extend(encode_varint(sub.len() as u32));
                bytes.extend(sub);
                out.push((field_num, bytes));
            }
            i = val_end;
            continue;
        }
        out.push((field_num, data[field_start..val_end].to_vec()));
        i = val_end;
    }
    if out.is_empty() {
        return Some(Vec::new());
    }
    out.sort_by_key(|(num, _)| *num);
    Some(out.into_iter().flat_map(|(_, b)| b).collect())
}

/// `getMessageReportingToken` — `msg_protobuf` é o `encodeWAMessage` (com pad)
/// da mensagem; a chave é `{ id, fromMe: true, remoteJid, participant }`.
pub fn get_message_reporting_token(
    msg_protobuf: &[u8],
    message: &wa::Message,
    msg_id: &str,
    remote_jid: &str,
    participant: Option<&str>,
) -> Option<BinaryNode> {
    let msg_secret = message
        .message_context_info
        .as_ref()
        .and_then(|c| c.message_secret.as_ref())
        .filter(|s| !s.is_empty())?;
    if msg_id.is_empty() {
        return None;
    }
    // `fromMe` sempre true no relay: from = remoteJid, to = participant || remoteJid.
    let from = remote_jid;
    let to = participant.unwrap_or(remote_jid);
    let info = format!("{msg_id}{from}{to}{ENC_SECRET_REPORT_TOKEN}");
    let reporting_secret = baileys_crypto::hkdf(msg_secret, 32, None, &info).ok()?;
    let content = extract_reporting_token_content(msg_protobuf, &reporting_fields())?;
    if content.is_empty() {
        return None;
    }
    let mut token = baileys_crypto::hmac_sign(&content, &reporting_secret, baileys_crypto::HmacVariant::Sha256);
    token.truncate(16);
    Some(BinaryNode::new("reporting").with_children(vec![
        BinaryNode::new("reporting_token").with_attr("v", "2").with_bytes(token),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn reporting_token_for_text_message() {
        let mut message = wa::Message {
            conversation: Some("oi".to_string()),
            ..Default::default()
        };
        ensure_message_secret(&mut message);
        assert_eq!(message.message_context_info.as_ref().and_then(|c| c.message_secret.as_ref()).map(Vec::len), Some(32));
        let node = get_message_reporting_token(&message.encode_to_vec(), &message, "3EB0ABC", "120363@g.us", None)
            .expect("reporting node");
        assert_eq!(node.tag, "reporting");
        assert_eq!(node.child("reporting_token").and_then(|t| t.attr("v")), Some("2"));
    }

    #[test]
    fn reaction_skips_message_secret() {
        let mut message = wa::Message {
            reaction_message: Some(Default::default()),
            ..Default::default()
        };
        ensure_message_secret(&mut message);
        assert!(message.message_context_info.is_none());
    }
}
