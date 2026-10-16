//! Grupos — port de `Socket/groups.ts` (Fase 3).
//!
//! Implementa as operações do namespace `w:g2` (create/leave/subject/
//! description/participants/invite/ephemeral/settings) e o parsing de
//! `extractGroupMetadata`.

use base64::Engine;
use baileys_core::BinaryNode;

/// Gera uma sender key aleatória de 32 bytes (para `groupCreate`).
pub fn generate_sender_key() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Metadados de um grupo (espelha `Types/GroupMetadata.ts`).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMetadata {
    pub id: String,
    pub subject: Option<String>,
    pub subject_owner: Option<String>,
    pub subject_owner_jid: Option<String>,
    pub subject_time: Option<u64>,
    pub size: usize,
    pub creation: Option<u64>,
    pub owner: Option<String>,
    pub owner_jid: Option<String>,
    pub desc: Option<String>,
    pub desc_id: Option<String>,
    pub desc_owner: Option<String>,
    pub desc_owner_jid: Option<String>,
    pub desc_time: Option<u64>,
    pub restrict: bool,
    pub announce: bool,
    pub is_community: bool,
    pub is_community_announce: bool,
    pub join_approval_mode: bool,
    pub member_add_mode: bool, // true = all_member_add
    pub ephemeral_duration: Option<u64>,
    pub participants: Vec<GroupParticipant>,
    pub addressing_mode: Option<String>,
}

/// Participante de grupo.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupParticipant {
    pub id: String,
    pub jid: String,
    pub lid: Option<String>,
    pub admin: Option<String>,
}

/// `extractGroupMetadata` — port fiel do Hineken.
pub fn extract_group_metadata(result: &BinaryNode) -> Option<GroupMetadata> {
    let group = result.child("group")?;

    let mut meta = GroupMetadata::default();

    // id
    let id = group.attr("id").unwrap_or_default();
    meta.id = if id.contains('@') {
        id.to_string()
    } else {
        baileys_core::jid_encode(id, baileys_core::JidServer::GUs, None)
    };

    // description
    if let Some(desc) = group.child("description") {
        meta.desc = desc.child_string("body").map(String::from);
        meta.desc_owner = desc
            .attr("participant")
            .map(|p| baileys_core::jid_normalized_user(p));
        meta.desc_owner_jid = desc
            .attr("participant_pn")
            .map(|p| baileys_core::jid_normalized_user(p));
        meta.desc_time = desc.attr("t").and_then(|t| t.parse().ok());
        meta.desc_id = desc.attr("id").map(String::from);
    }

    let eph = group.child("ephemeral").and_then(|e| e.attr("expiration"));
    meta.ephemeral_duration = eph.and_then(|e| e.parse().ok());

    meta.addressing_mode = group.attr("addressing_mode").map(String::from);

    meta.member_add_mode =
        group.child_string("member_add_mode") == Some("all_member_add");

    meta.subject = group.attr("subject").map(String::from);
    meta.subject_owner = group.attr("s_o").map(String::from);
    meta.subject_owner_jid = group.attr("s_o_pn").map(String::from);
    meta.subject_time = group.attr("s_t").and_then(|t| t.parse().ok());
    meta.size = group.children("participant").len();
    meta.creation = group.attr("creation").and_then(|c| c.parse().ok());
    meta.owner = group.attr("creator").map(|c| baileys_core::jid_normalized_user(c));
    meta.owner_jid = group.attr("creator_pn").map(|c| baileys_core::jid_normalized_user(c));

    meta.restrict = group.child("locked").is_some();
    meta.announce = group.child("announcement").is_some();
    meta.is_community = group.child("parent").is_some();
    meta.is_community_announce = group.child("default_sub_group").is_some();
    meta.join_approval_mode = group.child("membership_approval_mode").is_some();

    meta.participants = group
        .children("participant")
        .iter()
        .map(|p| {
            let id = p.attr("jid").unwrap_or_default().to_string();
            GroupParticipant {
                jid: if baileys_core::is_jid_user(&id) {
                    id.clone()
                } else {
                    p.attr("phone_number")
                        .map(|pn| baileys_core::jid_normalized_user(pn))
                        .unwrap_or_default()
                },
                lid: if baileys_core::is_lid_user(&id) {
                    Some(id.clone())
                } else {
                    p.attr("lid").map(String::from)
                },
                id,
                admin: p.attr("type").map(String::from),
            }
        })
        .collect();

    Some(meta)
}

/// Construção de nós de query de grupo (`groupQuery`).
pub fn group_query_node(jid: &str, r#type: &str, content: Vec<BinaryNode>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("type", r#type)
        .with_attr("xmlns", "w:g2")
        .with_attr("to", jid)
        .with_children(content)
}

/// `groupMetadata` — query `<query request="interactive"/>`.
pub fn group_metadata_query(jid: &str) -> BinaryNode {
    group_query_node(
        jid,
        "get",
        vec![BinaryNode::new("query").with_attr("request", "interactive")],
    )
}

/// `groupCreate` — `<create subject key><participant jid/>`.
pub fn group_create_query(subject: &str, key: &str, participants: &[String]) -> BinaryNode {
    group_query_node(
        "@g.us",
        "set",
        vec![BinaryNode::new("create")
            .with_attr("subject", subject)
            .with_attr("key", key)
            .with_children(
                participants
                    .iter()
                    .map(|jid| BinaryNode::new("participant").with_attr("jid", jid))
                    .collect(),
            )],
    )
}

/// `groupLeave` — `<leave><group id/>`.
pub fn group_leave_query(id: &str) -> BinaryNode {
    group_query_node(
        "@g.us",
        "set",
        vec![BinaryNode::new("leave").with_children(vec![
            BinaryNode::new("group").with_attr("id", id),
        ])],
    )
}

/// `groupUpdateSubject`.
pub fn group_update_subject_query(jid: &str, subject: &str) -> BinaryNode {
    group_query_node(
        jid,
        "set",
        vec![BinaryNode::new("subject").with_bytes(subject.as_bytes().to_vec())],
    )
}

/// `groupUpdateDescription` — `<description id prev delete><body/>`.
pub fn group_update_description_query(jid: &str, description: Option<&str>, prev: Option<&str>, new_id: Option<&str>) -> BinaryNode {
    let mut node = BinaryNode::new("description");
    if let Some(desc) = description {
        node = node.with_attr("id", new_id.unwrap_or(""));
        node = node.with_children(vec![BinaryNode::new("body").with_bytes(desc.as_bytes().to_vec())]);
    } else {
        node = node.with_attr("delete", "true");
    }
    if let Some(prev) = prev {
        node = node.with_attr("prev", prev);
    }
    group_query_node(jid, "set", vec![node])
}

/// `groupParticipantsUpdate` — `<action><participant jid/>`.
pub fn group_participants_update_query(jid: &str, participants: &[String], action: &str) -> BinaryNode {
    group_query_node(
        jid,
        "set",
        vec![BinaryNode::new(action).with_children(
            participants
                .iter()
                .map(|jid| BinaryNode::new("participant").with_attr("jid", jid))
                .collect(),
        )],
    )
}

/// `groupFetchAllParticipating` — `<participating><participants/><description/>`.
pub fn group_fetch_all_participating_query() -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("to", "@g.us")
        .with_attr("xmlns", "w:g2")
        .with_attr("type", "get")
        .with_children(vec![BinaryNode::new("participating").with_children(vec![
            BinaryNode::new("participants"),
            BinaryNode::new("description"),
        ])])
}

/// `groupInviteCode` — `<invite/>`.
pub fn group_invite_code_query(jid: &str) -> BinaryNode {
    group_query_node(jid, "get", vec![BinaryNode::new("invite")])
}

/// `groupToggleEphemeral`.
pub fn group_toggle_ephemeral_query(jid: &str, expiration: Option<u64>) -> BinaryNode {
    let content = match expiration {
        Some(e) => BinaryNode::new("ephemeral").with_attr("expiration", e.to_string()),
        None => BinaryNode::new("not_ephemeral"),
    };
    group_query_node(jid, "set", vec![content])
}

/// `groupSettingUpdate` — announcement/not_announcement/locked/unlocked.
pub fn group_setting_update_query(jid: &str, setting: &str) -> BinaryNode {
    group_query_node(jid, "set", vec![BinaryNode::new(setting)])
}

/// Monta o stanza `<message type="group" to=jid>` com o ciphertext sender-key
/// (`skmsg`).
///
/// A distribuição da sender-key é enviada separadamente, como `pkmsg` 1:1 por
/// participante (ver `send_group_text`/`send_group_message` no client).
pub fn group_message_node(
    jid: &str,
    msg_id: &str,
    ciphertext: &[u8],
) -> BinaryNode {
    BinaryNode::new("message")
        .with_attr("id", msg_id)
        .with_attr("type", "group")
        .with_attr("to", jid)
        .with_children(vec![
            BinaryNode::new("enc")
                .with_attr("v", "2")
                .with_attr("type", "skmsg")
                .with_bytes(ciphertext.to_vec()),
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_metadata_parses_group_node() {
        let node = BinaryNode::new("result").with_children(vec![BinaryNode::new("group")
            .with_attr("id", "123456789@g.us")
            .with_attr("subject", "Teste")
            .with_attr("creator", "5511999999999@s.whatsapp.net")
            .with_attr("creation", "1700000000")
            .with_children(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "5511999999999@s.whatsapp.net")
                    .with_attr("type", "admin"),
                BinaryNode::new("participant").with_attr("jid", "5511888888888@s.whatsapp.net"),
                BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
            ])]);

        let meta = extract_group_metadata(&node).unwrap();
        assert_eq!(meta.id, "123456789@g.us");
        assert_eq!(meta.subject.as_deref(), Some("Teste"));
        assert_eq!(meta.size, 2);
        assert_eq!(meta.ephemeral_duration, Some(86400));
        assert_eq!(meta.owner.as_deref(), Some("5511999999999@s.whatsapp.net"));
        assert_eq!(meta.participants[0].admin.as_deref(), Some("admin"));
    }

    #[test]
    fn group_id_without_domain_gets_gus() {
        let node = BinaryNode::new("result")
            .with_children(vec![BinaryNode::new("group").with_attr("id", "123456789")]);
        let meta = extract_group_metadata(&node).unwrap();
        assert_eq!(meta.id, "123456789@g.us");
    }

    #[test]
    fn create_query_has_participants() {
        let q = group_create_query("Grupo", "key123", &["5511@s.whatsapp.net".to_string()]);
        let create = q.child("create").unwrap();
        assert_eq!(create.attr("subject"), Some("Grupo"));
        assert_eq!(create.children("participant").len(), 1);
    }

    #[test]
    fn group_message_node_includes_skmsg() {
        let node = group_message_node("123@g.us", "msg-id", b"cipher");
        assert_eq!(node.attr("type"), Some("group"));
        let encs = node.children("enc");
        assert_eq!(encs.len(), 1);
        assert_eq!(encs[0].attr("type"), Some("skmsg"));
    }
}
