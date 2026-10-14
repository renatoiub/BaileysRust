//! USync (contatos) — port de `Socket/usync.ts` + `WAUSync` (Fase 3).
//!
//! Constrói as queries `<iq xmlns="usync">` e faz o parse do resultado
//! (contact, status, devices).

use baileys_core::{BinaryContent, BinaryNode, S_WHATSAPP_NET};

/// Protocolo de USync suportado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum USyncProtocol {
    Contact,
    Status,
    Devices,
    LID,
}

impl USyncProtocol {
    /// Nome do protocolo no XML (tag).
    pub fn tag(self) -> &'static str {
        match self {
            USyncProtocol::Contact => "contact",
            USyncProtocol::Status => "status",
            USyncProtocol::Devices => "devices",
            USyncProtocol::LID => "lid",
        }
    }

    /// Elemento de query do protocolo.
    pub fn query_element(self) -> BinaryNode {
        match self {
            USyncProtocol::Devices => BinaryNode::new("devices").with_attr("version", "2"),
            _ => BinaryNode::new(self.tag()),
        }
    }

    /// Elemento de usuário (para `contact`, usa o phone como conteúdo).
    pub fn user_element(self, user: &USyncUser) -> Option<BinaryNode> {
        match self {
            USyncProtocol::Contact => Some(
                BinaryNode::new("contact")
                    .with_string(user.phone.clone().unwrap_or_default()),
            ),
            USyncProtocol::Status | USyncProtocol::Devices | USyncProtocol::LID => None,
        }
    }
}

/// Usuário de uma query USync.
#[derive(Debug, Clone, Default)]
pub struct USyncUser {
    pub id: Option<String>,
    pub lid: Option<String>,
    pub phone: Option<String>,
}

/// Resultado de um usuário no USync.
#[derive(Debug, Clone, Default)]
pub struct USyncResult {
    pub id: String,
    pub contact: Option<bool>, // true = `type="in"` (é contato)
    pub status: Option<String>,
    pub devices: Vec<USyncDevice>,
    pub lid: Option<String>,
}

/// Dispositivo listado no protocolo `devices`.
#[derive(Debug, Clone, Default)]
pub struct USyncDevice {
    pub id: u32,
    pub key_index: Option<u32>,
    pub is_hosted: bool,
}

/// Monta o iq de USync (`<usync context mode sid last index>`).
pub fn usync_query(
    protocols: &[USyncProtocol],
    users: &[USyncUser],
    context: &str,
    mode: &str,
    sid: &str,
) -> BinaryNode {
    let user_nodes: Vec<BinaryNode> = users
        .iter()
        .map(|user| {
            let mut node = BinaryNode::new("user");
            if let Some(id) = &user.id {
                if !user.phone.is_some() {
                    node = node.with_attr("jid", id);
                }
            }
            let children: Vec<BinaryNode> = protocols
                .iter()
                .filter_map(|p| p.user_element(user))
                .collect();
            if !children.is_empty() {
                node = node.with_children(children);
            }
            node
        })
        .collect();

    let query_children: Vec<BinaryNode> = protocols
        .iter()
        .map(|p| p.query_element())
        .collect();

    BinaryNode::new("iq")
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", "get")
        .with_attr("xmlns", "usync")
        .with_children(vec![
            BinaryNode::new("usync")
                .with_attr("context", context)
                .with_attr("mode", mode)
                .with_attr("sid", sid)
                .with_attr("last", "true")
                .with_attr("index", "0")
                .with_children(vec![
                    BinaryNode::new("query").with_children(query_children),
                    BinaryNode::new("list").with_children(user_nodes),
                ]),
        ])
}

/// Faz o parse do resultado de USync.
pub fn parse_usync_result(result: &BinaryNode, protocols: &[USyncProtocol]) -> Vec<USyncResult> {
    if result.attr("type") != Some("result") {
        return Vec::new();
    }

    let Some(usync) = result.child("usync") else {
        return Vec::new();
    };
    let Some(list) = usync.child("list") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for user_node in list.children("user") {
        let id = user_node.attr("jid").unwrap_or_default().to_string();
        let mut entry = USyncResult {
            id: id.clone(),
            ..Default::default()
        };

        for proto in protocols {
            if let Some(content) = user_node.child(proto.tag()) {
                match proto {
                    USyncProtocol::Contact => {
                        entry.contact = Some(content.attr("type") == Some("in"));
                    }
                    USyncProtocol::Status => {
                        entry.status = match &content.content {
                            Some(BinaryContent::String(s)) if !s.is_empty() => Some(s.clone()),
                            Some(BinaryContent::Bytes(b)) => {
                                std::str::from_utf8(b).ok().map(|s| s.to_string())
                            }
                            _ => None,
                        };
                    }
                    USyncProtocol::Devices => {
                        if let Some(device_list) = content.child("device-list") {
                            for device in device_list.children("device") {
                                entry.devices.push(USyncDevice {
                                    id: device.attr("id").and_then(|v| v.parse().ok()).unwrap_or(0),
                                    key_index: device.attr("key-index").and_then(|v| v.parse().ok()),
                                    is_hosted: device.attr("is_hosted") == Some("true"),
                                });
                            }
                        }
                    }
                    USyncProtocol::LID => {
                        // Node `UsyncLIDProtocol.parser` retorna `node.attrs.val`.
                        entry.lid = content.attr("val").map(String::from);
                    }
                }
            }
        }

        out.push(entry);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usync_query_structure() {
        let q = usync_query(
            &[USyncProtocol::Contact, USyncProtocol::Status],
            &[USyncUser {
                id: None,
                lid: None,
                phone: Some("5511999999999".to_string()),
            }],
            "interactive",
            "query",
            "sid-1",
        );

        assert_eq!(q.attr("xmlns"), Some("usync"));
        let usync = q.child("usync").unwrap();
        assert_eq!(usync.attr("context"), Some("interactive"));
        assert_eq!(usync.attr("sid"), Some("sid-1"));
        let list = usync.child("list").unwrap();
        assert_eq!(list.children("user").len(), 1);
    }

    #[test]
    fn parse_contact_and_status() {
        let result = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_children(vec![BinaryNode::new("usync").with_children(vec![
                BinaryNode::new("list").with_children(vec![BinaryNode::new("user")
                    .with_attr("jid", "5511@s.whatsapp.net")
                    .with_children(vec![
                        BinaryNode::new("contact").with_attr("type", "in"),
                        BinaryNode::new("status").with_string("disponível"),
                    ])]),
            ])]);

        let parsed = parse_usync_result(&result, &[USyncProtocol::Contact, USyncProtocol::Status]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "5511@s.whatsapp.net");
        assert_eq!(parsed[0].contact, Some(true));
        assert_eq!(parsed[0].status.as_deref(), Some("disponível"));
    }
}
