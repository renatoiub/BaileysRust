//! JID utilities espelhando o `WABinary/jid-utils.ts` do Baileys.

pub const S_WHATSAPP_NET: &str = "@s.whatsapp.net";
pub const OFFICIAL_BIZ_JID: &str = "16505361212@c.us";
pub const SERVER_JID: &str = "server@c.us";
pub const PSA_WID: &str = "0@c.us";
pub const STORIES_JID: &str = "status@broadcast";
pub const META_AI_JID: &str = "13135550002@c.us";

/// Domínio do JID (server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JidServer {
    CUs,
    GUs,
    Broadcast,
    SWhatsappNet,
    Call,
    Lid,
    Newsletter,
    Bot,
}

impl JidServer {
    pub fn as_str(self) -> &'static str {
        match self {
            JidServer::CUs => "c.us",
            JidServer::GUs => "g.us",
            JidServer::Broadcast => "broadcast",
            JidServer::SWhatsappNet => "s.whatsapp.net",
            JidServer::Call => "call",
            JidServer::Lid => "lid",
            JidServer::Newsletter => "newsletter",
            JidServer::Bot => "bot",
        }
    }

    pub fn parse(server: &str) -> Option<JidServer> {
        Some(match server {
            "c.us" => JidServer::CUs,
            "g.us" => JidServer::GUs,
            "broadcast" => JidServer::Broadcast,
            "s.whatsapp.net" => JidServer::SWhatsappNet,
            "call" => JidServer::Call,
            "lid" => JidServer::Lid,
            "newsletter" => JidServer::Newsletter,
            "bot" => JidServer::Bot,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullJid {
    pub user: String,
    pub device: Option<u32>,
    pub server: JidServer,
    pub domain_type: u8,
}

/// `jidEncode` — monta um JID a partir das partes.
pub fn jid_encode(user: &str, server: JidServer, device: Option<u32>) -> String {
    let device = match device {
        Some(d) => format!(":{d}"),
        None => String::new(),
    };
    format!("{user}{device}@{}", server.as_str())
}

/// `jidDecode` — desmonta um JID em partes.
pub fn jid_decode(jid: &str) -> Option<FullJid> {
    let sep = jid.find('@')?;
    let server_str = &jid[sep + 1..];
    let user_combined = &jid[..sep];

    let (user_agent, device) = match user_combined.split_once(':') {
        Some((u, d)) => (u, d.parse::<u32>().ok()),
        None => (user_combined, None),
    };

    let user = user_agent.split('_').next().unwrap_or("").to_string();
    let server = JidServer::parse(server_str)?;

    Some(FullJid {
        user,
        device,
        domain_type: if server == JidServer::Lid { 1 } else { 0 },
        server,
    })
}

/// `isJidUser`
pub fn is_jid_user(jid: &str) -> bool {
    jid.ends_with("@s.whatsapp.net")
}

/// `isLidUser`
pub fn is_lid_user(jid: &str) -> bool {
    jid.ends_with("@lid")
}

/// `isJidBroadcast`
pub fn is_jid_broadcast(jid: &str) -> bool {
    jid.ends_with("@broadcast")
}

/// `isJidGroup`
pub fn is_jid_group(jid: &str) -> bool {
    jid.ends_with("@g.us")
}

/// `isJidStatusBroadcast`
pub fn is_jid_status_broadcast(jid: &str) -> bool {
    jid == "status@broadcast"
}

/// `isJidNewsletter`
pub fn is_jid_newsletter(jid: &str) -> bool {
    jid.ends_with("@newsletter")
}

/// `jidNormalizedUser` — normaliza um JID para o formato de usuário.
pub fn jid_normalized_user(jid: &str) -> String {
    let Some(decoded) = jid_decode(jid) else {
        return String::new();
    };
    let server = if decoded.server == JidServer::CUs {
        JidServer::SWhatsappNet
    } else {
        decoded.server
    };
    jid_encode(&decoded.user, server, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let jid = "5511999999999@s.whatsapp.net";
        let decoded = jid_decode(jid).unwrap();
        assert_eq!(decoded.user, "5511999999999");
        assert_eq!(decoded.server, JidServer::SWhatsappNet);
        assert_eq!(jid_encode(&decoded.user, decoded.server, None), jid);
    }

    #[test]
    fn device_jid() {
        let decoded = jid_decode("5511999999999:12@s.whatsapp.net").unwrap();
        assert_eq!(decoded.device, Some(12));
    }

    #[test]
    fn normalized_user() {
        assert_eq!(jid_normalized_user("5511999999999@c.us"), "5511999999999@s.whatsapp.net");
        assert_eq!(jid_normalized_user("120363@g.us"), "120363@g.us");
    }
}
