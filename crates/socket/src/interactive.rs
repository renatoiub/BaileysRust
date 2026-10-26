//! Mensagens interativas (botões, template, lista, native flow, carrossel,
//! shop, collection) e o nó `<biz>` que as faz renderizar.
//!
//! Builders: port do `generateWAMessageContent` da Hineken
//! (`Utils/messages.ts`: `buttons`, `templateButtons`, `sections`,
//! `interactiveButtons`, `shop`) mais `cards`/`collection` do README.
//! Nó `<biz>`: `getButtonArgs` da Hineken (`Socket/messages-send.ts`) e
//! `buildButtonAddonNode` do zapo, escolhidos por [`BizNodeMode`].

use baileys_core::BinaryNode;
use baileys_proto::proto as wa;
use serde_json::json;

use wa::message::{buttons_message, interactive_message, list_message, template_message};

/// Mídia de cabeçalho já enviada ao servidor de mídia.
#[derive(Debug, Clone)]
pub enum HeaderMedia {
    Image(wa::message::ImageMessage),
    Video(wa::message::VideoMessage),
    Document(wa::message::DocumentMessage),
    Location(wa::message::LocationMessage),
}

impl HeaderMedia {
    /// Extrai a mídia de um `wa::Message` montado pelo pipeline de mídia.
    pub fn from_message(msg: wa::Message) -> Option<Self> {
        if let Some(m) = msg.image_message {
            return Some(Self::Image(*m));
        }
        if let Some(m) = msg.video_message {
            return Some(Self::Video(*m));
        }
        if let Some(m) = msg.document_message {
            return Some(Self::Document(*m));
        }
        if let Some(m) = msg.document_with_caption_message.and_then(|f| f.message) {
            return Self::from_message(*m);
        }
        msg.location_message.map(|m| Self::Location(*m))
    }

    fn interactive_media(self) -> interactive_message::header::Media {
        use interactive_message::header::Media;
        match self {
            Self::Image(m) => Media::ImageMessage(Box::new(m)),
            Self::Video(m) => Media::VideoMessage(Box::new(m)),
            Self::Document(m) => Media::DocumentMessage(Box::new(m)),
            Self::Location(m) => Media::LocationMessage(Box::new(m)),
        }
    }
}

fn some_text(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// buttonsMessage
// ---------------------------------------------------------------------------

/// Botão de resposta (`buttonId` + `displayText`).
#[derive(Debug, Clone, Default)]
pub struct ReplyButton {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct ButtonsSpec {
    pub text: String,
    pub footer: Option<String>,
    pub title: Option<String>,
    pub media: Option<HeaderMedia>,
    pub buttons: Vec<ReplyButton>,
}

/// `buttonsMessage` (botões `RESPONSE`). Com mídia, o texto vai como
/// `contentText` e o header recebe a mídia; sem mídia, `title` vira header de
/// texto.
pub fn buttons_message(spec: ButtonsSpec) -> wa::Message {
    use buttons_message::{button, Button, Header, HeaderType};

    let (header, header_type) = match spec.media {
        Some(HeaderMedia::Image(m)) => (Some(Header::ImageMessage(Box::new(m))), HeaderType::Image),
        Some(HeaderMedia::Video(m)) => (Some(Header::VideoMessage(Box::new(m))), HeaderType::Video),
        Some(HeaderMedia::Document(m)) => (Some(Header::DocumentMessage(Box::new(m))), HeaderType::Document),
        Some(HeaderMedia::Location(m)) => (Some(Header::LocationMessage(Box::new(m))), HeaderType::Location),
        None => match some_text(spec.title) {
            Some(t) => (Some(Header::Text(t)), HeaderType::Text),
            None => (None, HeaderType::Empty),
        },
    };

    let buttons = spec
        .buttons
        .into_iter()
        .map(|b| Button {
            button_id: Some(b.id),
            button_text: Some(button::ButtonText { display_text: Some(b.text) }),
            r#type: Some(button::Type::Response as i32),
            native_flow_info: None,
        })
        .collect();

    wa::Message {
        buttons_message: Some(Box::new(wa::message::ButtonsMessage {
            content_text: Some(spec.text),
            footer_text: some_text(spec.footer),
            buttons,
            header_type: Some(header_type as i32),
            header,
            ..Default::default()
        })),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// templateMessage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum TemplateButton {
    QuickReply { text: String, id: String },
    Url { text: String, url: String },
    Call { text: String, phone: String },
}

#[derive(Debug, Clone, Default)]
pub struct TemplateSpec {
    pub text: String,
    pub footer: Option<String>,
    pub title: Option<String>,
    pub media: Option<HeaderMedia>,
    pub buttons: Vec<TemplateButton>,
}

/// `templateMessage` como a Hineken: `hydratedTemplate` com os botões e o
/// oneof em `fourRowTemplate` (vazio, porque o `fromObject` descarta os campos
/// hidratados).
pub fn template_message(spec: TemplateSpec) -> wa::Message {
    use template_message::hydrated_four_row_template::Title;
    use wa::hydrated_template_button::{
        HydratedButton, HydratedCallButton, HydratedQuickReplyButton, HydratedUrlButton,
    };

    let title = match spec.media {
        Some(HeaderMedia::Image(m)) => Some(Title::ImageMessage(Box::new(m))),
        Some(HeaderMedia::Video(m)) => Some(Title::VideoMessage(Box::new(m))),
        Some(HeaderMedia::Document(m)) => Some(Title::DocumentMessage(Box::new(m))),
        Some(HeaderMedia::Location(m)) => Some(Title::LocationMessage(Box::new(m))),
        None => some_text(spec.title).map(Title::HydratedTitleText),
    };

    let hydrated_buttons = spec
        .buttons
        .into_iter()
        .enumerate()
        .map(|(i, b)| wa::HydratedTemplateButton {
            index: Some(i as u32 + 1),
            hydrated_button: Some(match b {
                TemplateButton::QuickReply { text, id } => HydratedButton::QuickReplyButton(
                    HydratedQuickReplyButton { display_text: Some(text), id: Some(id) },
                ),
                TemplateButton::Url { text, url } => HydratedButton::UrlButton(HydratedUrlButton {
                    display_text: Some(text),
                    url: Some(url),
                    ..Default::default()
                }),
                TemplateButton::Call { text, phone } => HydratedButton::CallButton(HydratedCallButton {
                    display_text: Some(text),
                    phone_number: Some(phone),
                }),
            }),
        })
        .collect();

    let hydrated = template_message::HydratedFourRowTemplate {
        hydrated_content_text: Some(spec.text),
        hydrated_footer_text: some_text(spec.footer),
        hydrated_buttons,
        title,
        ..Default::default()
    };

    wa::Message {
        template_message: Some(Box::new(wa::message::TemplateMessage {
            hydrated_template: Some(Box::new(hydrated)),
            format: Some(template_message::Format::FourRowTemplate(Box::default())),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// listMessage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ListRow {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListSection {
    pub title: String,
    pub rows: Vec<ListRow>,
}

#[derive(Debug, Clone, Default)]
pub struct ListSpec {
    pub text: String,
    pub title: Option<String>,
    pub footer: Option<String>,
    pub button_text: String,
    pub sections: Vec<ListSection>,
}

/// `listMessage` `SINGLE_SELECT` (`description` = texto).
pub fn list_message(spec: ListSpec) -> wa::Message {
    let sections = spec
        .sections
        .into_iter()
        .map(|s| list_message::Section {
            title: Some(s.title),
            rows: s
                .rows
                .into_iter()
                .map(|r| list_message::Row {
                    title: Some(r.title),
                    description: some_text(r.description),
                    row_id: Some(r.id),
                })
                .collect(),
        })
        .collect();

    wa::Message {
        list_message: Some(Box::new(wa::message::ListMessage {
            title: some_text(spec.title),
            description: Some(spec.text),
            button_text: Some(spec.button_text),
            list_type: Some(list_message::ListType::SingleSelect as i32),
            sections,
            footer_text: some_text(spec.footer),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// interactiveMessage (native flow, carrossel, shop, collection)
// ---------------------------------------------------------------------------

/// Botão native flow (`name` + `buttonParamsJson`).
#[derive(Debug, Clone, Default)]
pub struct NativeButton {
    pub name: String,
    pub params_json: String,
}

impl NativeButton {
    pub fn new(name: impl Into<String>, params: serde_json::Value) -> Self {
        Self { name: name.into(), params_json: params.to_string() }
    }

    /// `quick_reply { display_text, id }`.
    pub fn quick_reply(text: &str, id: &str) -> Self {
        Self::new("quick_reply", json!({ "display_text": text, "id": id }))
    }

    /// `cta_url { display_text, url, merchant_url }`.
    pub fn cta_url(text: &str, url: &str) -> Self {
        Self::new("cta_url", json!({ "display_text": text, "url": url, "merchant_url": url }))
    }

    /// `cta_copy { display_text, copy_code }`.
    pub fn cta_copy(text: &str, code: &str) -> Self {
        Self::new("cta_copy", json!({ "display_text": text, "copy_code": code }))
    }

    /// `cta_call { display_text, phone_number }`.
    pub fn cta_call(text: &str, phone: &str) -> Self {
        Self::new("cta_call", json!({ "display_text": text, "phone_number": phone }))
    }
}

/// Cabeçalho comum das mensagens `interactiveMessage`.
#[derive(Debug, Clone, Default)]
pub struct InteractiveHeader {
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub media: Option<HeaderMedia>,
}

impl InteractiveHeader {
    fn build(self) -> interactive_message::Header {
        let has_media = self.media.is_some();
        interactive_message::Header {
            title: some_text(self.title),
            subtitle: some_text(self.subtitle),
            has_media_attachment: Some(has_media),
            media: self.media.map(HeaderMedia::interactive_media),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NativeFlowSpec {
    pub text: String,
    pub footer: Option<String>,
    pub header: InteractiveHeader,
    pub buttons: Vec<NativeButton>,
    pub message_params_json: Option<String>,
    pub message_version: Option<i32>,
}

fn native_flow(
    buttons: Vec<NativeButton>,
    message_params_json: Option<String>,
    message_version: Option<i32>,
) -> interactive_message::NativeFlowMessage {
    interactive_message::NativeFlowMessage {
        buttons: buttons
            .into_iter()
            .map(|b| interactive_message::native_flow_message::NativeFlowButton {
                name: Some(b.name),
                button_params_json: Some(b.params_json),
            })
            .collect(),
        message_params_json: some_text(message_params_json),
        message_version,
    }
}

fn interactive(
    header: Option<interactive_message::Header>,
    text: Option<String>,
    footer: Option<String>,
    body: interactive_message::InteractiveMessage,
) -> wa::message::InteractiveMessage {
    wa::message::InteractiveMessage {
        header: header.map(Box::new),
        body: Some(interactive_message::Body { text }),
        footer: some_text(footer).map(|t| interactive_message::Footer { text: Some(t) }),
        interactive_message: Some(body),
        ..Default::default()
    }
}

fn wrap_interactive(msg: wa::message::InteractiveMessage) -> wa::Message {
    wa::Message {
        interactive_message: Some(Box::new(msg)),
        ..Default::default()
    }
}

/// `interactiveMessage.nativeFlowMessage` (`interactiveButtons` da Hineken).
pub fn native_flow_message(spec: NativeFlowSpec) -> wa::Message {
    wrap_interactive(interactive(
        Some(spec.header.build()),
        Some(spec.text),
        spec.footer,
        interactive_message::InteractiveMessage::NativeFlowMessage(native_flow(
            spec.buttons,
            spec.message_params_json,
            spec.message_version,
        )),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct CarouselCard {
    pub header: InteractiveHeader,
    pub body: String,
    pub footer: Option<String>,
    pub buttons: Vec<NativeButton>,
}

#[derive(Debug, Clone, Default)]
pub struct CarouselSpec {
    pub text: String,
    pub footer: Option<String>,
    pub cards: Vec<CarouselCard>,
}

/// `interactiveMessage.carouselMessage`: cada card é um `InteractiveMessage`
/// com header (mídia) e botões native flow.
pub fn carousel_message(spec: CarouselSpec) -> wa::Message {
    let cards = spec
        .cards
        .into_iter()
        .map(|c| {
            interactive(
                Some(c.header.build()),
                Some(c.body),
                c.footer,
                interactive_message::InteractiveMessage::NativeFlowMessage(native_flow(
                    c.buttons,
                    None,
                    Some(1),
                )),
            )
        })
        .collect();

    wrap_interactive(interactive(
        None,
        Some(spec.text),
        spec.footer,
        interactive_message::InteractiveMessage::CarouselMessage(
            interactive_message::CarouselMessage { cards, message_version: Some(1) },
        ),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct ShopSpec {
    pub text: String,
    pub footer: Option<String>,
    pub header: InteractiveHeader,
    /// `Surface`: 1 = FB, 2 = IG, 3 = WA (a Hineken documenta 1-4).
    pub surface: i32,
    pub id: String,
}

/// `interactiveMessage.shopStorefrontMessage`.
pub fn shop_message(spec: ShopSpec) -> wa::Message {
    wrap_interactive(interactive(
        Some(spec.header.build()),
        Some(spec.text),
        spec.footer,
        interactive_message::InteractiveMessage::ShopStorefrontMessage(
            interactive_message::ShopMessage {
                id: Some(spec.id),
                surface: Some(spec.surface),
                message_version: Some(1),
            },
        ),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct CollectionSpec {
    pub text: String,
    pub footer: Option<String>,
    pub header: InteractiveHeader,
    pub biz_jid: String,
    pub id: String,
    pub version: i32,
}

/// `interactiveMessage.collectionMessage`.
pub fn collection_message(spec: CollectionSpec) -> wa::Message {
    wrap_interactive(interactive(
        Some(spec.header.build()),
        Some(spec.text),
        spec.footer,
        interactive_message::InteractiveMessage::CollectionMessage(
            interactive_message::CollectionMessage {
                biz_jid: Some(spec.biz_jid),
                id: Some(spec.id),
                message_version: Some(spec.version),
            },
        ),
    ))
}

/// `viewOnce: true` da Hineken (`{ viewOnceMessage: { message } }`).
pub fn wrap_view_once(msg: wa::Message) -> wa::Message {
    wa::Message {
        view_once_message: Some(Box::new(wa::message::FutureProofMessage {
            message: Some(Box::new(msg)),
        })),
        ..Default::default()
    }
}

/// Põe o `contextInfo` (reply/menções) no conteúdo interativo.
pub fn set_interactive_context_info(msg: &mut wa::Message, ctx: wa::ContextInfo) {
    let ctx = Box::new(ctx);
    if let Some(m) = msg.buttons_message.as_mut() {
        m.context_info = Some(ctx);
    } else if let Some(m) = msg.template_message.as_mut() {
        m.context_info = Some(ctx);
    } else if let Some(m) = msg.list_message.as_mut() {
        m.context_info = Some(ctx);
    } else if let Some(m) = msg.interactive_message.as_mut() {
        m.context_info = Some(ctx);
    } else if let Some(inner) = msg
        .view_once_message
        .as_mut()
        .and_then(|f| f.message.as_mut())
    {
        set_interactive_context_info(inner, *ctx);
    }
}

// ---------------------------------------------------------------------------
// nó <biz>
// ---------------------------------------------------------------------------

/// Variante do nó `<biz>` anexado ao `<message>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BizNodeMode {
    /// `getButtonArgs` da Hineken: `actual_actors`/`host_storage`/
    /// `privacy_mode_ts` + `<quality_control>`.
    #[default]
    Hineken,
    /// `buildButtonAddonNode` do zapo: `<biz>` sem atributos.
    Zapo,
    /// Sem nó (para comparar).
    None,
}

impl BizNodeMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "hineken" => Some(Self::Hineken),
            "zapo" => Some(Self::Zapo),
            "none" | "off" | "false" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hineken => "hineken",
            Self::Zapo => "zapo",
            Self::None => "none",
        }
    }
}

/// Desembrulha `viewOnce*`, `ephemeral`, `deviceSent` e `documentWithCaption`.
pub fn unwrap_message(msg: &wa::Message) -> &wa::Message {
    let mut current = msg;
    loop {
        let inner = current
            .ephemeral_message
            .as_ref()
            .or(current.view_once_message.as_ref())
            .or(current.view_once_message_v2.as_ref())
            .or(current.view_once_message_v2_extension.as_ref())
            .or(current.document_with_caption_message.as_ref())
            .and_then(|f| f.message.as_deref())
            .or_else(|| {
                current
                    .device_sent_message
                    .as_ref()
                    .and_then(|d| d.message.as_deref())
            });
        match inner {
            Some(next) => current = next,
            None => return current,
        }
    }
}

/// Native flows que a Hineken anuncia com o próprio nome.
const HINEKEN_NAMED_FLOWS: [&str; 6] = [
    "mpm",
    "cta_catalog",
    "send_location",
    "call_permission_request",
    "wa_payment_transaction_details",
    "automated_greeting_message_view_catalog",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum AddonKind {
    List,
    Mixed,
    /// Native flow anunciado pelo nome (`native_flow name=<n>`).
    Named(String),
    /// `review_and_pay` → `order_details`, `payment_info`.
    Payment(&'static str),
    /// Respostas (`*_response`): só o `<biz>` na Hineken.
    Reply,
}

fn addon_kind(msg: &wa::Message, mode: BizNodeMode) -> Option<AddonKind> {
    let msg = unwrap_message(msg);
    if msg.list_message.is_some() {
        return Some(AddonKind::List);
    }
    if msg.buttons_message.is_some() {
        return Some(AddonKind::Mixed);
    }
    if let Some(im) = msg.interactive_message.as_ref() {
        return match im.interactive_message.as_ref() {
            Some(interactive_message::InteractiveMessage::NativeFlowMessage(nf)) => {
                let first = nf
                    .buttons
                    .first()
                    .and_then(|b| b.name.as_deref())
                    .unwrap_or_default();
                Some(match first {
                    "review_and_pay" => AddonKind::Payment("order_details"),
                    "payment_info" => AddonKind::Payment("payment_info"),
                    "form_message" if mode == BizNodeMode::Zapo => AddonKind::Named(first.to_string()),
                    n if mode == BizNodeMode::Hineken && HINEKEN_NAMED_FLOWS.contains(&n) => {
                        AddonKind::Named(n.to_string())
                    }
                    _ => AddonKind::Mixed,
                })
            }
            Some(_) => Some(AddonKind::Mixed),
            None => None,
        };
    }
    if msg.buttons_response_message.is_some()
        || msg.list_response_message.is_some()
        || msg.interactive_response_message.is_some()
    {
        return Some(AddonKind::Reply);
    }
    None
}

fn native_flow_node(attrs: &[(&str, &str)]) -> BinaryNode {
    let mut nf = BinaryNode::new("native_flow");
    for (k, v) in attrs {
        nf = nf.with_attr(*k, *v);
    }
    BinaryNode::new("interactive")
        .with_attr("type", "native_flow")
        .with_attr("v", "1")
        .with_children(vec![nf])
}

/// Nó `<biz>` para mensagens interativas, ou `None` se a mensagem não precisa
/// dele (ou `mode == None`).
pub fn button_addon_node(msg: &wa::Message, mode: BizNodeMode) -> Option<BinaryNode> {
    if mode == BizNodeMode::None {
        return None;
    }
    let kind = addon_kind(msg, mode)?;

    match mode {
        BizNodeMode::Hineken => {
            if let AddonKind::Payment(name) = kind {
                return Some(BinaryNode::new("biz").with_attr("native_flow_name", name));
            }
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .to_string();
            let biz = BinaryNode::new("biz")
                .with_attr("actual_actors", "2")
                .with_attr("host_storage", "2")
                .with_attr("privacy_mode_ts", ts);
            let quality = BinaryNode::new("quality_control").with_attr("source_type", "third_party");
            let child = match kind {
                AddonKind::List => BinaryNode::new("list")
                    .with_attr("v", "2")
                    .with_attr("type", "product_list"),
                AddonKind::Named(name) => native_flow_node(&[("v", "2"), ("name", &name)]),
                AddonKind::Mixed => native_flow_node(&[("v", "9"), ("name", "mixed")]),
                AddonKind::Reply | AddonKind::Payment(_) => return Some(biz),
            };
            Some(biz.with_children(vec![child, quality]))
        }
        BizNodeMode::Zapo => {
            let child = match kind {
                AddonKind::List => BinaryNode::new("list")
                    .with_attr("type", "product_list")
                    .with_attr("v", "2"),
                AddonKind::Mixed => native_flow_node(&[("v", "9"), ("name", "mixed")]),
                AddonKind::Named(name) => native_flow_node(&[("name", &name)]),
                AddonKind::Payment(name) => native_flow_node(&[("name", name)]),
                AddonKind::Reply => return None,
            };
            Some(BinaryNode::new("biz").with_children(vec![child]))
        }
        BizNodeMode::None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child_tags(node: &BinaryNode) -> Vec<String> {
        match &node.content {
            Some(baileys_core::BinaryContent::Children(c)) => c.iter().map(|n| n.tag.clone()).collect(),
            _ => Vec::new(),
        }
    }

    fn first_child(node: &BinaryNode) -> BinaryNode {
        match &node.content {
            Some(baileys_core::BinaryContent::Children(c)) => c[0].clone(),
            _ => panic!("sem filhos"),
        }
    }

    fn flow(buttons: Vec<NativeButton>) -> wa::Message {
        native_flow_message(NativeFlowSpec {
            text: "oi".into(),
            buttons,
            ..Default::default()
        })
    }

    #[test]
    fn hineken_mixed_for_quick_reply() {
        let node = button_addon_node(&flow(vec![NativeButton::quick_reply("A", "a")]), BizNodeMode::Hineken).unwrap();
        assert_eq!(node.tag, "biz");
        assert_eq!(node.attr("actual_actors"), Some("2"));
        assert_eq!(child_tags(&node), vec!["interactive", "quality_control"]);
        let nf = first_child(&first_child(&node));
        assert_eq!(nf.attr("name"), Some("mixed"));
        assert_eq!(nf.attr("v"), Some("9"));
    }

    #[test]
    fn zapo_is_bare_biz() {
        let node = button_addon_node(&flow(vec![NativeButton::cta_url("Site", "https://x")]), BizNodeMode::Zapo).unwrap();
        assert!(node.attrs.is_empty());
        assert_eq!(child_tags(&node), vec!["interactive"]);
    }

    #[test]
    fn payment_flows() {
        let pay = flow(vec![NativeButton::new("review_and_pay", json!({}))]);
        let h = button_addon_node(&pay, BizNodeMode::Hineken).unwrap();
        assert_eq!(h.attr("native_flow_name"), Some("order_details"));
        assert!(child_tags(&h).is_empty());
        let z = button_addon_node(&pay, BizNodeMode::Zapo).unwrap();
        assert_eq!(first_child(&first_child(&z)).attr("name"), Some("order_details"));
    }

    #[test]
    fn hineken_named_flow() {
        let msg = flow(vec![NativeButton::new("cta_catalog", json!({}))]);
        let node = button_addon_node(&msg, BizNodeMode::Hineken).unwrap();
        let nf = first_child(&first_child(&node));
        assert_eq!(nf.attr("name"), Some("cta_catalog"));
        assert_eq!(nf.attr("v"), Some("2"));
    }

    #[test]
    fn list_and_unwrap() {
        let list = list_message(ListSpec {
            text: "t".into(),
            button_text: "Ver".into(),
            ..Default::default()
        });
        let wrapped = wa::Message {
            view_once_message_v2: Some(Box::new(wa::message::FutureProofMessage {
                message: Some(Box::new(wrap_view_once(list))),
            })),
            ..Default::default()
        };
        let node = button_addon_node(&wrapped, BizNodeMode::Hineken).unwrap();
        let l = first_child(&node);
        assert_eq!(l.tag, "list");
        assert_eq!(l.attr("type"), Some("product_list"));
        assert!(button_addon_node(&wrapped, BizNodeMode::None).is_none());
    }

    #[test]
    fn plain_text_has_no_biz() {
        let msg = wa::Message { conversation: Some("oi".into()), ..Default::default() };
        assert!(button_addon_node(&msg, BizNodeMode::Hineken).is_none());
    }

    #[test]
    fn carousel_builds_cards() {
        let msg = carousel_message(CarouselSpec {
            text: "c".into(),
            cards: vec![CarouselCard {
                body: "card".into(),
                buttons: vec![NativeButton::quick_reply("A", "a")],
                ..Default::default()
            }],
            ..Default::default()
        });
        let im = msg.interactive_message.as_ref().unwrap();
        match im.interactive_message.as_ref().unwrap() {
            interactive_message::InteractiveMessage::CarouselMessage(c) => assert_eq!(c.cards.len(), 1),
            _ => panic!("não é carrossel"),
        }
        assert!(button_addon_node(&msg, BizNodeMode::Zapo).is_some());
    }

    #[test]
    fn parse_modes() {
        assert_eq!(BizNodeMode::parse("ZAPO"), Some(BizNodeMode::Zapo));
        assert_eq!(BizNodeMode::parse(""), Some(BizNodeMode::Hineken));
        assert_eq!(BizNodeMode::parse("none"), Some(BizNodeMode::None));
        assert_eq!(BizNodeMode::parse("x"), None);
    }
}
