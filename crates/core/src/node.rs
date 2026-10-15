//! Tipo `BinaryNode` — a estrutura de nós que o WhatsApp usa na comunicação.

use serde::{Deserialize, Serialize};

/// Nó binário, espelhando `WABinary/types.ts`.
///
/// É mantido como dado puro (sem métodos) para facilitar serialização,
/// da mesma forma que o Baileys faz.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryNode {
    pub tag: String,
    #[serde(default)]
    pub attrs: Vec<(String, String)>,
    pub content: Option<BinaryContent>,
}

/// Conteúdo de um nó: filhos, string ou bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BinaryContent {
    Children(Vec<BinaryNode>),
    String(String),
    Bytes(Vec<u8>),
}

impl BinaryNode {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attrs: Vec::new(),
            content: None,
        }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((key.into(), value.into()));
        self
    }

    pub fn with_children(mut self, children: Vec<BinaryNode>) -> Self {
        self.content = Some(BinaryContent::Children(children));
        self
    }

    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.content = Some(BinaryContent::Bytes(bytes));
        self
    }

    pub fn with_string(mut self, s: impl Into<String>) -> Self {
        self.content = Some(BinaryContent::String(s.into()));
        self
    }

    /// Retorna o valor de um atributo por chave.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Retorna o primeiro filho com o `tag` dado.
    pub fn child(&self, tag: &str) -> Option<&BinaryNode> {
        match &self.content {
            Some(BinaryContent::Children(children)) => children.iter().find(|c| c.tag == tag),
            _ => None,
        }
    }

    /// Retorna todos os filhos com o `tag` dado.
    pub fn children(&self, tag: &str) -> Vec<&BinaryNode> {
        match &self.content {
            Some(BinaryContent::Children(children)) => children.iter().filter(|c| c.tag == tag).collect(),
            _ => Vec::new(),
        }
    }

    /// Retorna o conteúdo do primeiro filho com o `tag` dado como bytes.
    pub fn child_bytes(&self, tag: &str) -> Option<&[u8]> {
        match self.child(tag)?.content.as_ref()? {
            BinaryContent::Bytes(b) => Some(b.as_slice()),
            BinaryContent::String(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// Retorna o conteúdo do primeiro filho com o `tag` dado como string.
    pub fn child_string(&self, tag: &str) -> Option<&str> {
        match self.child(tag)?.content.as_ref()? {
            BinaryContent::String(s) => Some(s.as_str()),
            BinaryContent::Bytes(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    /// Retorna o conteúdo do próprio nó como texto (String ou bytes UTF-8).
    pub fn content_text(&self) -> String {
        match &self.content {
            Some(BinaryContent::String(s)) => s.clone(),
            Some(BinaryContent::Bytes(b)) => String::from_utf8_lossy(b).to_string(),
            _ => String::new(),
        }
    }
}
