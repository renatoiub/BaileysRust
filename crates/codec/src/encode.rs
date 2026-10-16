//! Encode WABinary — espelhando `WABinary/encode.ts`.

use std::collections::HashMap;

use baileys_core::{jid_decode, BinaryContent, BinaryNode};

use crate::constants::{tags, TOKEN_MAP};

pub struct EncodeOptions {
    pub token_map: HashMap<&'static str, (Option<usize>, usize)>,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self {
            token_map: TOKEN_MAP.clone(),
        }
    }
}

struct Encoder<'a> {
    buffer: Vec<u8>,
    opts: &'a EncodeOptions,
}

/// `encodeBinaryNode` — codifica um nó em bytes.
pub fn encode_binary_node(node: &BinaryNode) -> Vec<u8> {
    let opts = EncodeOptions::default();
    let mut enc = Encoder {
        buffer: vec![0],
        opts: &opts,
    };
    enc.encode_node(node);
    enc.buffer
}

impl<'a> Encoder<'a> {
    fn push_byte(&mut self, value: u8) {
        self.buffer.push(value);
    }

    fn push_int(&mut self, value: u64, n: usize) {
        for i in 0..n {
            let shift = (n - 1 - i) * 8;
            self.buffer.push(((value >> shift) & 0xFF) as u8);
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn push_int16(&mut self, value: u16) {
        self.push_bytes(&[(value >> 8) as u8, (value & 0xFF) as u8]);
    }

    fn push_int20(&mut self, value: u32) {
        self.push_bytes(&[
            ((value >> 16) & 0x0F) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]);
    }

    fn write_byte_length(&mut self, length: usize) {
        if length >= 4_294_967_296 {
            panic!("string too large to encode: {length}");
        }
        if length >= 1 << 20 {
            self.push_byte(tags::BINARY_32);
            self.push_int(length as u64, 4);
        } else if length >= 256 {
            self.push_byte(tags::BINARY_20);
            self.push_int20(length as u32);
        } else {
            self.push_byte(tags::BINARY_8);
            self.push_byte(length as u8);
        }
    }

    fn write_string_raw(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.write_byte_length(bytes.len());
        self.push_bytes(bytes);
    }

    fn write_jid(&mut self, user: &str, server: &str, device: Option<u32>) {
        if let Some(device) = device {
            self.push_byte(tags::AD_JID);
            // `domainType || 0` do Node: 1 para `@lid`, 0 para `@s.whatsapp.net`.
            // Sem isso, devices lid são codificados como `@s.whatsapp.net` no wire
            // e o servidor não resolve o usuário (encrypt IQ nunca responde).
            self.push_byte(if server == "lid" { 1 } else { 0 });
            self.push_byte(device as u8);
            self.write_string(user);
        } else {
            self.push_byte(tags::JID_PAIR);
            if !user.is_empty() {
                self.write_string(user);
            } else {
                self.push_byte(tags::LIST_EMPTY);
            }
            self.write_string(server);
        }
    }

    fn pack_nibble(&self, c: char) -> u8 {
        match c {
            '-' => 10,
            '.' => 11,
            '\0' => 15,
            '0'..='9' => c as u8 - b'0',
            _ => panic!("invalid byte for nibble \"{c}\""),
        }
    }

    fn pack_hex(&self, c: char) -> u8 {
        match c {
            '0'..='9' => c as u8 - b'0',
            'A'..='F' => 10 + c as u8 - b'A',
            'a'..='f' => 10 + c as u8 - b'a',
            '\0' => 15,
            _ => panic!("Invalid hex char \"{c}\""),
        }
    }

    fn write_packed_bytes(&mut self, s: &str, is_nibble: bool) {
        if s.len() > tags::PACKED_MAX as usize {
            panic!("Too many bytes to pack");
        }

        self.push_byte(if is_nibble { tags::NIBBLE_8 } else { tags::HEX_8 });

        let mut rounded_length = (s.len() as f64 / 2.0).ceil() as u8;
        if s.len() % 2 != 0 {
            rounded_length |= 128;
        }
        self.push_byte(rounded_length);

        let chars: Vec<char> = s.chars().collect();

        let half = chars.len() / 2;
        for i in 0..half {
            let a = chars[2 * i];
            let b = chars[2 * i + 1];
            let va = if is_nibble { self.pack_nibble(a) } else { self.pack_hex(a) };
            let vb = if is_nibble { self.pack_nibble(b) } else { self.pack_hex(b) };
            self.push_byte((va << 4) | vb);
        }
        if chars.len() % 2 != 0 {
            let last = chars[chars.len() - 1];
            let va = if is_nibble { self.pack_nibble(last) } else { self.pack_hex(last) };
            let vb = 15; // '\0'
            self.push_byte((va << 4) | vb);
        }
    }

    fn is_nibble(&self, s: &str) -> bool {
        if s.is_empty() || s.len() > tags::PACKED_MAX as usize {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == '.')
    }

    fn is_hex(&self, s: &str) -> bool {
        if s.is_empty() || s.len() > tags::PACKED_MAX as usize {
            return false;
        }
        s.chars().all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
    }

    fn write_string(&mut self, s: &str) {
        if let Some((dict, index)) = self.opts.token_map.get(s) {
            match dict {
                Some(d) => {
                    self.push_byte(tags::DICTIONARY_0 + *d as u8);
                }
                None => {}
            }
            self.push_byte(*index as u8);
        } else if self.is_nibble(s) {
            self.write_packed_bytes(s, true);
        } else if self.is_hex(s) {
            self.write_packed_bytes(s, false);
        } else if let Some(decoded) = jid_decode(s) {
            self.write_jid(&decoded.user, decoded.server.as_str(), decoded.device);
        } else {
            self.write_string_raw(s);
        }
    }

    fn write_list_start(&mut self, size: usize) {
        if size == 0 {
            self.push_byte(tags::LIST_EMPTY);
        } else if size < 256 {
            self.push_byte(tags::LIST_8);
            self.push_byte(size as u8);
        } else {
            self.push_byte(tags::LIST_16);
            self.push_int16(size as u16);
        }
    }

    fn encode_node(&mut self, node: &BinaryNode) {
        let attrs = node
            .attrs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .collect::<Vec<_>>();

        let content_count = match &node.content {
            None => 0,
            Some(BinaryContent::String(s)) if s.is_empty() => 0,
            Some(_) => 1,
        };

        self.write_list_start(2 * attrs.len() + 1 + content_count);
        self.write_string(&node.tag);

        for (k, v) in attrs {
            self.write_string(k);
            self.write_string(v);
        }

        match &node.content {
            Some(BinaryContent::String(s)) => {
                if !s.is_empty() {
                    self.write_string(s);
                }
            }
            Some(BinaryContent::Bytes(bytes)) => {
                self.write_byte_length(bytes.len());
                self.push_bytes(bytes);
            }
            Some(BinaryContent::Children(children)) => {
                self.write_list_start(children.len());
                for child in children {
                    self.encode_node(child);
                }
            }
            None => {}
        }
    }
}

/// Re-export útil: monta um nó com filhos via referências `jid_encode`.
pub fn encode_jid(node: &BinaryNode) -> Option<String> {
    if let Some(BinaryContent::String(s)) = &node.content {
        return Some(s.clone());
    }
    None
}

// Mantém `jid_encode` importado para uso futuro no encoder de AD_JID.
#[allow(unused_imports)]
use baileys_core::jid_encode as _jid_encode_unused;
