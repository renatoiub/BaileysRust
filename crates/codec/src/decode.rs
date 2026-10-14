//! Decode WABinary — espelhando `WABinary/decode.ts`.

use std::io::Read;

use baileys_core::{jid_encode, BinaryContent, BinaryNode, JidServer};

use crate::constants::{tags, DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS};

/// `decompressingIfRequired` — remove o byte de flag e infla se necessário.
pub fn decompress_if_required(buffer: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if buffer.is_empty() {
        return Err(DecodeError::EndOfStream);
    }
    if buffer[0] & 2 != 0 {
        let mut decoder = flate2::read::ZlibDecoder::new(&buffer[1..]);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).map_err(DecodeError::Inflate)?;
        Ok(out)
    } else {
        Ok(buffer[1..].to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("end of stream")]
    EndOfStream,
    #[error("invalid node")]
    InvalidNode,
    #[error("invalid string with tag: {0}")]
    InvalidStringTag(u8),
    #[error("invalid tag for list size: {0}")]
    InvalidListTag(u8),
    #[error("invalid nibble: {0}")]
    InvalidNibble(u8),
    #[error("invalid hex: {0}")]
    InvalidHex(u8),
    #[error("invalid jid pair: {0}")]
    InvalidJidPair(String),
    #[error("inflate failed: {0}")]
    Inflate(std::io::Error),
    #[error("unknown tag: {0}")]
    UnknownTag(u8),
}

struct Decoder<'a> {
    buffer: &'a [u8],
    index: usize,
}

impl<'a> Decoder<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, index: 0 }
    }

    fn check_eos(&self, length: usize) -> Result<(), DecodeError> {
        if self.index + length > self.buffer.len() {
            Err(DecodeError::EndOfStream)
        } else {
            Ok(())
        }
    }

    fn next(&mut self) -> Result<u8, DecodeError> {
        self.check_eos(1)?;
        let v = self.buffer[self.index];
        self.index += 1;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        self.check_eos(n)?;
        let v = &self.buffer[self.index..self.index + n];
        self.index += n;
        Ok(v)
    }

    fn read_string_from_chars(&mut self, length: usize) -> Result<String, DecodeError> {
        let bytes = self.read_bytes(length)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn read_int(&mut self, n: usize) -> Result<u64, DecodeError> {
        self.check_eos(n)?;
        let mut val = 0u64;
        for _ in 0..n {
            val = (val << 8) | self.next()? as u64;
        }
        Ok(val)
    }

    fn read_int20(&mut self) -> Result<u32, DecodeError> {
        self.check_eos(3)?;
        let a = self.next()? as u32;
        let b = self.next()? as u32;
        let c = self.next()? as u32;
        Ok(((a & 15) << 16) + (b << 8) + c)
    }

    fn unpack_hex(&self, value: u8) -> Result<u8, DecodeError> {
        match value {
            0..=9 => Ok(b'0' + value),
            10..=15 => Ok(b'A' + value - 10),
            _ => Err(DecodeError::InvalidHex(value)),
        }
    }

    fn unpack_nibble(&self, value: u8) -> Result<u8, DecodeError> {
        match value {
            0..=9 => Ok(b'0' + value),
            10 => Ok(b'-'),
            11 => Ok(b'.'),
            15 => Ok(0),
            _ => Err(DecodeError::InvalidNibble(value)),
        }
    }

    fn unpack_byte(&self, tag: u8, value: u8) -> Result<u8, DecodeError> {
        if tag == tags::NIBBLE_8 {
            self.unpack_nibble(value)
        } else if tag == tags::HEX_8 {
            self.unpack_hex(value)
        } else {
            Err(DecodeError::UnknownTag(tag))
        }
    }

    fn read_packed8(&mut self, tag: u8) -> Result<String, DecodeError> {
        let start_byte = self.next()?;
        let mut value = String::new();
        for _ in 0..(start_byte & 127) {
            let cur = self.next()?;
            value.push(self.unpack_byte(tag, (cur & 0xF0) >> 4)? as char);
            value.push(self.unpack_byte(tag, cur & 0x0F)? as char);
        }
        if start_byte >> 7 != 0 {
            value.pop();
        }
        Ok(value)
    }

    fn is_list_tag(&self, tag: u8) -> bool {
        tag == tags::LIST_EMPTY || tag == tags::LIST_8 || tag == tags::LIST_16
    }

    fn read_list_size(&mut self, tag: u8) -> Result<usize, DecodeError> {
        match tag {
            tags::LIST_EMPTY => Ok(0),
            tags::LIST_8 => Ok(self.next()? as usize),
            tags::LIST_16 => Ok(self.read_int(2)? as usize),
            _ => Err(DecodeError::InvalidListTag(tag)),
        }
    }

    fn read_jid_pair(&mut self) -> Result<String, DecodeError> {
        let i = self.read_string_from_next_tag()?;
        let j = self.read_string_from_next_tag()?;
        if !j.is_empty() {
            Ok(format!("{i}@{j}"))
        } else {
            Err(DecodeError::InvalidJidPair(format!("{i}, {j}")))
        }
    }

    fn read_ad_jid(&mut self) -> Result<String, DecodeError> {
        let domain_type = self.next()?;
        let device = self.next()?;
        let user = self.read_string_from_next_tag()?;
        let server = if domain_type == 0 || domain_type == 128 {
            JidServer::SWhatsappNet
        } else {
            JidServer::Lid
        };
        Ok(jid_encode(&user, server, Some(device as u32)))
    }

    fn read_string(&mut self, tag: u8) -> Result<String, DecodeError> {
        if tag >= 1 && (tag as usize) < SINGLE_BYTE_TOKENS.len() {
            return Ok(SINGLE_BYTE_TOKENS[tag as usize].to_string());
        }

        match tag {
            tags::DICTIONARY_0 | tags::DICTIONARY_1 | tags::DICTIONARY_2 | tags::DICTIONARY_3 => {
                let dict_index = (tag - tags::DICTIONARY_0) as usize;
                let index = self.next()? as usize;
                let dict = DOUBLE_BYTE_TOKENS
                    .get(dict_index)
                    .ok_or(DecodeError::InvalidStringTag(tag))?;
                dict.get(index)
                    .map(|s| s.to_string())
                    .ok_or(DecodeError::InvalidStringTag(tag))
            }
            tags::LIST_EMPTY => Ok(String::new()),
            tags::BINARY_8 => {
                let len = self.next()? as usize;
                self.read_string_from_chars(len)
            }
            tags::BINARY_20 => {
                let len = self.read_int20()? as usize;
                self.read_string_from_chars(len)
            }
            tags::BINARY_32 => {
                let len = self.read_int(4)? as usize;
                self.read_string_from_chars(len)
            }
            tags::JID_PAIR => self.read_jid_pair(),
            tags::AD_JID => self.read_ad_jid(),
            tags::HEX_8 | tags::NIBBLE_8 => self.read_packed8(tag),
            _ => Err(DecodeError::InvalidStringTag(tag)),
        }
    }

    fn read_string_from_next_tag(&mut self) -> Result<String, DecodeError> {
        let tag = self.next()?;
        self.read_string(tag)
    }

    fn read_list(&mut self, tag: u8) -> Result<Vec<BinaryNode>, DecodeError> {
        let size = self.read_list_size(tag)?;
        let mut items = Vec::with_capacity(size);
        for _ in 0..size {
            items.push(self.decode_node()?);
        }
        Ok(items)
    }

    fn decode_node(&mut self) -> Result<BinaryNode, DecodeError> {
        let list_size_tag = self.next()?;
        let list_size = self.read_list_size(list_size_tag)?;
        let header = self.read_string_from_next_tag()?;
        if list_size == 0 || header.is_empty() {
            return Err(DecodeError::InvalidNode);
        }

        let attrs_len = (list_size - 1) >> 1;
        let mut attrs = Vec::with_capacity(attrs_len);
        for _ in 0..attrs_len {
            let key = self.read_string_from_next_tag()?;
            let value = self.read_string_from_next_tag()?;
            attrs.push((key, value));
        }

        let mut content: Option<BinaryContent> = None;
        if list_size % 2 == 0 {
            let tag = self.next()?;
            if self.is_list_tag(tag) {
                content = Some(BinaryContent::Children(self.read_list(tag)?));
            } else {
                let decoded = match tag {
                    tags::BINARY_8 => {
                        let len = self.next()? as usize;
                        self.read_bytes(len)?.to_vec()
                    }
                    tags::BINARY_20 => {
                        let len = self.read_int20()? as usize;
                        self.read_bytes(len)?.to_vec()
                    }
                    tags::BINARY_32 => {
                        let len = self.read_int(4)? as usize;
                        self.read_bytes(len)?.to_vec()
                    }
                    _ => self.read_string(tag)?.into_bytes(),
                };
                content = Some(BinaryContent::Bytes(decoded));
            }
        }

        Ok(BinaryNode {
            tag: header,
            attrs,
            content,
        })
    }
}

/// `decodeBinaryNode` — decodifica um buffer em nó (com descompressão se necessário).
///
/// Espelha o `decodeBinaryNode` do Baileys: primeiro `decompressingIfRequired`
/// (remove o byte prefixo `0x00` ou infla zlib `0x02`), depois decodifica.
pub fn decode_binary_node(buff: &[u8]) -> Result<BinaryNode, DecodeError> {
    let decompressed = decompress_if_required(buff)?;
    let mut decoder = Decoder::new(&decompressed);
    decoder.decode_node()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_binary_node;

    #[test]
    fn decode_requires_compressed_stripped() {
        // Nó "iq" vazio: prefixo 0x00 (sem compressão), LIST_8 com 1 elemento
        // (o tag), tag "iq" = single-byte 0x19.
        let encoded = vec![0x00, tags::LIST_8, 1, 0x19];
        let node = decode_binary_node(&encoded).unwrap();
        assert_eq!(node.tag, "iq");
        assert!(node.attrs.is_empty());
    }

    #[test]
    fn ad_jid_lid_device_roundtrip() {
        // Um JID de device `@lid` deve codificar com domainType=1 e voltar igual.
        let node = BinaryNode::new("user").with_attr("jid", "209354640896217:1@lid");
        let encoded = encode_binary_node(&node);
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded.attr("jid"), Some("209354640896217:1@lid"));
    }

    #[test]
    fn ad_jid_swhatsapp_device_roundtrip() {
        // Um JID de device `@s.whatsapp.net` deve codificar com domainType=0.
        let node = BinaryNode::new("user").with_attr("jid", "5511999999999:12@s.whatsapp.net");
        let encoded = encode_binary_node(&node);
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded.attr("jid"), Some("5511999999999:12@s.whatsapp.net"));
    }
}