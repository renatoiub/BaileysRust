//! SRTP — AES-128-CTR + HMAC-SHA1 (port de `services/call/srtp.ts`).
//!
//! WhatsApp usa auth tags de 4 bytes e label de derivação conforme RFC 3711.

use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::rtp::{RtpPacket, RtpHeader};
use crate::types::{
    SrtpKeyingMaterial, SRTP_AUTH_TAG_LEN, SRTP_LABEL_AUTH, SRTP_LABEL_ENCRYPTION, SRTP_LABEL_SALT,
};

type Aes128Ctr = Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// Erros de SRTP.
#[derive(Debug, thiserror::Error)]
pub enum SrtpError {
    #[error("packet too short: {0} bytes")]
    PacketTooShort(usize),
    #[error("no payload: {0}B total, {1}B header, auth={2}")]
    NoPayload(usize, usize, usize),
    #[error("invalid key/salt length")]
    InvalidKeying,
    #[error("rtp: {0}")]
    Rtp(#[from] crate::rtp::RtpError),
}

/// Contexto SRTP (uma direção).
pub struct SrtpContext {
    session_key: Vec<u8>,
    session_salt: Vec<u8>,
    auth_key: Vec<u8>,
    roc: u32,
    last_seq: u16,
    initialized: bool,
    auth_tag_len: usize,
}

impl SrtpContext {
    pub fn new(keying: &SrtpKeyingMaterial, auth_tag_len: Option<usize>) -> Result<Self, SrtpError> {
        let auth_tag_len = auth_tag_len.unwrap_or(SRTP_AUTH_TAG_LEN);
        Ok(Self {
            session_key: derive_key(keying, SRTP_LABEL_ENCRYPTION, 16)?,
            auth_key: derive_key(keying, SRTP_LABEL_AUTH, 20)?,
            session_salt: derive_key(keying, SRTP_LABEL_SALT, 14)?,
            roc: 0,
            last_seq: 0,
            initialized: false,
            auth_tag_len,
        })
    }

    pub fn set_auth_keying(&mut self, keying: &SrtpKeyingMaterial) -> Result<(), SrtpError> {
        self.auth_key = derive_key(keying, SRTP_LABEL_AUTH, 20)?;
        Ok(())
    }

    /// Protege um pacote RTP (criptografa payload + autentica).
    pub fn protect(&mut self, packet: &RtpPacket) -> Result<Vec<u8>, SrtpError> {
        self.update_roc(packet.header.sequence_number);
        let index = self.packet_index(packet.header.sequence_number);

        let header_size = packet.header.size();
        let mut output = vec![0u8; header_size + packet.payload.len() + self.auth_tag_len];

        packet.header.encode(&mut output)?;

        let iv = self.generate_iv(packet.header.ssrc, index);
        let mut cipher = Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into());
        let mut encrypted = packet.payload.clone();
        cipher.apply_keystream(&mut encrypted);
        output[header_size..header_size + packet.payload.len()].copy_from_slice(&encrypted);

        if self.auth_tag_len > 0 {
            let tag = self.compute_auth_tag(&output[..header_size + packet.payload.len()], self.roc);
            output[header_size + packet.payload.len()..].copy_from_slice(&tag[..self.auth_tag_len]);
        }

        Ok(output)
    }

    /// Desprotege um pacote SRTP (ignora auth tag; descriptografa payload).
    pub fn unprotect(&mut self, data: &[u8]) -> Result<RtpPacket, SrtpError> {
        if data.len() < 12 {
            return Err(SrtpError::PacketTooShort(data.len()));
        }

        let header = RtpHeader::decode(data).map_err(|_| SrtpError::PacketTooShort(data.len()))?;
        let header_size = header.size();
        if data.len() < header_size + self.auth_tag_len {
            return Err(SrtpError::PacketTooShort(data.len()));
        }
        let payload_len = data.len() - header_size - self.auth_tag_len;

        self.update_roc(header.sequence_number);
        let index = self.packet_index(header.sequence_number);

        let iv = self.generate_iv(header.ssrc, index);
        let mut cipher = Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into());
        let mut decrypted = data[header_size..header_size + payload_len].to_vec();
        cipher.apply_keystream(&mut decrypted);

        Ok(RtpPacket::new(header, decrypted))
    }

    fn update_roc(&mut self, seq: u16) {
        if !self.initialized {
            self.last_seq = seq;
            self.initialized = true;
            return;
        }

        // Rollover: queda maior que metade do espaço de sequência (32768).
        let diff = (seq as i32) - (self.last_seq as i32);
        if diff < -32768 {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = seq;
    }

    fn packet_index(&self, seq: u16) -> u64 {
        ((self.roc as u64) << 16) | seq as u64
    }

    fn generate_iv(&self, ssrc: u32, index: u64) -> Vec<u8> {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.session_salt);

        let ssrc_bytes = ssrc.to_be_bytes();
        for i in 0..4 {
            iv[4 + i] ^= ssrc_bytes[i];
        }

        let index_bytes = index.to_be_bytes();
        for i in 0..6 {
            iv[8 + i] ^= index_bytes[2 + i];
        }

        iv.to_vec()
    }

    fn compute_auth_tag(&self, data: &[u8], roc: u32) -> Vec<u8> {
        let mut mac = HmacSha1::new_from_slice(&self.auth_key).expect("hmac key");
        mac.update(data);
        mac.update(&roc.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

/// Sessão SRTP (send + recv).
pub struct SrtpSession {
    send_ctx: SrtpContext,
    recv_ctx: SrtpContext,
}

impl SrtpSession {
    pub fn new(
        send_key: &SrtpKeyingMaterial,
        recv_key: &SrtpKeyingMaterial,
        send_auth_len: Option<usize>,
        recv_auth_len: Option<usize>,
    ) -> Result<Self, SrtpError> {
        Ok(Self {
            send_ctx: SrtpContext::new(send_key, send_auth_len)?,
            recv_ctx: SrtpContext::new(recv_key, recv_auth_len)?,
        })
    }

    pub fn protect(&mut self, packet: &RtpPacket) -> Result<Vec<u8>, SrtpError> {
        self.send_ctx.protect(packet)
    }

    pub fn unprotect(&mut self, data: &[u8]) -> Result<RtpPacket, SrtpError> {
        self.recv_ctx.unprotect(data)
    }

    pub fn set_send_auth_keying(&mut self, keying: &SrtpKeyingMaterial) -> Result<(), SrtpError> {
        self.send_ctx.set_auth_keying(keying)
    }
}

/// `deriveKey` (RFC 3711): AES-128-CTR sobre zeros, IV = salt(14) || 0x0000 || label.
fn derive_key(
    keying: &SrtpKeyingMaterial,
    label: u8,
    length: usize,
) -> Result<Vec<u8>, SrtpError> {
    if keying.master_key.len() != 16 || keying.master_salt.len() != 14 {
        return Err(SrtpError::InvalidKeying);
    }

    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&keying.master_salt);
    iv[7] ^= label;

    let zeros = vec![0u8; length];
    let mut cipher = Aes128Ctr::new(keying.master_key.as_slice().into(), iv.as_slice().into());
    let mut out = zeros;
    cipher.apply_keystream(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_unprotect_roundtrip() {
        let keying = SrtpKeyingMaterial {
            master_key: vec![0x42u8; 16],
            master_salt: vec![0x24u8; 14],
        };
        let mut session = SrtpSession::new(&keying, &keying, None, None).unwrap();

        let mut rtp = crate::rtp::RtpSession::whatsapp_opus(0x12345678);
        let packet = rtp.create_packet(b"hello-srtp".to_vec(), true);

        let protected = session.protect(&packet).unwrap();
        assert_eq!(protected.len(), 12 + 10 + 4);

        let unprotected = session.unprotect(&protected).unwrap();
        assert_eq!(unprotected.payload, b"hello-srtp");
        assert_eq!(unprotected.header.ssrc, 0x12345678);
    }

    #[test]
    fn derive_key_matches_rfc3711_structure() {
        let keying = SrtpKeyingMaterial {
            master_key: vec![0xE1u8; 16],
            master_salt: vec![0x0Eu8; 14],
        };
        let enc = derive_key(&keying, SRTP_LABEL_ENCRYPTION, 16).unwrap();
        assert_eq!(enc.len(), 16);
        // Não pode ser todo zero (aplicou keystream).
        assert!(enc.iter().any(|b| *b != 0));
    }

    #[test]
    fn roc_rollover_detection() {
        let keying = SrtpKeyingMaterial {
            master_key: vec![1u8; 16],
            master_salt: vec![2u8; 14],
        };
        let mut ctx = SrtpContext::new(&keying, None).unwrap();
        // 0xFFFE → 0x0003 = wrap
        ctx.update_roc(0xFFFE);
        ctx.update_roc(0x0003);
        assert_eq!(ctx.roc, 1);
    }
}
