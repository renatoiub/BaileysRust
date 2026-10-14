//! RTP — header/packet/session (port de `services/call/rtp.ts`).

use rand::RngCore;

use crate::types::{PayloadType, RtpConfig};

const RTP_VERSION: u8 = 2;
const MIN_HEADER_SIZE: usize = 12;

/// Erros de RTP.
#[derive(Debug, thiserror::Error)]
pub enum RtpError {
    #[error("buffer too small for RTP header")]
    BufferTooSmall,
    #[error("invalid RTP version: {0}")]
    InvalidVersion(u8),
    #[error("buffer too small for CSRC list")]
    CsrcTooSmall,
}

/// Cabeçalho RTP.
#[derive(Debug, Clone, Default)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc: Vec<u32>,
    pub extension_profile: u16,
    pub extension_data: Vec<u8>,
}

impl RtpHeader {
    pub fn new(payload_type: u8, sequence_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            version: RTP_VERSION,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            ..Default::default()
        }
    }

    pub fn size(&self) -> usize {
        let mut s = MIN_HEADER_SIZE + self.csrc_count as usize * 4;
        if self.extension {
            s += 4 + self.extension_data.len();
        }
        s
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, RtpError> {
        if buf.len() < self.size() {
            return Err(RtpError::BufferTooSmall);
        }

        buf[0] = ((self.version & 0x03) << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension as u8) << 4)
            | (self.csrc_count & 0x0f);
        buf[1] = ((self.marker as u8) << 7) | (self.payload_type & 0x7f);
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut offset = 12;
        for c in &self.csrc {
            buf[offset..offset + 4].copy_from_slice(&c.to_be_bytes());
            offset += 4;
        }

        if self.extension {
            buf[offset..offset + 2].copy_from_slice(&self.extension_profile.to_be_bytes());
            buf[offset + 2..offset + 4]
                .copy_from_slice(&((self.extension_data.len() / 4) as u16).to_be_bytes());
            buf[offset + 4..offset + 4 + self.extension_data.len()]
                .copy_from_slice(&self.extension_data);
        }

        Ok(self.size())
    }

    pub fn encode_vec(&self) -> Result<Vec<u8>, RtpError> {
        let mut out = vec![0u8; self.size()];
        self.encode(&mut out)?;
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, RtpError> {
        if buf.len() < MIN_HEADER_SIZE {
            return Err(RtpError::BufferTooSmall);
        }

        let version = (buf[0] >> 6) & 0x03;
        if version != RTP_VERSION {
            return Err(RtpError::InvalidVersion(version));
        }

        let padding = ((buf[0] >> 5) & 0x01) != 0;
        let extension = ((buf[0] >> 4) & 0x01) != 0;
        let csrc_count = buf[0] & 0x0f;
        let marker = ((buf[1] >> 7) & 0x01) != 0;
        let payload_type = buf[1] & 0x7f;
        let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let header_size = MIN_HEADER_SIZE + csrc_count as usize * 4;
        if buf.len() < header_size {
            return Err(RtpError::CsrcTooSmall);
        }

        let mut csrc = Vec::with_capacity(csrc_count as usize);
        let mut offset = 12;
        for _ in 0..csrc_count {
            let v = u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
            csrc.push(v);
            offset += 4;
        }

        let mut header = RtpHeader::new(payload_type, sequence_number, timestamp, ssrc);
        header.version = version;
        header.padding = padding;
        header.extension = extension;
        header.csrc_count = csrc_count;
        header.marker = marker;
        header.csrc = csrc;

        if extension && buf.len() >= offset + 4 {
            header.extension_profile = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let ext_words = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let ext_bytes = ext_words as usize * 4;
            offset += 4;
            if buf.len() >= offset + ext_bytes {
                header.extension_data = buf[offset..offset + ext_bytes].to_vec();
            }
        }

        Ok(header)
    }
}

/// Pacote RTP.
#[derive(Debug, Clone)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    pub fn new(header: RtpHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    pub fn size(&self) -> usize {
        self.header.size() + self.payload.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, RtpError> {
        let mut buf = vec![0u8; self.size()];
        let header_size = self.header.encode(&mut buf)?;
        buf[header_size..].copy_from_slice(&self.payload);
        Ok(buf)
    }

    pub fn decode(buf: &[u8]) -> Result<Self, RtpError> {
        let header = RtpHeader::decode(buf)?;
        let payload = buf[header.size()..].to_vec();
        Ok(Self::new(header, payload))
    }
}

/// Sessão RTP — mantém seq/timestamp/ssrc.
#[derive(Debug, Clone)]
pub struct RtpSession {
    ssrc: u32,
    payload_type: u8,
    sequence_number: u16,
    sample_rate: u32,
    timestamp: u32,
    samples_per_packet: u32,
}

impl RtpSession {
    pub fn new(ssrc: u32, payload_type: u8, sample_rate: u32, samples_per_packet: u32) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            ssrc,
            payload_type,
            sequence_number: (rng.next_u32() & 0xFFFF) as u16,
            sample_rate,
            timestamp: rng.next_u32(),
            samples_per_packet,
        }
    }

    /// WhatsApp Opus usa clock RTP de 16 kHz (matches Go rtp.go).
    pub fn whatsapp_opus(ssrc: u32) -> Self {
        Self::new(ssrc, PayloadType::WhatsAppOpus as u8, 16000, 960)
    }

    pub fn from_config(config: &RtpConfig) -> Self {
        Self::new(
            config.ssrc,
            config.payload_type,
            config.sample_rate,
            config.samples_per_packet,
        )
    }

    pub fn create_packet(&mut self, payload: Vec<u8>, marker: bool) -> RtpPacket {
        let header = RtpHeader::new(
            self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc,
        )
        .with_marker(marker);

        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(self.samples_per_packet);

        RtpPacket::new(header, payload)
    }

    pub fn create_packet_with_duration(
        &mut self,
        payload: Vec<u8>,
        duration_samples: u32,
        marker: bool,
    ) -> RtpPacket {
        let header = RtpHeader::new(
            self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc,
        )
        .with_marker(marker);

        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(duration_samples);

        RtpPacket::new(header, payload)
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

impl RtpHeader {
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = RtpHeader::new(120, 0x1234, 0xDEADBEEF, 0x01020304).with_marker(true);
        let encoded = header.encode_vec().unwrap();
        assert_eq!(encoded.len(), 12);
        let decoded = RtpHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.payload_type, 120);
        assert_eq!(decoded.sequence_number, 0x1234);
        assert_eq!(decoded.timestamp, 0xDEADBEEF);
        assert_eq!(decoded.ssrc, 0x01020304);
        assert!(decoded.marker);
    }

    #[test]
    fn packet_roundtrip() {
        let mut session = RtpSession::whatsapp_opus(0xAABBCCDD);
        let packet = session.create_packet(vec![1, 2, 3, 4], true);
        let encoded = packet.encode().unwrap();
        let decoded = RtpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
        assert_eq!(decoded.header.ssrc, 0xAABBCCDD);
    }

    #[test]
    fn session_increments() {
        let mut session = RtpSession::whatsapp_opus(1);
        let p1 = session.create_packet(vec![0], false);
        let p2 = session.create_packet(vec![0], false);
        assert_eq!(p2.header.sequence_number, p1.header.sequence_number.wrapping_add(1));
        assert_eq!(p2.header.timestamp, p1.header.timestamp.wrapping_add(960));
    }
}
