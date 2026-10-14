//! Utilidades de ID espelhando `Utils/generics.ts`.

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::jid::jid_decode;

/// `generateMessageID` — gera um ID de mensagem MD no formato `3EB0...`.
pub fn generate_message_id() -> String {
    let mut bytes = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("3EB0{}", hex_upper(&bytes))
}

/// `generateMessageIDV2` — ID baseado em hash SHA-256 do timestamp + user + random.
pub fn generate_message_id_v2(user_id: Option<&str>) -> String {
    let mut data = Vec::with_capacity(44);
    data.extend_from_slice(&(unix_timestamp_seconds() as u64).to_be_bytes());

    if let Some(user_id) = user_id {
        if let Some(decoded) = jid_decode(user_id) {
            data.extend_from_slice(decoded.user.as_bytes());
            data.extend_from_slice(b"@c.us");
        }
    }

    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);
    data.extend_from_slice(&random);

    let hash = Sha256::digest(&data);
    format!("3EB0{}", hex_upper(&hash)[..18].to_string())
}

/// `generateRegistrationId` — número de 14 bits a partir de 2 bytes aleatórios.
pub fn generate_registration_id() -> u32 {
    let mut bytes = [0u8; 2];
    rand::thread_rng().fill_bytes(&mut bytes);
    (u16::from_be_bytes(bytes) & 0x3FFF) as u32
}

/// `unixTimestampSeconds`
pub fn unix_timestamp_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Prefixo de tag MD: `bytes.readUInt16BE().bytes.readUInt16BE(2)-`.
pub fn generate_md_tag_prefix() -> String {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    let a = u16::from_be_bytes([bytes[0], bytes[1]]);
    let b = u16::from_be_bytes([bytes[2], bytes[3]]);
    format!("{a}.{b}-")
}

/// `encodeBigEndian` — codifica um número em big-endian com `n` bytes.
pub fn encode_big_endian(value: u32, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    for i in 0..n {
        out[i] = ((value >> (8 * (n - 1 - i))) & 0xFF) as u8;
    }
    out
}

/// `writeRandomPadMax16` — adiciona padding aleatório (1–16 bytes, PKCS-like).
pub fn write_random_pad_max16(msg: &[u8]) -> Vec<u8> {
    let mut pad = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut pad);
    let pad_length = (pad[0] & 0x0F) as usize + 1;

    let mut out = Vec::with_capacity(msg.len() + pad_length);
    out.extend_from_slice(msg);
    out.extend(std::iter::repeat(pad_length as u8).take(pad_length));
    out
}

/// `unpadRandomMax16` — remove o padding aleatório.
pub fn unpad_random_max16(e: &[u8]) -> Result<Vec<u8>, &'static str> {
    if e.is_empty() {
        return Err("unpadRandomMax16 given empty bytes");
    }
    let r = *e.last().unwrap() as usize;
    if r > e.len() {
        return Err("pad value larger than input");
    }
    Ok(e[..e.len() - r].to_vec())
}

/// `bytesToCrockford` — converte bytes para base32 Crockford (para pairing code).
pub fn bytes_to_crockford(buffer: &[u8]) -> String {
    const CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";
    let mut value: u32 = 0;
    let mut bit_count = 0;
    let mut out: Vec<char> = Vec::new();

    for &b in buffer {
        value = (value << 8) | b as u32;
        bit_count += 8;
        while bit_count >= 5 {
            out.push(CHARS[((value >> (bit_count - 5)) & 31) as usize] as char);
            bit_count -= 5;
        }
    }
    if bit_count > 0 {
        out.push(CHARS[((value << (5 - bit_count)) & 31) as usize] as char);
    }
    out.into_iter().collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_id_is_14_bits() {
        assert!(generate_registration_id() <= 0x3FFF);
    }

    #[test]
    fn pad_roundtrip() {
        let msg = b"hello world";
        let padded = write_random_pad_max16(msg);
        assert!(padded.len() > msg.len());
        let unpadded = unpad_random_max16(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }

    #[test]
    fn crockford_output_charset() {
        let s = bytes_to_crockford(&[0xAB, 0xCD, 0xEF, 0x01, 0x23]);
        assert!(s.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTVWXYZ".contains(c)));
    }

    #[test]
    fn big_endian_encoding() {
        assert_eq!(encode_big_endian(0x010203, 3), vec![1, 2, 3]);
    }
}
