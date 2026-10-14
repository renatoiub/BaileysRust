//! Derivação de chaves SRTP por JID (port de `services/call/encryption.ts`).

use rand::RngCore;

use crate::types::SrtpKeyingMaterial;

/// `derivePerJidSrtpKey` — HKDF-SHA256 do callKey com info = deviceJid.
///
/// Saída de 46 bytes: masterKey = [0..16], masterSalt = [16..30].
pub fn derive_per_jid_srtp_key(
    call_key: &[u8],
    device_jid: &str,
) -> Result<SrtpKeyingMaterial, baileys_crypto::error::CryptoError> {
    let output = baileys_crypto::hkdf(call_key, 46, None, device_jid)?;
    Ok(SrtpKeyingMaterial {
        master_key: output[0..16].to_vec(),
        master_salt: output[16..30].to_vec(),
    })
}

/// `generateCallKey` — 32 bytes aleatórios.
pub fn generate_call_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key.to_vec()
}

/// `generateSecureSsrc` — HKDF-SHA256 com salt = counter (LE) e info = jid.
pub fn generate_secure_ssrc(call_id: &str, self_jid: &str, counter: u32) -> u32 {
    let key = call_id.as_bytes();
    let salt = counter.to_le_bytes();
    let info = self_jid.as_bytes();

    // hkdfSync("sha256", key, salt, info, 4) → u32 LE.
    // O baileys `hkdf` aceita salt como bytes; aqui passamos o salt diretamente.
    let output = hkdf_with_salt(key, Some(&salt), info, 4);
    u32::from_le_bytes([output[0], output[1], output[2], output[3]])
}

/// HKDF-SHA256 com salt explícito (o helper público `baileys_crypto::hkdf`
/// usa `None`; aqui precisamos do salt = counter LE).
fn hkdf_with_salt(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let salt = salt.unwrap_or(&[]);
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_key_is_32_bytes() {
        let key = generate_call_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn per_jid_key_splits_16_14() {
        let call_key = vec![0xABu8; 32];
        let keying = derive_per_jid_srtp_key(&call_key, "peer@s.whatsapp.net").unwrap();
        assert_eq!(keying.master_key.len(), 16);
        assert_eq!(keying.master_salt.len(), 14);
    }

    #[test]
    fn secure_ssrc_deterministic() {
        let a = generate_secure_ssrc("call-id", "me@s.whatsapp.net", 0);
        let b = generate_secure_ssrc("call-id", "me@s.whatsapp.net", 0);
        assert_eq!(a, b);
        let c = generate_secure_ssrc("call-id", "me@s.whatsapp.net", 1);
        assert_ne!(a, c);
    }
}
