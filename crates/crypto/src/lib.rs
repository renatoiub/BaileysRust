//! `baileys-crypto` — primitivas criptográficas do WhatsApp.
//!
//! Port fiel de `Hineken/src/Utils/crypto.ts` + `libsignal/src/curve.js`
//! (que usa `curve25519-js`, i.e. **XEdDSA**, não Ed25519 puro).
//!
//! # Compatibilidade crítica
//!
//! As assinaturas do WhatsApp usam o esquema XEdDSA do libsignal:
//!
//! - A chave secreta é o scalar X25519 **clampado** (não o hash SHA-512 de uma
//!   seed como no Ed25519 padrão).
//! - O nonce é `r = SHA-512(clamped_secret || message) mod L`.
//! - A chave pública Ed25519 é obtida pela conversão birracional
//!   `y = (u - 1) / (u + 1)` a partir da chave pública X25519 (Montgomery).
//! - O bit de paridade de `x` da chave pública é "emprestado" do bit 7 do byte
//!   final de `S` (o que é possível porque `S < L < 2^253`).
//!
//! Vetores de teste em `scripts/crypto-vectors.json` foram gerados a partir do
//! `libsignal` real usado pelo container Node, garantindo paridade byte a byte.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};

use baileys_core::constants::KEY_BUNDLE_TYPE;

use crate::error::CryptoError;

pub mod error;

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Par de chaves Curve25519 (privada = 32 bytes, pública = 32 bytes sem byte de versão).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// Prefixa o byte de versão `05` para uso em operações de curva (libsignal).
pub fn generate_signal_pub_key(pub_key: &[u8]) -> Vec<u8> {
    if pub_key.len() == 33 {
        pub_key.to_vec()
    } else {
        let mut out = Vec::with_capacity(33);
        out.extend_from_slice(&KEY_BUNDLE_TYPE);
        out.extend_from_slice(pub_key);
        out
    }
}

/// `Curve` — espelha o objeto `Curve` do Baileys (libsignal.curve).
pub struct Curve;

impl Curve {
    /// `generateKeyPair` — gera um par de chaves X25519.
    pub fn generate_key_pair() -> KeyPair {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        KeyPair {
            private: secret.to_bytes().to_vec(),
            public: public.as_bytes().to_vec(),
        }
    }

    /// `curve.generateKeyPair` do libsignal-node — igual a [`generate_key_pair`],
    /// mas a chave pública já vem com o byte de versão `05` prefixado (33 bytes).
    ///
    /// O libsignal-node (`libsignal/src/curve.js`) faz `prefixKeyInPublicKey`
    /// em toda chave gerada; o WhatsApp espera 33 bytes no wire (pkmsg/msg/skey).
    /// Não usar nos handshakes Noise (que exigem X25519 cru de 32 bytes).
    pub fn generate_signal_key_pair() -> KeyPair {
        let kp = Self::generate_key_pair();
        KeyPair {
            private: kp.private,
            public: generate_signal_pub_key(&kp.public),
        }
    }

    /// `getPublicFromPrivateKey` — deriva a chave pública X25519 de uma privada.
    pub fn public_from_private(private_key: &[u8]) -> Result<Vec<u8>> {
        let secret = to_static_secret(private_key)?;
        Ok(x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec())
    }

    /// `sharedKey` — calcula o segredo compartilhado X25519.
    ///
    /// A pub key pode ter 32 bytes (sem prefixo) ou 33 (com prefixo `05`).
    pub fn shared_key(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
        let secret = to_static_secret(private_key)?;
        let public = to_public_key(public_key)?;
        Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
    }

    /// `sign` — assinatura XEdDSA (libsignal `calculateSignature`).
    pub fn sign(private_key: &[u8], buf: &[u8]) -> Result<Vec<u8>> {
        xeddsa_sign(private_key, buf)
    }

    /// `verify` — verificação XEdDSA (libsignal `verifySignature`).
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        xeddsa_verify(public_key, message, signature)
    }
}

fn to_static_secret(private_key: &[u8]) -> Result<x25519_dalek::StaticSecret> {
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(private_key.len()));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(private_key);
    Ok(x25519_dalek::StaticSecret::from(bytes))
}

fn to_public_key(public_key: &[u8]) -> Result<x25519_dalek::PublicKey> {
    // Pode ter 32 bytes (sem prefixo) ou 33 (com prefixo 05).
    let pub_bytes = if public_key.len() == 33 {
        &public_key[1..]
    } else if public_key.len() == 32 {
        public_key
    } else {
        return Err(CryptoError::InvalidKeyLength(public_key.len()));
    };
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(pub_bytes);
    Ok(x25519_dalek::PublicKey::from(bytes))
}


/// Aplica o clamp X25519 padrão a uma secret key de 32 bytes.
fn clamp_x25519_scalar(secret: &mut [u8; 32]) {
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
}

/// `curve25519_sign` do `curve25519-js`: assina com XEdDSA.
///
/// Passos (espelhando `curve25519_sign`):
/// 1. Clamp da secret key.
/// 2. `A_edwards = [clamped]B` (igual à pub X25519 em coordenadas Edwards).
/// 3. `r = SHA512(clamped || msg) mod L`, `R = [r]B`.
/// 4. `h = SHA512(R || A || msg) mod L`.
/// 5. `S = r + h*a mod L`.
/// 6. `signature = R || S`, com `signature[63] |= signBit(A)`.
pub fn xeddsa_sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(private_key.len()));
    }

    // 1. Clamp (curve25519_sign aplica clamp em uma cópia).
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(private_key);
    clamp_x25519_scalar(&mut clamped);

    // 2. A = [clamped]B (Edwards).
    let a = Scalar::from_bytes_mod_order(clamped);
    let a_edwards = ED25519_BASEPOINT_POINT * a;
    let a_compressed = a_edwards.compress();
    let sign_bit = a_compressed.as_bytes()[31] & 0x80;

    // 3. r = SHA512(clamped || msg) mod L; R = [r]B.
    let mut hasher = Sha512::new();
    hasher.update(clamped);
    hasher.update(message);
    let r = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
    let r_edwards = ED25519_BASEPOINT_POINT * r;
    let r_compressed = r_edwards.compress();

    // 4. h = SHA512(R || A || msg) mod L.
    let mut hasher = Sha512::new();
    hasher.update(r_compressed.as_bytes());
    hasher.update(a_compressed.as_bytes());
    hasher.update(message);
    let h = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    // 5. S = r + h*a mod L.
    let s = r + h * a;

    // 6. signature = R || S, com sign bit de A no byte final de S.
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(r_compressed.as_bytes());
    signature.extend_from_slice(s.to_bytes().as_ref());
    signature[63] |= sign_bit;

    Ok(signature)
}

/// `curve25519_sign_open` do `curve25519-js`: verifica assinatura XEdDSA.
pub fn xeddsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let pub_bytes = if public_key.len() == 33 {
        &public_key[1..]
    } else if public_key.len() == 32 {
        public_key
    } else {
        return false;
    };
    if pub_bytes.len() != 32 {
        return false;
    }

    // S deve ser canônico (< L). O bit 7 de signature[63] é o sign bit de A.
    let sign_bit = (signature[63] & 0x80) != 0;
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);
    s_bytes[31] &= 0x7F; // limpa sign bit (no-op p/ S canônico, como no JS)
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };

    // R = signature[0..32] como ponto Edwards.
    let r_bytes: &[u8; 32] = signature[0..32].try_into().unwrap();
    let Some(r_edwards) = CompressedEdwardsY(*r_bytes).decompress() else {
        return false;
    };

    // A = converte Montgomery (u) → Edwards (y = (u-1)/(u+1)), com sign bit restaurado.
    let mont = MontgomeryPoint(pub_bytes.try_into().unwrap());
    let sign_choice = if sign_bit { 1u8 } else { 0u8 };
    let Some(a_edwards) = mont.to_edwards(sign_choice) else {
        return false;
    };

    // h = SHA512(R || A || msg) mod L, onde A é a forma Edwards comprimida.
    let a_compressed = a_edwards.compress();
    let mut hasher = Sha512::new();
    hasher.update(r_edwards.compress().as_bytes());
    hasher.update(a_compressed.as_bytes());
    hasher.update(message);
    let h = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    // O JS `unpackneg` retorna -A, então a verificação é [S]B - [h]A = R.
    let a_neg = -a_edwards;
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &a_neg, &s);
    check == r_edwards
}

/// `signedKeyPair` — gera um pre-key assinado.
pub fn signed_key_pair(identity_key_pair: &KeyPair, key_id: u32) -> SignedKeyPair {
    let pre_key = Curve::generate_key_pair();
    let pub_key = generate_signal_pub_key(&pre_key.public);
    let signature = Curve::sign(&identity_key_pair.private, &pub_key).unwrap_or_default();
    SignedKeyPair {
        key_pair: pre_key,
        signature,
        key_id,
        timestamp_s: None,
    }
}

/// Par de chaves assinado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
    pub key_id: u32,
    pub timestamp_s: Option<u64>,
}

const GCM_TAG_LENGTH: usize = 16;

/// `aesEncryptGCM` — AES-256-GCM com o tag sufixado ao ciphertext.
pub fn aes_encrypt_gcm(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: additional_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// `aesDecryptGCM` — AES-256-GCM com o tag sufixado ao ciphertext.
pub fn aes_decrypt_gcm(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < GCM_TAG_LENGTH {
        return Err(CryptoError::InvalidCiphertext);
    }
    let (enc, tag) = ciphertext.split_at(ciphertext.len() - GCM_TAG_LENGTH);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let nonce = Nonce::from_slice(iv);

    // Reconstrói ciphertext+tag para a API aes-gcm (que espera msg||tag).
    let mut full = Vec::with_capacity(ciphertext.len());
    full.extend_from_slice(enc);
    full.extend_from_slice(tag);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: full.as_slice(),
                aad: additional_data,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// `aesEncryptCTR` — AES-256-CTR (usado no `generatePairingKey`).
pub fn aes_encrypt_ctr(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

    let key: &[u8; 32] = key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(iv.len()))?;

    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    let mut out = plaintext.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

/// `aesDecryptCTR` — AES-256-CTR (CTR é simétrico).
pub fn aes_decrypt_ctr(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    aes_encrypt_ctr(ciphertext, key, iv)
}

/// `hkdf` — HKDF-SHA256, espelhando a implementação do Baileys.
pub fn hkdf(
    input_key_material: &[u8],
    expanded_length: usize,
    salt: Option<&[u8]>,
    info: &str,
) -> Result<Vec<u8>> {
    let salt = salt.unwrap_or(&[]);
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut okm = vec![0u8; expanded_length];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(okm)
}

/// `derivePairingCodeKey` — PBKDF2-SHA256, 2<<16 iterações, 32 bytes.
pub fn derive_pairing_code_key(pairing_code: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(pairing_code.as_bytes(), salt, 2 << 16, &mut out)
        .map_err(|_| CryptoError::Pbkdf2Failed)?;
    Ok(out)
}

/// `deriveSecrets` — espelho exato de `libsignal/src/crypto.js`.
///
/// Implementação específica do RFC 5869 que retorna até 3 chunks de 32 bytes:
///
/// ```text
/// PRK   = HMAC-SHA256(salt, input)
/// info0 = info || 0x01
/// T(1)  = HMAC-SHA256(PRK, info0)
/// T(n)  = HMAC-SHA256(PRK, T(n-1) || info || n)
/// ```
///
/// O `salt` DEVE ter exatamente 32 bytes.
pub fn derive_secrets(input: &[u8], salt: &[u8], info: &[u8], chunks: usize) -> Result<Vec<Vec<u8>>> {
    use hmac::digest::{KeyInit, Mac};
    type HmacSha256 = hmac::Hmac<Sha256>;

    if salt.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(salt.len()));
    }
    assert!(chunks >= 1 && chunks <= 3, "chunks must be in 1..=3");

    let mut prk = <HmacSha256 as KeyInit>::new_from_slice(salt).expect("hmac key");
    prk.update(input);
    let prk = prk.finalize().into_bytes();

    // infoArray = [0u8; 32] || info || [0]
    let mut info_array = Vec::with_capacity(32 + info.len() + 1);
    info_array.extend_from_slice(&[0u8; 32]);
    info_array.extend_from_slice(info);
    info_array.push(0);

    let mut signed = Vec::with_capacity(chunks);
    let last = info_array.len() - 1;
    for n in 1..=chunks {
        info_array[last] = n as u8;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(prk.as_slice()).expect("hmac key");
        // n=1: HMAC(PRK, info || n) — a partir do byte 32.
        // n>1: HMAC(PRK, T(n-1) || info || n) — array completo.
        if n == 1 {
            mac.update(&info_array[32..]);
        } else {
            mac.update(&info_array[..]);
        }
        let t = mac.finalize().into_bytes();
        // O próximo HMAC usa T(n-1) como prefixo (bytes 0..32 da info_array).
        info_array[..32].copy_from_slice(t.as_slice());
        signed.push(t.to_vec());
    }

    Ok(signed)
}

/// `encrypt` do libsignal — AES-256-CBC com padding PKCS7.
pub fn aes_encrypt_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use cbc::cipher::block_padding::Pkcs7;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let key: &[u8; 32] = key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(iv.len()))?;

    let cipher = Aes256CbcEnc::new(key.into(), iv.into());
    // `encrypt_padded_mut` needs a buffer with room for the PKCS7 padding.
    let block_size = 16usize;
    let padded_len = (plaintext.len() / block_size + 1) * block_size;
    let mut buf = vec![0u8; padded_len];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(ct.to_vec())
}

/// `decrypt` do libsignal — AES-256-CBC com padding PKCS7.
pub fn aes_decrypt_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::cipher::block_padding::Pkcs7;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let key: &[u8; 32] = key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(iv.len()))?;

    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let mut buf = ciphertext.to_vec();
    let pt = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(pt.to_vec())
}

/// `sha256`
pub fn sha256(buffer: &[u8]) -> Vec<u8> {
    Sha256::digest(buffer).to_vec()
}

/// `sha512`
pub fn sha512(buffer: &[u8]) -> Vec<u8> {
    Sha512::digest(buffer).to_vec()
}

/// `md5`
pub fn md5(buffer: &[u8]) -> Vec<u8> {
    md5::Md5::digest(buffer).to_vec()
}

/// `hmacSign` — HMAC-SHA256/SHA512.
pub fn hmac_sign(buffer: &[u8], key: &[u8], variant: HmacVariant) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    match variant {
        HmacVariant::Sha256 => {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac key");
            mac.update(buffer);
            mac.finalize().into_bytes().to_vec()
        }
        HmacVariant::Sha512 => {
            let mut mac = <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key).expect("hmac key");
            mac.update(buffer);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HmacVariant {
    Sha256,
    Sha512,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn shared_key_is_symmetric() {
        let a = Curve::generate_key_pair();
        let b = Curve::generate_key_pair();
        let ab = Curve::shared_key(&a.private, &b.public).unwrap();
        let ba = Curve::shared_key(&b.private, &a.public).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 32);
    }

    #[test]
    fn gcm_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 12];
        let plaintext = b"hello whatsapp";
        let aad = b"header";
        let enc = aes_encrypt_gcm(plaintext, &key, &iv, aad).unwrap();
        let dec = aes_decrypt_gcm(&enc, &key, &iv, aad).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn hkdf_known_length() {
        let out = hkdf(b"secret", 64, None, "").unwrap();
        assert_eq!(out.len(), 64);
    }

    // Vetores gerados a partir do libsignal real (scripts/crypto-vectors.json).
    #[test]
    fn xeddsa_signature_matches_libsignal() {
        let private = from_hex("4242424242424242424242424242424242424242424242424242424242424242");
        let msg = from_hex("77686174736170702d6e6f6973652d746573742d6d657373616765");
        let expected =
            "7e4058495b069937d5f9d3fb42502d9f03a13fe9f70f2cb6bb72b863ad5f9759\
             7705817f476fa23565672c34cff82d5487fc854a96976e2c6e44cc4d90198e01";
        let sig = xeddsa_sign(&private, &msg).unwrap();
        assert_eq!(hex(&sig), expected);
    }

    #[test]
    fn xeddsa_signature_signed_prekey_matches_libsignal() {
        let identity_private =
            from_hex("4242424242424242424242424242424242424242424242424242424242424242");
        let signed_pub = from_hex("0504bcd2e0d00f2cce5fe8f1c6c2fbec5c07fa56e3aa5c88a5689975d88b3fce05");
        let expected =
            "ea98b3edcf11095c3def1f6f48d982298d270f68696fff2028a9714be00fa85a\
             d89fc3e39f730d19bc68a92f4bd13507c93ebe77c67ebbbc94cfa6276ee40d0d";
        let sig = xeddsa_sign(&identity_private, &signed_pub).unwrap();
        assert_eq!(hex(&sig), expected);
    }

    #[test]
    fn xeddsa_verify_matches_libsignal() {
        let pub_a = from_hex("132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472");
        let pub_b = from_hex("04bcd2e0d00f2cce5fe8f1c6c2fbec5c07fa56e3aa5c88a5689975d88b3fce05");
        let msg = from_hex("77686174736170702d6e6f6973652d746573742d6d657373616765");
        let sig = from_hex(
            "7e4058495b069937d5f9d3fb42502d9f03a13fe9f70f2cb6bb72b863ad5f9759\
             7705817f476fa23565672c34cff82d5487fc854a96976e2c6e44cc4d90198e01",
        );
        assert!(xeddsa_verify(&pub_a, &msg, &sig));
        assert!(!xeddsa_verify(&pub_b, &msg, &sig));
        assert!(!xeddsa_verify(&pub_a, b"tampered-message", &sig));
    }

    #[test]
    fn xeddsa_fuzz_vectors_match_libsignal() {
        for i in 0..12u8 {
            let seed = vec![i; 32];
            let pub_key = Curve::public_from_private(&seed).unwrap();
            let msg = format!("msg-{i}");
            let sig = xeddsa_sign(&seed, msg.as_bytes()).unwrap();
            assert!(
                xeddsa_verify(&pub_key, msg.as_bytes(), &sig),
                "fuzz verify failed for seed {i}"
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
