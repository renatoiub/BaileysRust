//! Pre-key records — espelho de `keyhelper.js`.

use baileys_crypto::{Curve, KeyPair};

/// A pre-key pair (public key WITHOUT version byte, private key raw).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKeyRecord {
    pub key_id: u32,
    pub key_pair: KeyPair,
}

/// A signed pre-key pair + signature + key id + timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPreKeyRecord {
    pub key_id: u32,
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
    pub timestamp_s: Option<u64>,
}

/// `generatePreKey`
pub fn generate_pre_key(key_id: u32) -> PreKeyRecord {
    PreKeyRecord {
        key_id,
        key_pair: Curve::generate_key_pair(),
    }
}

/// `generateSignedPreKey` — gera par (pub 32 bytes) e assina `generateSignalPubKey(pub)` (33 bytes).
pub fn generate_signed_pre_key(identity_key_pair: &KeyPair, signed_key_id: u32) -> SignedPreKeyRecord {
    let key_pair = Curve::generate_key_pair();
    let signature = Curve::sign(
        &identity_key_pair.private,
        &baileys_crypto::generate_signal_pub_key(&key_pair.public),
    )
    .unwrap_or_default();
    SignedPreKeyRecord {
        key_id: signed_key_id,
        key_pair,
        signature,
        timestamp_s: None,
    }
}

/// `generateRegistrationId` — 14 bits a partir de 2 bytes aleatórios.
pub fn generate_registration_id() -> u32 {
    baileys_core::ids::generate_registration_id()
}
