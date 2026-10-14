//! Byte-for-byte parity test against the real libsignal (Node).
//!
//! Fixed keys below are the exact values printed by `scripts/signal-vectors.js`
//! (run against `container/node_modules/libsignal`).

use baileys_crypto::Curve;
use baileys_signal::protocol::crypto::derive_secrets;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn shared_secret_and_master_key_match_libsignal() {
    let alice_identity_pub = from_hex("057a1a4e709bf085ac494aba0469b9b1eda0ab1f78b16aabb79ffeda90623e8522");
    let alice_identity_priv = vec![0x41u8; 32];
    let bob_identity_pub = from_hex("05132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472");
    let bob_identity_priv = vec![0x42u8; 32];

    let bob_spk_pub = from_hex("05e6cc677ebcb3794af3d482694a6f0342cf4d426d4c82b927ce73bdcae6f8400d");
    let bob_spk_priv = from_hex("1070206280b94ed5cfccd7eaa8e90869eb899ac244f0a3e5df0c76368838ec65");
    let bob_prekey_pub = from_hex("05b11ef49fb9dfb69a639f01df1498b8fd18efb42cdedbb39af925a0f07bb2e778");
    let bob_prekey_priv = from_hex("b82f9b333d1a81f28362437ef1b3c734506e171e8a4b940ac44c8203b3fedc7b");
    let alice_base_pub = from_hex("05fc0a34b5da454aab1142326d325fb90deeacd4a6ceaf9c3c57676e6596c6d239");
    let alice_base_priv = from_hex("f02d60e64ee8bcb6ec1bd0b8582eee42e9a70cc05738a7db105a1d745a418a57");

    // Simulate initiator (Alice → Bob with prekey).
    let mut shared_secret = vec![0xffu8; 32 * 5];
    let a1 = Curve::shared_key(&alice_identity_priv, &bob_spk_pub).unwrap();
    let a2 = Curve::shared_key(&alice_base_priv, &bob_identity_pub).unwrap();
    let a3 = Curve::shared_key(&alice_base_priv, &bob_spk_pub).unwrap();
    let a4 = Curve::shared_key(&alice_base_priv, &bob_prekey_pub).unwrap();
    shared_secret[32..64].copy_from_slice(&a1);
    shared_secret[64..96].copy_from_slice(&a2);
    shared_secret[96..128].copy_from_slice(&a3);
    shared_secret[128..160].copy_from_slice(&a4);

    let master = derive_secrets(&shared_secret, &[0u8; 32], b"WhisperText", 2).unwrap();
    assert_eq!(hex(&master[0]), "2562396717c494fab79fbfc088f5b2a6ff434f2a393aa18dfdc4aae30a4aa3f2");
    assert_eq!(hex(&master[1]), "cea7a4e4ac2f26bb3c9f33afe686df958f38e0e21c269e8afb4991538817dcf8");

    // Responder (Bob receives).
    let mut shared_secret_r = vec![0xffu8; 32 * 5];
    let a1r = Curve::shared_key(&bob_identity_priv, &alice_base_pub).unwrap();
    let a2r = Curve::shared_key(&bob_spk_priv, &alice_identity_pub).unwrap();
    let a3r = Curve::shared_key(&bob_spk_priv, &alice_base_pub).unwrap();
    let a4r = Curve::shared_key(&bob_prekey_priv, &alice_base_pub).unwrap();
    shared_secret_r[64..96].copy_from_slice(&a1r);
    shared_secret_r[32..64].copy_from_slice(&a2r);
    shared_secret_r[96..128].copy_from_slice(&a3r);
    shared_secret_r[128..160].copy_from_slice(&a4r);

    let master_r = derive_secrets(&shared_secret_r, &[0u8; 32], b"WhisperText", 2).unwrap();
    assert_eq!(master_r[0], master[0]);
    assert_eq!(master_r[1], master[1]);

    // Sanity: the identity public derivation must match (getPublicFromPrivateKey).
    assert_eq!(
        hex(&Curve::public_from_private(&alice_identity_priv).unwrap()),
        "7a1a4e709bf085ac494aba0469b9b1eda0ab1f78b16aabb79ffeda90623e8522"
    );
    let _ = (alice_identity_pub, bob_prekey_priv);
}
