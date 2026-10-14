//! Round-trip tests for the 1-on-1 `SessionCipher` and group `GroupCipher`.
//!
//! These prove the ratchets are self-consistent (encrypt/decrypt across two
//! independent `MemoryStore`s) and that serialization matches the Node format.

use baileys_signal::protocol::prekey::{generate_pre_key, generate_signed_pre_key};
use baileys_signal::protocol::session::{DeviceBundle, SessionBuilder, SessionCipher};
use baileys_signal::protocol::{
    GroupCipher, GroupSessionBuilder, MemoryStore, ProtocolAddress, SenderKeyDistributionMessage,
    SenderKeyName, SenderKeyRecord, SignalStore,
};
use baileys_crypto::Curve;

fn alice_store() -> MemoryStore {
    let identity = Curve::generate_key_pair();
    let signed_pre_key = generate_signed_pre_key(&identity, 1);
    MemoryStore::new(
        (baileys_crypto::generate_signal_pub_key(&identity.public), identity.private.clone()),
        (signed_pre_key.key_pair.public.clone(), signed_pre_key.key_pair.private.clone()),
        0x1234,
    )
}

fn bob_store() -> MemoryStore {
    let identity = Curve::generate_key_pair();
    let signed_pre_key = generate_signed_pre_key(&identity, 1);
    MemoryStore::new(
        (baileys_crypto::generate_signal_pub_key(&identity.public), identity.private.clone()),
        (signed_pre_key.key_pair.public.clone(), signed_pre_key.key_pair.private.clone()),
        0x5678,
    )
}

#[test]
fn session_cipher_prekey_roundtrip() {
    let alice = alice_store();
    let bob = bob_store();

    // Bob's device bundle (what Alice receives via <key>/<skey>).
    let (bob_identity_pub, _) = bob.get_our_identity().unwrap();
    let (bob_signed_pub, bob_signed_priv) = bob.load_signed_pre_key().unwrap();
    let bob_pre_key = generate_pre_key(31337);
    bob.insert_pre_key(31337, (bob_pre_key.key_pair.public.clone(), bob_pre_key.key_pair.private.clone()));

    let bundle = DeviceBundle {
        registration_id: bob.get_our_registration_id().unwrap(),
        identity_key: bob_identity_pub,
        signed_pre_key: baileys_signal::protocol::prekey::SignedPreKeyRecord {
            key_id: 1,
            key_pair: baileys_crypto::KeyPair { private: bob_signed_priv, public: bob_signed_pub },
            signature: vec![],
            timestamp_s: None,
        },
        pre_key: Some(bob_pre_key),
    };

    // Alice initiates a session to Bob.
    let alice_addr = ProtocolAddress::new("bob", 1);
    let alice_builder = SessionBuilder::new(&alice, alice_addr.clone());
    alice_builder.init_outgoing(&bundle).unwrap();

    // Alice encrypts a message → should be type 3 (pkmsg).
    let alice_cipher = SessionCipher::new(&alice, alice_addr.clone());
    let enc = alice_cipher.encrypt(b"hello bob").unwrap();
    assert_eq!(enc.r#type, 3, "first message must be a prekey message");

    // Bob decrypts the prekey message.
    let bob_cipher = SessionCipher::new(&bob, ProtocolAddress::new("alice", 1));
    let plaintext = bob_cipher.decrypt_pre_key_whisper_message(&enc.body).unwrap();
    assert_eq!(plaintext, b"hello bob");

    // Bob replies → type 1 (normal msg).
    let reply = bob_cipher.encrypt(b"hello alice").unwrap();
    assert_eq!(reply.r#type, 1);
    let back = alice_cipher.decrypt_whisper_message(&reply.body).unwrap();
    assert_eq!(back, b"hello alice");

    // Multiple messages in a row (chain advance).
    for i in 0..5u8 {
        let m = format!("msg {i}");
        let e = alice_cipher.encrypt(m.as_bytes()).unwrap();
        let p = bob_cipher.decrypt_whisper_message(&e.body).unwrap();
        assert_eq!(p, m.as_bytes());
    }
}

#[test]
fn session_cipher_skipped_message_keys() {
    let alice = alice_store();
    let bob = bob_store();

    let (bob_identity_pub, _) = bob.get_our_identity().unwrap();
    let (bob_signed_pub, bob_signed_priv) = bob.load_signed_pre_key().unwrap();
    let bundle = DeviceBundle {
        registration_id: bob.get_our_registration_id().unwrap(),
        identity_key: bob_identity_pub,
        signed_pre_key: baileys_signal::protocol::prekey::SignedPreKeyRecord {
            key_id: 1,
            key_pair: baileys_crypto::KeyPair { private: bob_signed_priv, public: bob_signed_pub },
            signature: vec![],
            timestamp_s: None,
        },
        pre_key: None,
    };

    let alice_addr = ProtocolAddress::new("bob", 1);
    SessionBuilder::new(&alice, alice_addr.clone()).init_outgoing(&bundle).unwrap();
    let alice_cipher = SessionCipher::new(&alice, alice_addr);
    let bob_cipher = SessionCipher::new(&bob, ProtocolAddress::new("alice", 1));

    // Bootstrap.
    let first = alice_cipher.encrypt(b"boot").unwrap();
    let _ = bob_cipher.decrypt_pre_key_whisper_message(&first.body).unwrap();

    // Encrypt 3 messages; decrypt only the 3rd (skipped keys cached).
    let e1 = alice_cipher.encrypt(b"one").unwrap();
    let _e2 = alice_cipher.encrypt(b"two").unwrap();
    let e3 = alice_cipher.encrypt(b"three").unwrap();
    let p3 = bob_cipher.decrypt_whisper_message(&e3.body).unwrap();
    assert_eq!(p3, b"three");
    let p1 = bob_cipher.decrypt_whisper_message(&e1.body).unwrap();
    assert_eq!(p1, b"one");
}

#[test]
fn group_cipher_roundtrip() {
    let alice = alice_store();
    let bob = bob_store();

    let group_id = "g.us-00000000";
    let alice_name = SenderKeyName::new(group_id, ProtocolAddress::new("alice", 1));
    let bob_name = SenderKeyName::new(group_id, ProtocolAddress::new("alice", 1));

    // Alice creates a sender key and distributes it.
    let alice_builder = GroupSessionBuilder::new(&alice);
    let distribution = alice_builder.create(&alice_name).unwrap();

    // Bob processes the distribution (via a fresh SenderKeyDistributionMessage clone).
    let dist_bytes = distribution.serialize().to_vec();
    let dist = SenderKeyDistributionMessage::from_serialized(dist_bytes).unwrap();
    GroupSessionBuilder::new(&bob).process(&bob_name, &dist).unwrap();

    // Alice encrypts for the group; Bob decrypts.
    let alice_cipher = GroupCipher::new(&alice, alice_name);
    let bob_cipher = GroupCipher::new(&bob, bob_name);

    let ciphertext = alice_cipher.encrypt(b"group hello").unwrap();
    let plaintext = bob_cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(plaintext, b"group hello");

    // Multiple messages.
    for i in 0..5u8 {
        let m = format!("group {i}");
        let c = alice_cipher.encrypt(m.as_bytes()).unwrap();
        let p = bob_cipher.decrypt(&c).unwrap();
        assert_eq!(p, m.as_bytes());
    }
}

#[test]
fn sender_key_record_json_roundtrip() {
    let store = alice_store();
    let name = SenderKeyName::new("g.us-test", ProtocolAddress::new("me", 1));
    let builder = GroupSessionBuilder::new(&store);
    let dist = builder.create(&name).unwrap();
    let record = store.load_sender_key(&name).unwrap();

    let json = record.serialize_json();
    // Must be Buffer.toJSON format with type/data fields.
    assert!(json.contains("\"type\":\"Buffer\""), "json should be Buffer.toJSON: {json}");

    let parsed = SenderKeyRecord::deserialize(json.as_bytes()).unwrap();
    assert_eq!(parsed.serialize(), record.serialize());
    assert!(dist.id > 0);
}

#[test]
fn session_record_json_serialization() {
    let store = alice_store();
    let (identity_pub, _) = store.get_our_identity().unwrap();
    let _signed = store.load_signed_pre_key().unwrap();
    let bob = bob_store();
    let (bob_identity_pub, _) = bob.get_our_identity().unwrap();
    let (bob_signed_pub, bob_signed_priv) = bob.load_signed_pre_key().unwrap();
    let bundle = DeviceBundle {
        registration_id: bob.get_our_registration_id().unwrap(),
        identity_key: bob_identity_pub,
        signed_pre_key: baileys_signal::protocol::prekey::SignedPreKeyRecord {
            key_id: 1,
            key_pair: baileys_crypto::KeyPair { private: bob_signed_priv, public: bob_signed_pub },
            signature: vec![],
            timestamp_s: None,
        },
        pre_key: None,
    };
    let addr = ProtocolAddress::new("bob", 1);
    SessionBuilder::new(&store, addr.clone()).init_outgoing(&bundle).unwrap();
    let record = store.load_session(&addr.to_string()).unwrap().unwrap();

    // Serialize to the Node format (serde_json).
    let json = serde_json::to_string(&record).unwrap();
    assert!(json.contains("\"_sessions\""), "missing _sessions key: {json}");
    assert!(json.contains("\"version\":\"v1\""), "missing version: {json}");

    // Paridade com o `session_record.js` do libsignal (camelCase): o Node
    // grava as chaves de sinal no Redis/SQLite nesse formato.
    assert!(json.contains("\"registrationId\""), "missing registrationId: {json}");
    assert!(json.contains("\"currentRatchet\""), "missing currentRatchet: {json}");
    assert!(json.contains("\"ephemeralKeyPair\""), "missing ephemeralKeyPair: {json}");
    assert!(json.contains("\"lastRemoteEphemeralKey\""), "missing lastRemoteEphemeralKey: {json}");
    assert!(json.contains("\"previousCounter\""), "missing previousCounter: {json}");
    assert!(json.contains("\"indexInfo\""), "missing indexInfo: {json}");
    assert!(json.contains("\"baseKey\""), "missing baseKey: {json}");
    assert!(json.contains("\"baseKeyType\""), "missing baseKeyType: {json}");
    assert!(json.contains("\"remoteIdentityKey\""), "missing remoteIdentityKey: {json}");
    assert!(json.contains("\"_chains\""), "missing _chains: {json}");
    assert!(json.contains("\"chainKey\""), "missing chainKey: {json}");
    assert!(json.contains("\"chainType\""), "missing chainType: {json}");
    assert!(json.contains("\"messageKeys\""), "missing messageKeys: {json}");
    assert!(json.contains("\"pendingPreKey\""), "missing pendingPreKey: {json}");
    assert!(json.contains("\"signedKeyId\""), "missing signedKeyId: {json}");
    // `preKeyId` é opcional (só aparece quando há preKey); neste teste o bundle
    // foi iniciado sem preKey, então deve estar ausente — igual ao Node.
    assert!(!json.contains("\"preKeyId\""), "preKeyId should be absent without preKey: {json}");
    assert!(!json.contains("\"registration_id\""), "snake_case leaked: {json}");
    assert!(!json.contains("\"current_ratchet\""), "snake_case leaked: {json}");
    assert!(!json.contains("\"index_info\""), "snake_case leaked: {json}");
    assert!(!json.contains("\"chain_key\""), "snake_case leaked: {json}");

    // Deserialize back.
    let parsed: baileys_signal::protocol::record::SessionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, record);
    let _ = identity_pub;
}
