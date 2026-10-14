use baileys_signal::protocol::record::SessionRecord;

#[test]
fn deserialize_snake_case_legacy_session() {
    // Formato gravado por uma versão antiga do record.rs (sem camelCase).
    let legacy = r#"{
      "_sessions": {
        "abc": {
          "registration_id": 123,
          "current_ratchet": {
            "ephemeral_key_pair": { "pubKey": "cHVia2V5", "privKey": "cHJpdmtleQ==" },
            "last_remote_ephemeral_key": "cmVtb3Rl",
            "previous_counter": 0,
            "root_key": "cm9vdA=="
          },
          "index_info": {
            "base_key": "YmFzZQ==",
            "base_key_type": 2,
            "closed": -1,
            "used": 1,
            "created": 1,
            "remote_identity_key": "aWQ="
          },
          "_chains": {
            "chainid": {
              "chain_key": { "counter": 0, "key": "a2V5" },
              "chain_type": 1,
              "message_keys": {}
            }
          }
        }
      },
      "version": "v1"
    }"#;

    let parsed: SessionRecord = serde_json::from_str(legacy).unwrap();
    let entry = parsed.sessions.get("abc").unwrap();
    assert_eq!(entry.registration_id, 123);
    assert_eq!(entry.current_ratchet.previous_counter, 0);
    assert_eq!(entry.index_info.base_key, "YmFzZQ==");
    let chain = entry.chains.get("chainid").unwrap();
    assert_eq!(chain.chain_key.counter, 0);
    assert_eq!(chain.chain_type, 1);

    // A re-serialização deve sair em camelCase (formato canônico do Node).
    let out = serde_json::to_string(&parsed).unwrap();
    assert!(out.contains("\"registrationId\":123"));
    assert!(out.contains("\"currentRatchet\""));
    assert!(out.contains("\"indexInfo\""));
    assert!(out.contains("\"chainKey\""));
    assert!(out.contains("\"chainType\""));
    assert!(!out.contains("registration_id"));
    assert!(!out.contains("current_ratchet"));
    assert!(!out.contains("chain_key"));
    assert!(!out.contains("chain_type"));
}
