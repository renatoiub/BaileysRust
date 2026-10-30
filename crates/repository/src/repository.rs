//! `SignalRepository` — port fiel de `makeLibSignalRepository`.
//!
//! Expõe a mesma superfície de alto nível usada pelo socket:
//! `encryptMessage`, `decryptMessage`, `encryptGroupMessage`, `decryptGroupMessage`,
//! `processSenderKeyDistributionMessage`, `injectE2ESession` e
//! `jidToSignalProtocolAddress`.

use baileys_signal::protocol::group::{
    GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage, SenderKeyRecord,
};
use baileys_signal::protocol::session::{
    jid_to_signal_protocol_address, DeviceBundle, SessionBuilder, SessionCipher,
};
use baileys_signal::protocol::{ProtocolAddress, SenderKeyName, SignalStore};
use baileys_signal::Result;

/// Estruturas de entrada para `injectE2ESession` (espelham o JS).
#[derive(Debug, Clone)]
pub struct InjectPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InjectSignedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Bundle de sessão a injetar (resultado de `<key>`/`<skey>` do servidor).
#[derive(Debug, Clone)]
pub struct InjectSession {
    pub registration_id: u32,
    pub identity_key: Vec<u8>, // 33 bytes (com prefixo 05)
    pub signed_pre_key: InjectSignedPreKey,
    pub pre_key: Option<InjectPreKey>,
}

/// Resultado do `encryptGroupMessage`.
pub struct GroupEncryptResult {
    pub ciphertext: Vec<u8>,
    pub sender_key_distribution_message: Vec<u8>,
}

/// Repositório de alto nível do Signal, sobre qualquer `SignalStore`.
pub struct SignalRepository<'a> {
    store: &'a dyn SignalStore,
}

impl<'a> SignalRepository<'a> {
    pub fn new(store: &'a dyn SignalStore) -> Self {
        Self { store }
    }

    /// `jidToSignalProtocolAddress` — `551199...@s.whatsapp.net:12` → `551199...::12`.
    pub fn jid_to_signal_protocol_address(&self, jid: &str) -> Result<String> {
        Ok(jid_to_signal_protocol_address(jid)?.to_string())
    }

    /// `decryptMessage` — descriptografa uma mensagem 1:1 (`msg` ou `pkmsg`).
    pub fn decrypt_message(&self, jid: &str, r#type: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let addr = jid_to_signal_protocol_address(jid)?;
        let cipher = SessionCipher::new(self.store, addr);
        match r#type {
            "pkmsg" => cipher.decrypt_pre_key_whisper_message(ciphertext),
            "msg" => cipher.decrypt_whisper_message(ciphertext),
            other => Err(baileys_signal::error::SignalError::UnknownMessageType(
                other.to_string(),
            )),
        }
    }

    /// `encryptMessage` — criptografa para um jid 1:1.
    pub fn encrypt_message(&self, jid: &str, data: &[u8]) -> Result<MessageEncryptResult> {
        let addr = jid_to_signal_protocol_address(jid)?;
        let cipher = SessionCipher::new(self.store, addr);
        let enc = cipher.encrypt(data)?;
        Ok(MessageEncryptResult {
            r#type: if enc.r#type == 3 { "pkmsg" } else { "msg" }.to_string(),
            ciphertext: enc.body,
        })
    }

    /// `decryptGroupMessage`
    pub fn decrypt_group_message(
        &self,
        group: &str,
        author_jid: &str,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        let name = jid_to_signal_sender_key_name(group, author_jid);
        let cipher = GroupCipher::new(self.store, name);
        cipher.decrypt(msg)
    }

    /// `processSenderKeyDistributionMessage`
    pub fn process_sender_key_distribution_message(
        &self,
        group_id: &str,
        author_jid: &str,
        axolotl: &[u8],
    ) -> Result<()> {
        let builder = GroupSessionBuilder::new(self.store);
        let name = jid_to_signal_sender_key_name(group_id, author_jid);
        let message = SenderKeyDistributionMessage::from_serialized(axolotl.to_vec())?;
        builder.process(&name, &message)
    }

    /// `encryptGroupMessage`
    pub fn encrypt_group_message(
        &self,
        group: &str,
        me_id: &str,
        data: &[u8],
    ) -> Result<GroupEncryptResult> {
        let name = jid_to_signal_sender_key_name(group, me_id);
        let builder = GroupSessionBuilder::new(self.store);

        let distribution = builder.create(&name)?;
        let cipher = GroupCipher::new(self.store, name);
        let ciphertext = cipher.encrypt(data)?;

        Ok(GroupEncryptResult {
            ciphertext,
            sender_key_distribution_message: distribution.serialize().to_vec(),
        })
    }

    /// Troca a sender key própria do grupo por um registro vazio; o próximo
    /// `encrypt_group_message` gera uma nova. Sobrescreve em vez de apagar para
    /// não depender do delete (o load cai no SQLite quando falta na extensão).
    pub fn reset_sender_key(&self, group: &str, me_id: &str) -> Result<String> {
        let name = jid_to_signal_sender_key_name(group, me_id);
        self.store.store_sender_key(&name, &SenderKeyRecord::default())?;
        Ok(name.to_string())
    }

    /// `injectE2ESession` — injeta uma sessão recebida via `<key>`/`<skey>`.
    pub fn inject_e2e_session(&self, jid: &str, session: InjectSession) -> Result<()> {
        let builder = SessionBuilder::new(self.store, jid_to_signal_protocol_address(jid)?);
        builder.init_outgoing(&DeviceBundle {
            registration_id: session.registration_id,
            identity_key: session.identity_key,
            signed_pre_key: baileys_signal::protocol::prekey::SignedPreKeyRecord {
                key_id: session.signed_pre_key.key_id,
                key_pair: baileys_crypto::KeyPair {
                    private: vec![],
                    public: session.signed_pre_key.public_key,
                },
                signature: session.signed_pre_key.signature,
                timestamp_s: None,
            },
            pre_key: session.pre_key.map(|pk| baileys_signal::protocol::prekey::PreKeyRecord {
                key_id: pk.key_id,
                key_pair: baileys_crypto::KeyPair {
                    private: vec![],
                    public: pk.public_key,
                },
            }),
        })
    }
}

/// Resultado do `encryptMessage`.
pub struct MessageEncryptResult {
    pub r#type: String,
    pub ciphertext: Vec<u8>,
}

/// `jidToSignalSenderKeyName` — `{group}::{user}::{device}`.
fn jid_to_signal_sender_key_name(group: &str, user: &str) -> SenderKeyName {
    SenderKeyName::new(group, jid_to_signal_protocol_address(user).unwrap_or_else(|_| {
        ProtocolAddress::new(user, 0)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use baileys_signal::protocol::MemoryStore;
    use baileys_crypto::Curve;

    fn mem_store() -> MemoryStore {
        let identity = Curve::generate_key_pair();
        let signed = baileys_signal::protocol::prekey::generate_signed_pre_key(&identity, 1);
        MemoryStore::new(
            (baileys_crypto::generate_signal_pub_key(&identity.public), identity.private),
            (signed.key_pair.public, signed.key_pair.private),
            1234,
        )
    }

    #[test]
    fn group_roundtrip_via_repository() {
        let alice = mem_store();
        let bob = mem_store();

        let repo_alice = SignalRepository::new(&alice);
        let repo_bob = SignalRepository::new(&bob);

        let group = "1234@g.us";
        let alice_jid = "55111@s.whatsapp.net";
        let _bob_jid = "55112@s.whatsapp.net";

        let enc = repo_alice
            .encrypt_group_message(group, alice_jid, b"group via repo")
            .unwrap();

        repo_bob
            .process_sender_key_distribution_message(
                group,
                alice_jid,
                &enc.sender_key_distribution_message,
            )
            .unwrap();

        let plaintext = repo_bob
            .decrypt_group_message(group, alice_jid, &enc.ciphertext)
            .unwrap();
        assert_eq!(plaintext, b"group via repo");
    }

    #[test]
    fn one_to_one_roundtrip_via_repository() {
        let alice = mem_store();
        let bob = mem_store();

        let (bob_identity, _) = bob.get_our_identity().unwrap();
        let (bob_spk_pub, _bob_spk_priv) = bob.load_signed_pre_key().unwrap();
        let pre_key = baileys_signal::protocol::prekey::generate_pre_key(9);
        bob.insert_pre_key(9, (pre_key.key_pair.public.clone(), pre_key.key_pair.private.clone()));

        let repo_alice = SignalRepository::new(&alice);
        let repo_bob = SignalRepository::new(&bob);

        let alice_jid = "55111@s.whatsapp.net";
        let bob_jid = "55112@s.whatsapp.net";

        repo_alice
            .inject_e2e_session(
                bob_jid,
                InjectSession {
                    registration_id: bob.get_our_registration_id().unwrap(),
                    identity_key: bob_identity,
                    signed_pre_key: InjectSignedPreKey {
                        key_id: 1,
                        public_key: bob_spk_pub,
                        signature: vec![],
                    },
                    pre_key: Some(InjectPreKey {
                        key_id: 9,
                        public_key: pre_key.key_pair.public,
                        signature: vec![],
                    }),
                },
            )
            .unwrap();

        let enc = repo_alice.encrypt_message(bob_jid, b"hello").unwrap();
        assert_eq!(enc.r#type, "pkmsg");

        let pt = repo_bob
            .decrypt_message(alice_jid, &enc.r#type, &enc.ciphertext)
            .unwrap();
        assert_eq!(pt, b"hello");
    }
}
