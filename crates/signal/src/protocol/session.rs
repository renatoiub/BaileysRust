//! `SessionBuilder` â€” port fiel de `libsignal/src/session_builder.js`.

use baileys_crypto::{Curve, KeyPair};

use crate::error::SignalError;
use crate::Result;

use super::address::ProtocolAddress;
use super::chain::{BaseKeyType, ChainType};
use super::crypto::derive_secrets;
use super::prekey::{PreKeyRecord, SignedPreKeyRecord};
use super::record::{encode_b64, now_ms, Chain, ChainKey, PendingPreKey, Ratchet, SerializedKeyPair, SessionEntry, SessionRecord};
use super::whisper::PreKeyWhisperMessage;
use super::SignalStore;
use prost::Message as _;

/// `SessionBuilder`
pub struct SessionBuilder<'a> {
    addr: ProtocolAddress,
    store: &'a dyn SignalStore,
}

/// Pre-key bundle of a remote device (the data received via `<key>`/`<skey>`).
#[derive(Debug, Clone)]
pub struct DeviceBundle {
    pub registration_id: u32,
    pub identity_key: Vec<u8>, // 33 bytes (with 05 prefix)
    pub signed_pre_key: SignedPreKeyRecord,
    pub pre_key: Option<PreKeyRecord>,
}

impl<'a> SessionBuilder<'a> {
    pub fn new(store: &'a dyn SignalStore, addr: ProtocolAddress) -> Self {
        Self { addr, store }
    }

    /// `initOutgoing`
    pub fn init_outgoing(&self, device: &DeviceBundle) -> Result<()> {
        let fq_addr = self.addr.to_string();

        if !self.store.is_trusted_identity(&self.addr.id, &device.identity_key) {
            return Err(SignalError::UntrustedIdentityKey);
        }
        // verifySignature(identityKey, signedPreKey.publicKey, signedPreKey.signature, true)
        // isInit=true no-op in libsignal â€” skip.

        let base_key = Curve::generate_signal_key_pair();
        let device_pre_key = device.pre_key.as_ref().map(|k| k.key_pair.public.clone());
        let mut session = self.init_session(
            true,
            Some(&base_key),
            None,
            &device.identity_key,
            device_pre_key.as_deref(),
            Some(&device.signed_pre_key.key_pair.public),
            device.registration_id,
        )?;

        let mut pending = PendingPreKey {
            signed_key_id: device.signed_pre_key.key_id,
            base_key: encode_b64(&base_key.public),
            pre_key_id: None,
        };
        if let Some(pre_key) = &device.pre_key {
            pending.pre_key_id = Some(pre_key.key_id);
        }
        session.pending_pre_key = Some(pending);

        let mut record = self.store.load_session(&fq_addr)?.unwrap_or_default();
        if let Some(open) = record.get_open_session().cloned() {
            record.close_session(&open);
        }
        record.set_session(session);
        self.store.store_session(&fq_addr, &record)
    }

    /// `initIncoming`
    pub fn init_incoming(
        &self,
        record: &mut SessionRecord,
        message: &PreKeyWhisperMessage,
    ) -> Result<Option<u32>> {
        let fq_addr = self.addr.to_string();
        let identity_key = message
            .identity_key
            .as_deref()
            .ok_or(SignalError::UntrustedIdentityKey)?;

        if !self.store.is_trusted_identity(&fq_addr, identity_key) {
            return Err(SignalError::UntrustedIdentityKey);
        }
        if let Some(base_key) = message.base_key.as_deref() {
            if record.sessions.contains_key(&encode_b64(base_key)) {
                // We haven't replied yet.
                return Ok(None);
            }
        }

        let pre_key_pair: Option<(Vec<u8>, Vec<u8>)> = match message.pre_key_id {
            Some(id) => Some(
                self.store
                    .load_pre_key(id)?
                    .ok_or(SignalError::InvalidPreKeyId)?,
            ),
            None => None,
        };
        let signed_pre_key_pair = self
            .store
            .load_signed_pre_key()
            .map_err(|_| SignalError::MissingSignedPreKey)?;

        if let Some(open) = record.get_open_session().cloned() {
            record.close_session(&open);
        }

        // `load_pre_key` returns `(public, private)` (mirrors libsignal's
        // `{pubKey, privKey}`).
        let our_ephemeral = pre_key_pair.map(|(public, private)| KeyPair { private, public });
        let session = self.init_session(
            false,
            our_ephemeral.as_ref(),
            Some(&KeyPair {
                private: signed_pre_key_pair.1,
                public: signed_pre_key_pair.0,
            }),
            identity_key,
            message.base_key.as_deref(),
            None,
            message.registration_id.unwrap_or(0),
        )?;

        record.set_session(session);
        Ok(message.pre_key_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn init_session(
        &self,
        is_initiator: bool,
        our_ephemeral_key: Option<&KeyPair>,
        our_signed_key: Option<&KeyPair>,
        their_identity_pub_key: &[u8],
        their_ephemeral_pub_key: Option<&[u8]>,
        their_signed_pub_key: Option<&[u8]>,
        registration_id: u32,
    ) -> Result<SessionEntry> {
        // Determine ourSignedKey / theirSignedPubKey per the JS logic.
        let our_signed_key: &KeyPair = if is_initiator {
            if our_signed_key.is_some() {
                return Err(SignalError::NoOpenSession);
            }
            our_ephemeral_key.expect("initiator requires ourEphemeralKey")
        } else {
            if their_signed_pub_key.is_some() {
                return Err(SignalError::NoOpenSession);
            }
            our_signed_key.expect("responder requires ourSignedKey")
        };

        let their_signed_pub_key: &[u8] = if is_initiator {
            their_signed_pub_key.expect("initiator requires theirSignedPubKey")
        } else {
            their_ephemeral_pub_key.expect("responder requires theirEphemeralPubKey")
        };

        let shared_len = if our_ephemeral_key.is_none() || their_ephemeral_pub_key.is_none() {
            32 * 4
        } else {
            32 * 5
        };
        let mut shared_secret = vec![0u8; shared_len];
        shared_secret[..32].fill(0xFF);

        let (our_identity_pub, our_identity_priv) = self.store.get_our_identity()?;
        let our_identity_key = KeyPair {
            private: our_identity_priv,
            public: our_identity_pub,
        };

        let a1 = Curve::shared_key(&our_identity_key.private, their_signed_pub_key)?;
        let a2 = Curve::shared_key(&our_signed_key.private, their_identity_pub_key)?;
        let a3 = Curve::shared_key(&our_signed_key.private, their_signed_pub_key)?;

        let (a1_off, a2_off) = if is_initiator { (32, 64) } else { (64, 32) };
        shared_secret[a1_off..a1_off + 32].copy_from_slice(&a1);
        shared_secret[a2_off..a2_off + 32].copy_from_slice(&a2);
        shared_secret[96..128].copy_from_slice(&a3);

        if let (Some(our_eph), Some(their_eph)) = (our_ephemeral_key, their_ephemeral_pub_key) {
            let a4 = Curve::shared_key(&our_eph.private, their_eph)?;
            shared_secret[128..160].copy_from_slice(&a4);
        }

        let master_key = derive_secrets(&shared_secret, &[0u8; 32], b"WhisperText", 2)?;

        let ephemeral_key_pair = if is_initiator {
            Curve::generate_signal_key_pair()
        } else {
            our_signed_key.clone()
        };

        let mut session = SessionEntry {
            registration_id,
            current_ratchet: Ratchet {
                ephemeral_key_pair: SerializedKeyPair {
                    pub_key: encode_b64(&ephemeral_key_pair.public),
                    priv_key: encode_b64(&ephemeral_key_pair.private),
                },
                last_remote_ephemeral_key: encode_b64(their_signed_pub_key),
                previous_counter: 0,
                root_key: encode_b64(&master_key[0]),
            },
            index_info: super::record::IndexInfo {
                base_key: encode_b64(if is_initiator {
                    &our_ephemeral_key.expect("initiator base").public
                } else {
                    their_ephemeral_pub_key.unwrap_or_default()
                }),
                base_key_type: if is_initiator {
                    BaseKeyType::Ours as u32
                } else {
                    BaseKeyType::Theirs as u32
                },
                closed: -1,
                used: now_ms(),
                created: now_ms(),
                remote_identity_key: encode_b64(their_identity_pub_key),
            },
            chains: Default::default(),
            pending_pre_key: None,
        };

        if is_initiator {
            let their = their_signed_pub_key.to_vec();
            self.calculate_sending_ratchet(&mut session, &their);
        }

        Ok(session)
    }

    fn calculate_sending_ratchet(&self, session: &mut SessionEntry, remote_key: &[u8]) {
        let ratchet_priv = session
            .current_ratchet
            .ephemeral_key_pair
            .priv_key
            .clone();
        let ratchet_priv = super::record::decode_b64(&ratchet_priv);
        let shared_secret = Curve::shared_key(&ratchet_priv, remote_key).unwrap_or_default();
        let root_key = super::record::decode_b64(&session.current_ratchet.root_key);
        let master_key = derive_secrets(&shared_secret, &root_key, b"WhisperRatchet", 2).unwrap_or_default();

        let pub_key = super::record::decode_b64(&session.current_ratchet.ephemeral_key_pair.pub_key);
        let _ = session.add_chain(
            &pub_key,
            Chain::new_sending(-1, master_key[1].clone()),
        );
        session.current_ratchet.root_key = encode_b64(&master_key[0]);
    }
}

/// Helpers de `libsignal.ts` (endereÃ§o).
pub fn jid_to_signal_protocol_address(jid: &str) -> Result<ProtocolAddress> {
    let (user, _suffix) = jid
        .split_once('@')
        .ok_or(SignalError::InvalidAddress)?;
    let (user, device) = match user.split_once(':') {
        Some((u, d)) => (u, d.parse::<u32>().unwrap_or(0)),
        None => (user, 0),
    };
    Ok(ProtocolAddress::new(user, device))
}

/// `SessionCipher` â€” port fiel de `libsignal/src/session_cipher.js`.
pub struct SessionCipher<'a> {
    addr: ProtocolAddress,
    store: &'a dyn SignalStore,
}

const VERSION: u8 = 3;

/// Resultado de `encrypt`.
pub struct EncryptResult {
    /// 3 = prekey bundle (`pkmsg`), 1 = normal (`msg`).
    pub r#type: u32,
    pub body: Vec<u8>,
    pub registration_id: u32,
}

impl<'a> SessionCipher<'a> {
    pub fn new(store: &'a dyn SignalStore, addr: ProtocolAddress) -> Self {
        Self { addr, store }
    }

    fn encode_tuple_byte(n1: u8, n2: u8) -> Result<u8> {
        if n1 > 15 || n2 > 15 {
            return Err(SignalError::IncompatibleVersion);
        }
        Ok((n1 << 4) | n2)
    }

    fn decode_tuple_byte(byte: u8) -> (u8, u8) {
        (byte >> 4, byte & 0xf)
    }

    fn get_record(&self) -> Result<Option<SessionRecord>> {
        self.store.load_session(&self.addr.to_string())
    }

    fn store_record(&self, record: &mut SessionRecord) -> Result<()> {
        record.remove_old_sessions();
        self.store.store_session(&self.addr.to_string(), record)
    }

    /// `encrypt(data)`
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptResult> {
        let (our_identity_pub, _) = self.store.get_our_identity()?;
        let mut record = self.get_record()?.ok_or(SignalError::NoSessionRecord)?;

        // Scope: borrow session mutably while reading chain info.
        let open_base = {
            let open = record.get_open_session().ok_or(SignalError::NoOpenSession)?;
            open.index_info.base_key.clone()
        };
        let (chain_counter, chain_key_bytes, ephemeral_pub, previous_counter, remote_identity, pending) = {
            let session = record.sessions.get_mut(&open_base).unwrap();
            let remote_identity_key = super::record::decode_b64(&session.index_info.remote_identity_key);
            if !self.store.is_trusted_identity(&self.addr.id, &remote_identity_key) {
                return Err(SignalError::UntrustedIdentityKey);
            }

            let ephemeral_pub = super::record::decode_b64(&session.current_ratchet.ephemeral_key_pair.pub_key);
            let chain = session
                .get_chain_mut(&ephemeral_pub)
                .ok_or(SignalError::NoOpenSession)?;
            if chain.chain_type() == Some(ChainType::Receiving) {
                return Err(SignalError::EncryptOnReceivingChain);
            }
            let target = chain.chain_key.counter + 1;
            Self::fill_message_keys(chain, target)?;

            let chain_counter = chain.chain_key.counter;
            let msg_key = chain
                .message_keys
                .remove(&chain_counter.to_string())
                .ok_or(SignalError::MessageCounterError)?;
            let msg_key_bytes = super::record::decode_b64(&msg_key);
            let keys = derive_secrets(&msg_key_bytes, &[0u8; 32], b"WhisperMessageKeys", 3)?;

            // The prekey is only sent once; clear it now (mirrors libsignal
            // `session.pendingPreKey = undefined`).
            let pending = session.pending_pre_key.take();

            (
                chain_counter,
                keys,
                ephemeral_pub,
                session.current_ratchet.previous_counter,
                session.index_info.remote_identity_key.clone(),
                pending,
            )
        };

        // Encode WhisperMessage.
        let msg = super::whisper::WhisperMessage {
            ephemeral_key: Some(ephemeral_pub.clone()),
            counter: Some(chain_counter as u32),
            previous_counter: Some(previous_counter),
            ciphertext: Some(super::crypto::encrypt(&chain_key_bytes[0], data, &chain_key_bytes[2][..16])?),
        };
        let msg_buf = msg.encode_to_vec();

        // MAC input = ourIdentity.pub || remoteIdentity || versionByte || msg
        let mut mac_input = Vec::with_capacity(msg_buf.len() + 33 * 2 + 1);
        mac_input.extend_from_slice(&our_identity_pub);
        mac_input.extend_from_slice(&super::record::decode_b64(&remote_identity));
        mac_input.push(Self::encode_tuple_byte(VERSION, VERSION)?);
        mac_input.extend_from_slice(&msg_buf);
        let mac = super::crypto::calculate_mac(&chain_key_bytes[1], &mac_input);

        let mut result = Vec::with_capacity(msg_buf.len() + 9);
        result.push(Self::encode_tuple_byte(VERSION, VERSION)?);
        result.extend_from_slice(&msg_buf);
        result.extend_from_slice(&mac[..8]);

        // Store (message keys already removed from the chain in the block above).
        self.store_record(&mut record)?;

        let (r#type, body) = if let Some(pending) = pending {
            let pre_key_msg = super::whisper::PreKeyWhisperMessage {
                identity_key: Some(our_identity_pub.clone()),
                registration_id: Some(self.store.get_our_registration_id()?),
                base_key: Some(super::record::decode_b64(&pending.base_key)),
                signed_pre_key_id: Some(pending.signed_key_id),
                message: Some(result.clone()),
                pre_key_id: pending.pre_key_id,
            };
            let mut body = Vec::with_capacity(1 + pre_key_msg.encoded_len());
            body.push(Self::encode_tuple_byte(VERSION, VERSION)?);
            body.extend_from_slice(&pre_key_msg.encode_to_vec());
            (3, body)
        } else {
            (1, result)
        };

        Ok(EncryptResult {
            r#type,
            body,
            registration_id: {
                let session = record.sessions.values().find(|s| !record.is_closed(s)).ok_or(SignalError::NoOpenSession)?;
                session.registration_id
            },
        })
    }

    /// `decryptWhisperMessage(data)`
    pub fn decrypt_whisper_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut record = self.get_record()?.ok_or(SignalError::NoSessionRecord)?;
        let sessions: Vec<SessionEntry> = record.get_sessions().into_iter().cloned().collect();
        if sessions.is_empty() {
            return Err(SignalError::NoSessions);
        }

        let mut last_err = SignalError::NoMatchingSessions;
        let mut result = None;
        for session in sessions.iter() {
            match self.do_decrypt_whisper_message(data, session) {
                Ok((plaintext, advanced)) => {
                    result = Some((session.index_info.base_key.clone(), plaintext, advanced));
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let (base_key, plaintext, advanced) = result.ok_or(last_err)?;

        // Write back the ratchet-advanced session and bump `used`.
        if let Some(session) = record.sessions.get_mut(&base_key) {
            *session = advanced;
            session.index_info.used = now_ms();
        }
        self.store_record(&mut record)?;
        Ok(plaintext)
    }

    /// `decryptPreKeyWhisperMessage(data)`
    pub fn decrypt_pre_key_whisper_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(SignalError::IncompatibleVersion);
        }
        let versions = Self::decode_tuple_byte(data[0]);
        if versions.1 > 3 || versions.0 < 3 {
            return Err(SignalError::IncompatibleVersion);
        }

        let pre_key_proto = super::whisper::PreKeyWhisperMessage::decode(&data[1..])?;
        let mut record = self.get_record()?.unwrap_or_default();

        let builder = SessionBuilder::new(self.store, self.addr.clone());
        let pre_key_id = builder.init_incoming(&mut record, &pre_key_proto)?;

        let base_key = pre_key_proto
            .base_key
            .as_deref()
            .ok_or(SignalError::NoOpenSession)?;
        let session = record
            .sessions
            .get(&super::record::encode_b64(base_key))
            .ok_or(SignalError::NoOpenSession)?
            .clone();
        let message = pre_key_proto
            .message
            .as_deref()
            .ok_or(SignalError::NoOpenSession)?;
        let (plaintext, advanced_session) = self.do_decrypt_whisper_message(message, &session)?;

        // Write back the ratchet-advanced session (the clone above would otherwise
        // discard the stepped ratchet state).
        record
            .sessions
            .insert(super::record::encode_b64(base_key), advanced_session);

        self.store_record(&mut record)?;
        // NOTE: NÃO remove a pre-key após o uso. O libsignal do Hineken
        // (`@whiskeysystems/libsignal`) define `removePreKey` no storage mas
        // nunca o chama em `decryptPreKeyWhisperMessage` — as pre-keys
        // permanecem no store. Isso é essencial para o retry: quando o
        // remetente retransmite com uma pre-key antiga, ela ainda precisa
        // existir (`load_pre_key`) ou a decriptação falha com
        // `invalid pre-key ID`.
        let _ = pre_key_id;
        Ok(plaintext)
    }

    fn do_decrypt_whisper_message(
        &self,
        message_buffer: &[u8],
        session: &SessionEntry,
    ) -> Result<(Vec<u8>, SessionEntry)> {
        if message_buffer.len() < 9 {
            return Err(SignalError::IncompatibleVersion);
        }
        let versions = Self::decode_tuple_byte(message_buffer[0]);
        if versions.1 > 3 || versions.0 < 3 {
            return Err(SignalError::IncompatibleVersion);
        }
        let message_proto = &message_buffer[1..message_buffer.len() - 8];
        let message = super::whisper::WhisperMessage::decode(message_proto)?;
        let ephemeral_key = message
            .ephemeral_key
            .as_deref()
            .ok_or(SignalError::NoOpenSession)?;
        let previous_counter = message.previous_counter.unwrap_or(0);
        let counter = message.counter.unwrap_or(0);

        let mut session = session.clone();
        Self::maybe_step_ratchet(&mut session, ephemeral_key, previous_counter)?;

        let chain = session
            .get_chain_mut(ephemeral_key)
            .ok_or(SignalError::NoOpenSession)?;
        if chain.chain_type() == Some(ChainType::Sending) {
return Err(SignalError::DecryptOnSendingChain);
        }
        Self::fill_message_keys(chain, counter as i32)?;
        let msg_key = chain
            .message_keys
            .remove(&counter.to_string())
            .ok_or(SignalError::MessageCounterError)?;
        let msg_key_bytes = super::record::decode_b64(&msg_key);
        let keys = derive_secrets(&msg_key_bytes, &[0u8; 32], b"WhisperMessageKeys", 3)?;

        let (our_identity_pub, _) = self.store.get_our_identity()?;
        let mut mac_input = Vec::with_capacity(message_proto.len() + 33 * 2 + 1);
        mac_input.extend_from_slice(&super::record::decode_b64(&session.index_info.remote_identity_key));
        mac_input.extend_from_slice(&our_identity_pub);
        mac_input.push(Self::encode_tuple_byte(VERSION, VERSION)?);
        mac_input.extend_from_slice(message_proto);

        super::crypto::verify_mac(&mac_input, &keys[1], &message_buffer[message_buffer.len() - 8..], 8)?;

        let ciphertext = message
            .ciphertext
            .as_deref()
            .ok_or(SignalError::NoOpenSession)?;
        let pt = super::crypto::decrypt(&keys[0], ciphertext, &keys[2][..16])?;
        Ok((pt, session))
    }

    fn fill_message_keys(chain: &mut Chain, counter: i32) -> Result<()> {
        if chain.chain_key.counter >= counter {
            return Ok(());
        }
        if counter - chain.chain_key.counter > 2000 {
            return Err(SignalError::TooFarIntoFuture);
        }
        let key = chain
            .chain_key
            .key_bytes()
            .ok_or(SignalError::ChainClosed)?;

        chain
            .message_keys
            .insert(
                (chain.chain_key.counter + 1).to_string(),
                super::record::encode_b64(&super::crypto::calculate_mac(&key, &[1])),
            );
        chain.chain_key = ChainKey::new(
            chain.chain_key.counter + 1,
            super::crypto::calculate_mac(&key, &[2]),
        );
        Self::fill_message_keys(chain, counter)
    }

    fn maybe_step_ratchet(session: &mut SessionEntry, remote_key: &[u8], previous_counter: u32) -> Result<()> {
        if session.get_chain(remote_key).is_some() {
            return Ok(());
        }
        let last_remote = super::record::decode_b64(&session.current_ratchet.last_remote_ephemeral_key);
        if let Some(prev_chain) = session.get_chain_mut(&last_remote).map(|c| c.clone()) {
            // fill previous chain and close it
            let mut prev = prev_chain;
            Self::fill_message_keys(&mut prev, previous_counter as i32)?;
            prev.chain_key.key = None;
            *session.get_chain_mut(&last_remote).unwrap() = prev;
        }

        let root_key = super::record::decode_b64(&session.current_ratchet.root_key);
        let eph_priv = super::record::decode_b64(&session.current_ratchet.ephemeral_key_pair.priv_key);
        let shared = Curve::shared_key(&eph_priv, remote_key)?;
        let master = derive_secrets(&shared, &root_key, b"WhisperRatchet", 2)?;

        // receiving chain for the remote key
        session
            .add_chain(remote_key, Chain::new_receiving(-1, master[1].clone()))?;
        session.current_ratchet.root_key = super::record::encode_b64(&master[0]);

        // previous counter from old sending chain
        let eph_pub = super::record::decode_b64(&session.current_ratchet.ephemeral_key_pair.pub_key);
        if let Some(prev_sending) = session.get_chain(&eph_pub) {
            session.current_ratchet.previous_counter = prev_sending.chain_key.counter as u32;
            session.delete_chain(&eph_pub)?;
        }

        // swap ephemeral key
        let new_eph = Curve::generate_signal_key_pair();
        session.current_ratchet.ephemeral_key_pair = SerializedKeyPair {
            pub_key: super::record::encode_b64(&new_eph.public),
            priv_key: super::record::encode_b64(&new_eph.private),
        };

        // sending chain with the remote key
        let root_key = super::record::decode_b64(&session.current_ratchet.root_key);
        let shared = Curve::shared_key(&new_eph.private, remote_key)?;
        let master = derive_secrets(&shared, &root_key, b"WhisperRatchet", 2)?;
        session
            .add_chain(&new_eph.public, Chain::new_sending(-1, master[1].clone()))?;
        session.current_ratchet.root_key = super::record::encode_b64(&master[0]);
        session.current_ratchet.last_remote_ephemeral_key = super::record::encode_b64(remote_key);

        Ok(())
    }

    /// `hasOpenSession`
    pub fn has_open_session(&self) -> Result<bool> {
        let record = self.get_record()?.ok_or(SignalError::NoSessionRecord)?;
        Ok(record.have_open_session())
    }

    /// `closeOpenSession`
    pub fn close_open_session(&self) -> Result<()> {
        let mut record = match self.get_record()? {
            Some(r) => r,
            None => return Ok(()),
        };
        if let Some(open) = record.get_open_session().cloned() {
            record.close_session(&open);
            self.store_record(&mut record)?;
        }
        Ok(())
    }
}
