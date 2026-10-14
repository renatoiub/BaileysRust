//! `SqliteSignalStore` — implementa `SignalStore` sobre o SQLite compatível.
//!
//! Espelha o `signalStorage` do `Hineken/src/Signal/libsignal.ts`, com SQLite
//! nativo como armazenamento padrão (igual ao `useSQLiteAuthState` do Node).
//!
//! Camadas externas (ex. Redis, como no `authKeysRedis.ts` do Node) são
//! opcionais e injetadas pelo app através de um [`SignalStoreExtension`]:
//!
//! - **Leitura**: extensão primeiro; miss cai no SQLite e copia de volta.
//! - **Escrita**: extensão primeiro; se retornar `false`, cai no SQLite.
//! - **Remoção**: extensão primeiro; se retornar `false`, cai no SQLite.
//!
//! Sem extensão configurada (ex. testes), lê/grava direto no SQLite.
//!
//! Chaves usadas:
//! - `session-{id}`  → `SessionRecord` (JSON com base64, `_sessions`/`version`).
//! - `pre-key-{id}`  → `{ public, private }` (BufferJSON base64).
//! - `sender-key-{id}` → bytes UTF-8 do `JSON.stringify(SenderKeyRecord.serialize())`
//!   (o JSON interno usa `Buffer.toJSON()`: `{"type":"Buffer","data":[...]}`).

use std::sync::{Arc, Mutex, RwLock};

use base64::Engine;
use baileys_crypto::generate_signal_pub_key;
use baileys_signal::protocol::record::SessionRecord;
use baileys_signal::protocol::{
    SenderKeyName, SenderKeyRecord, SignalStore,
};
use baileys_signal::Result;
use baileys_store::creds::{init_auth_creds, AuthenticationCreds, BufferValue, SerializedKeyPair};
use baileys_store::sqlite::SQLiteAuthState;

/// Extensão de armazenamento de chaves de sinal (runtime-neutra, genérica).
///
/// O app pode injetar um backend externo (ex. Redis, como no
/// `authKeysRedis.ts` do Node) por cima do SQLite nativo. A biblioteca em si
/// não conhece Redis — ela apenas delega `load`/`store`/`remove` e cai no
/// SQLite quando a extensão não resolve.
///
/// As strings trafegadas são o JSON cru (formato BufferJSON) tal como o
/// SQLite armazena, sem reviver buffers — exatamente o que os métodos
/// tipados de `SignalStore` esperam desserializar.
pub trait SignalStoreExtension: Send + Sync {
    /// Retorna o JSON cru se o backend tem a chave; `None` = miss (cai no SQLite).
    fn load(&self, category: &str, id: &str) -> Option<String>;
    /// Grava o JSON cru. `true` = backend tratou; `false` = cai no SQLite.
    fn store(&self, category: &str, id: &str, json: &str) -> bool;
    /// Remove a chave. `true` = backend tratou; `false` = cai no SQLite.
    fn remove(&self, category: &str, id: &str) -> bool;
}

/// Store de sinal apoiado pelo SQLite (`auth_data`), com extensão opcional.
pub struct SqliteSignalStore {
    sqlite: Arc<SQLiteAuthState>,
    creds: Arc<RwLock<AuthenticationCreds>>,
    /// Extensão opcional (Redis no app). `None` = só SQLite nativo (testes).
    ext: Mutex<Option<Arc<dyn SignalStoreExtension>>>,
}

impl SqliteSignalStore {
    /// Cria o store a partir de um `SQLiteAuthState` já aberto.
    ///
    /// As creds são lidas do SQLite e mantidas num `RwLock`; o socket atualiza
    /// essa cópia conforme pareamento/login evoluem (via [`Self::update_creds`]).
    pub fn new(sqlite: Arc<SQLiteAuthState>) -> Result<Self> {
        let creds = sqlite
            .read_creds()
            .map_err(|e| baileys_signal::error::SignalError::Store(e.to_string()))?
            .unwrap_or_else(init_auth_creds);
        Ok(Self {
            sqlite,
            creds: Arc::new(RwLock::new(creds)),
            ext: Mutex::new(None),
        })
    }

    /// Registra uma extensão de armazenamento (ex. Redis-first do app).
    pub fn set_extension(&self, ext: Arc<dyn SignalStoreExtension>) {
        *self.ext.lock().expect("ext lock") = Some(ext);
    }

    /// Snapshot da extensão configurada (clone barato do Arc).
    fn extension(&self) -> Option<Arc<dyn SignalStoreExtension>> {
        self.ext.lock().expect("ext lock").clone()
    }

    /// Atualiza a cópia local das creds (e persiste no SQLite).
    pub fn update_creds(&self, creds: AuthenticationCreds) -> Result<()> {
        self.sqlite
            .save_creds(&creds)
            .map_err(|e| baileys_signal::error::SignalError::Store(e.to_string()))?;
        let mut guard = self.creds.write().expect("creds lock");
        *guard = creds;
        Ok(())
    }

    /// Acesso ao handle das creds (snapshot atual).
    pub fn creds(&self) -> AuthenticationCreds {
        self.creds.read().expect("creds lock").clone()
    }

    fn sqlite_err(e: impl std::fmt::Display) -> baileys_signal::error::SignalError {
        baileys_signal::error::SignalError::Store(e.to_string())
    }

    fn parse_err(e: impl std::fmt::Display) -> baileys_signal::error::SignalError {
        baileys_signal::error::SignalError::Store(e.to_string())
    }

    fn read_buffer(value: &BufferValue) -> Vec<u8> {
        match value {
            BufferValue::Buffer { data, .. } | BufferValue::Raw(data) => {
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .unwrap_or_default()
            }
        }
    }

    /// Grava uma pre-key (extensão primeiro quando há uma), no formato do Node.
    pub fn store_pre_key(&self, id: u32, key_pair: &SerializedKeyPair) -> Result<()> {
        let key = format!("pre-key-{id}");
        let json = baileys_store::buffer_json::stringify(key_pair)
            .map_err(Self::sqlite_err)?;
        if let Some(ext) = self.extension() {
            if ext.store("pre-key", &id.to_string(), &json) {
                return Ok(());
            }
            self.sqlite
                .write_string(&key, &json)
                .map_err(Self::sqlite_err)?;
            return Ok(());
        }
        self.sqlite
            .write_value(&key, key_pair)
            .map_err(Self::sqlite_err)?;
        Ok(())
    }
}

impl SignalStore for SqliteSignalStore {
    fn load_session(&self, id: &str) -> Result<Option<SessionRecord>> {
        let key = format!("session-{id}");
        if let Some(ext) = self.extension() {
            if let Some(raw) = ext.load("session", id) {
                return serde_json::from_str(&raw).map(Some).map_err(Self::parse_err);
            }
            // Miss na extensão → SQLite + copy-back.
            if let Some(raw) = self.sqlite.read_string(&key).map_err(Self::sqlite_err)? {
                let parsed: SessionRecord =
                    serde_json::from_str(&raw).map_err(Self::parse_err)?;
                let _ = ext.store("session", id, &raw);
                return Ok(Some(parsed));
            }
            return Ok(None);
        }
        self.sqlite.read_value(&key).map_err(Self::sqlite_err)
    }

    fn store_session(&self, id: &str, session: &SessionRecord) -> Result<()> {
        let key = format!("session-{id}");
        let json = baileys_store::buffer_json::stringify(session)
            .map_err(Self::sqlite_err)?;
        if let Some(ext) = self.extension() {
            if ext.store("session", id, &json) {
                return Ok(());
            }
            self.sqlite
                .write_string(&key, &json)
                .map_err(Self::sqlite_err)?;
            return Ok(());
        }
        self.sqlite
            .write_value(&key, session)
            .map_err(Self::sqlite_err)?;
        Ok(())
    }

    fn load_pre_key(&self, id: u32) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let key = format!("pre-key-{id}");
        if let Some(ext) = self.extension() {
            if let Some(raw) = ext.load("pre-key", &id.to_string()) {
                let kp: SerializedKeyPair =
                    serde_json::from_str(&raw).map_err(Self::parse_err)?;
                return Ok(Some((
                    Self::read_buffer(&kp.public),
                    Self::read_buffer(&kp.private),
                )));
            }
            // Miss na extensão → SQLite + copy-back.
            if let Some(raw) = self.sqlite.read_string(&key).map_err(Self::sqlite_err)? {
                let kp: SerializedKeyPair =
                    serde_json::from_str(&raw).map_err(Self::parse_err)?;
                let _ = ext.store("pre-key", &id.to_string(), &raw);
                return Ok(Some((
                    Self::read_buffer(&kp.public),
                    Self::read_buffer(&kp.private),
                )));
            }
            return Ok(None);
        }
        let value: Option<SerializedKeyPair> = self
            .sqlite
            .read_value(&key)
            .map_err(Self::sqlite_err)?;
        Ok(value.map(|kp| {
            (Self::read_buffer(&kp.public), Self::read_buffer(&kp.private))
        }))
    }

    fn remove_pre_key(&self, id: u32) -> Result<()> {
        let key = format!("pre-key-{id}");
        if let Some(ext) = self.extension() {
            // `removePreKey` do Node faz `keys.set({ 'pre-key': { [id]: null } })`.
            if ext.remove("pre-key", &id.to_string()) {
                return Ok(());
            }
            self.sqlite.remove(&key).map_err(Self::sqlite_err)?;
            return Ok(());
        }
        self.sqlite.remove(&key).map_err(Self::sqlite_err)?;
        Ok(())
    }

    fn load_signed_pre_key(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let creds = self.creds();
        let signed = &creds.signed_pre_key;
        Ok((
            Self::read_buffer(&signed.key_pair.public),
            Self::read_buffer(&signed.key_pair.private),
        ))
    }

    fn get_our_identity(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let creds = self.creds();
        let identity = &creds.signed_identity_key;
        Ok((
            generate_signal_pub_key(&Self::read_buffer(&identity.public)),
            Self::read_buffer(&identity.private),
        ))
    }

    fn get_our_registration_id(&self) -> Result<u32> {
        Ok(self.creds().registration_id)
    }

    fn load_sender_key(&self, name: &SenderKeyName) -> Result<SenderKeyRecord> {
        let key = format!("sender-key-{}", name.to_string());
        if let Some(ext) = self.extension() {
            if let Some(raw) = ext.load("sender-key", &name.to_string()) {
                let value: BufferValue =
                    serde_json::from_str(&raw).map_err(Self::parse_err)?;
                return SenderKeyRecord::deserialize(&Self::read_buffer(&value));
            }
            // Miss na extensão → SQLite + copy-back.
            if let Some(raw) = self.sqlite.read_string(&key).map_err(Self::sqlite_err)? {
                let value: BufferValue =
                    serde_json::from_str(&raw).map_err(Self::parse_err)?;
                let _ = ext.store("sender-key", &name.to_string(), &raw);
                return SenderKeyRecord::deserialize(&Self::read_buffer(&value));
            }
            return Ok(SenderKeyRecord::default());
        }
        let value: Option<BufferValue> = self
            .sqlite
            .read_value(&key)
            .map_err(Self::sqlite_err)?;
        match value {
            Some(v) => SenderKeyRecord::deserialize(&Self::read_buffer(&v)),
            None => Ok(SenderKeyRecord::default()),
        }
    }

    fn store_sender_key(&self, name: &SenderKeyName, record: &SenderKeyRecord) -> Result<()> {
        let key = format!("sender-key-{}", name.to_string());
        let json = record.serialize_json();
        let value = BufferValue::Buffer {
            type_: "Buffer".to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(json.as_bytes()),
        };
        let value_json = baileys_store::buffer_json::stringify(&value)
            .map_err(Self::sqlite_err)?;
        if let Some(ext) = self.extension() {
            // O Node grava `Buffer.from(serialized, 'utf-8')`
            // (BufferJSON → `{"type":"Buffer","data":"<base64>"}`).
            if ext.store("sender-key", &name.to_string(), &value_json) {
                return Ok(());
            }
            self.sqlite
                .write_value(&key, &value)
                .map_err(Self::sqlite_err)?;
            return Ok(());
        }
        self.sqlite
            .write_value(&key, &value)
            .map_err(Self::sqlite_err)?;
        Ok(())
    }
}
