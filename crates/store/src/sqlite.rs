//! Store SQLite compatível — espelhando `Utils/use-sqlLite.ts`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::buffer_json;
use crate::creds::AuthenticationCreds;

/// `SQLiteAuthState` — encapsula o acesso ao `db.sqlite` com a tabela `auth_data`.
pub struct SQLiteAuthState {
    conn: Mutex<Connection>,
    path: std::path::PathBuf,
}

/// Erros do store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl SQLiteAuthState {
    /// Abre (ou cria) o store em `folder/db.sqlite`, espelhando o `useSQLiteAuthState`.
    pub fn open(folder: impl AsRef<Path>) -> Result<Self, StoreError> {
        let folder = folder.as_ref();
        std::fs::create_dir_all(folder)?;
        let path = folder.join("db.sqlite");

        let conn = Connection::open(&path)?;

        // PRAGMAs iguais ao container Node.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "busy_timeout", 60000)?;
        conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
        conn.pragma_update(None, "journal_size_limit", 33554432)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS auth_data (
                key TEXT PRIMARY KEY,
                value TEXT
            );",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Escreve uma chave (serialização BufferJSON), com `INSERT OR REPLACE`.
    pub fn write_value<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), StoreError> {
        let json = buffer_json::stringify(value)?;
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            "INSERT OR REPLACE INTO auth_data (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, json],
        )?;
        Ok(())
    }

    /// Lê uma chave e desserializa.
    ///
    /// Usa parse **sem reviver** para que tipos tipados (ex. `BufferValue`,
    /// `AuthenticationCreds`) tratem o formato `{"type":"Buffer","data":"..."}`
    /// diretamente. Para acesso genérico (bytes já revividos), use [`read_raw`].
    pub fn read_value<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, StoreError> {
        let Some(value) = self.read_string(key)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(&value)?))
    }

    /// Lê o valor JSON cru de uma chave (sem desserializar).
    pub fn read_string(&self, key: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare("SELECT value FROM auth_data WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let value: String = row.get(0)?;
        Ok(Some(value))
    }

    /// Grava um JSON já serializado (sem re-serializar), `INSERT OR REPLACE`.
    pub fn write_string(&self, key: &str, json: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            "INSERT OR REPLACE INTO auth_data (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, json],
        )?;
        Ok(())
    }

    /// Lê uma chave como JSON genérico com buffers revividos (byte arrays).
    pub fn read_raw(&self, key: &str) -> Result<Option<serde_json::Value>, StoreError> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare("SELECT value FROM auth_data WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let value: String = row.get(0)?;
        Ok(Some(buffer_json::revive_str(&value)?))
    }

    /// Remove uma chave.
    pub fn remove(&self, key: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute("DELETE FROM auth_data WHERE key = ?1", rusqlite::params![key])?;
        Ok(())
    }

    /// Remove chaves por padrão LIKE (usado para limpar sender-keys de sessão).
    pub fn remove_by_pattern(&self, pattern: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute("DELETE FROM auth_data WHERE key LIKE ?1", rusqlite::params![pattern])?;
        Ok(())
    }

    /// Lê as credenciais.
    pub fn read_creds(&self) -> Result<Option<AuthenticationCreds>, StoreError> {
        self.read_value("creds")
    }

    /// Grava as credenciais.
    pub fn save_creds(&self, creds: &AuthenticationCreds) -> Result<(), StoreError> {
        self.write_value("creds", creds)
    }

    /// Remove todo o diretório da sessão (`deleteSQLiteAuthState`).
    pub fn delete(folder: impl AsRef<Path>) -> Result<(), StoreError> {
        std::fs::remove_dir_all(folder)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_roundtrip() {
        let dir = std::env::temp_dir().join(format!("baileys-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let store = SQLiteAuthState::open(&dir).unwrap();
        let value = serde_json::json!({"public": {"type":"Buffer","data":"AQIDBA=="}, "private": {"type":"Buffer","data":"BQYHCA=="}});
        store.write_value("test-key", &value).unwrap();

        let read: serde_json::Value = store.read_raw("test-key").unwrap().unwrap();
        assert_eq!(read, serde_json::json!({
            "public": [1,2,3,4],
            "private": [5,6,7,8]
        }));

        store.remove("test-key").unwrap();
        assert!(store.read_raw("test-key").unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
