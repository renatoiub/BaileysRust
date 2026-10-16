//! Cache TTL plugável — port dos caches do Hineken (`@cacheable/node-cache`).
//!
//! `TtlCache<T>` é um cache híbrido: mantém o mapa em memória (fallback) e,
//! opcionalmente, delega para um backend externo (`CacheStore`, ex.: Redis).
//! A semântica é "backend primeiro, memória como fallback":
//!
//! - `get`: backend → hit desserializa JSON; miss/falha → memória.
//! - `set`: tenta backend (JSON com TTL); falha → grava só na memória.
//!   Backend saudável não polui a memória (reduz RAM do container).
//! - `remove`: apaga do backend e da memória.
//!
//! O backend é injetado via [`TtlCache::set_backend`] com um `namespace` que
//! prefixa a chave repassada (ex.: `cache:global:devices`). Caches globais
//! usam `cache:global:{namespace}`; caches por conexão usam
//! `cache:instance:{instanceKey}:{namespace}` (definido pelo app).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::sync::Mutex;

/// Backend externo de cache (ex.: Redis). Implementação dyn-safe: o crate
/// `socket` não depende do cliente Redis; o app injeta o que quiser.
pub trait CacheStore: Send + Sync {
    /// Retorna o valor como string (JSON) ou `None` em miss/falha.
    fn get(&self, key: &str) -> BoxFuture<'static, Option<String>>;
    /// Grava `value` com TTL em segundos; `false` em falha (aciona fallback).
    fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> BoxFuture<'static, bool>;
    /// Remove a chave; `false` em falha.
    fn remove(&self, key: &str) -> BoxFuture<'static, bool>;
}

/// Entrada de cache TTL (port dos caches do Hineken `cache-utils.ts`).
struct TtlEntry<T> {
    value: T,
    stored_at: Instant,
    ttl: Duration,
}

impl<T> TtlEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            stored_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.stored_at.elapsed() >= self.ttl
    }
}

/// Cache TTL híbrido: memória + backend externo opcional.
///
/// `T` precisa ser `Clone + Serialize + DeserializeOwned` para trafegar como
/// JSON pelo backend (a memória continua guardando o valor tipado).
pub struct TtlCache<T> {
    inner: Mutex<HashMap<String, TtlEntry<T>>>,
    default_ttl: Duration,
    max_keys: usize,
    /// Prefixo das chaves repassadas ao backend (ex.: `cache:global:devices`).
    namespace: std::sync::Mutex<String>,
    backend: std::sync::Mutex<Option<Arc<dyn CacheStore>>>,
}

impl<T: Clone + serde::Serialize + serde::de::DeserializeOwned> TtlCache<T> {
    pub fn new(default_ttl: Duration, max_keys: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            default_ttl,
            max_keys,
            namespace: std::sync::Mutex::new(String::new()),
            backend: std::sync::Mutex::new(None),
        }
    }

    /// Define o backend externo e o namespace que prefixa as chaves.
    pub fn set_backend(&self, namespace: &str, backend: Option<Arc<dyn CacheStore>>) {
        *self.namespace.lock().unwrap() = namespace.to_string();
        *self.backend.lock().unwrap() = backend;
    }

    /// Chave repassada ao backend: `"{namespace}:{key}"`.
    fn backend_key(&self, key: &str) -> String {
        let ns = self.namespace.lock().unwrap().clone();
        if ns.is_empty() {
            key.to_string()
        } else {
            format!("{ns}:{key}")
        }
    }

    pub async fn get(&self, key: &str) -> Option<T> {
        // Backend primeiro.
        let backend = self.backend.lock().unwrap().clone();
        let backend_key = self.backend_key(key);
        if let Some(backend) = backend {
            if let Some(json) = backend.get(&backend_key).await {
                if let Ok(value) = serde_json::from_str::<T>(&json) {
                    return Some(value);
                }
                // JSON ilegível (versão antiga?): trata como miss e cai
                // para a memória abaixo.
            }
        }
        // Fallback em memória.
        let mut map = self.inner.lock().await;
        match map.get(key) {
            Some(entry) if !entry.is_expired() => Some(entry.value.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    pub async fn set(&self, key: String, value: T) {
        self.set_with_ttl(key, value, self.default_ttl).await;
    }

    pub async fn set_with_ttl(&self, key: String, value: T, ttl: Duration) {
        // Tenta o backend primeiro (JSON + TTL em segundos).
        let backend = self.backend.lock().unwrap().clone();
        let backend_key = self.backend_key(&key);
        let mut backend_ok = false;
        if let Some(backend) = backend {
            let ttl_seconds = ttl.as_secs();
            if let Ok(json) = serde_json::to_string(&value) {
                backend_ok = backend.set(&backend_key, &json, Some(ttl_seconds)).await;
            }
        }
        // Backend ausente/falho → memória como fallback (e só então).
        if !backend_ok {
            self.memory_insert(key, value, ttl).await;
        }
    }

    async fn memory_insert(&self, key: String, value: T, ttl: Duration) {
        let mut map = self.inner.lock().await;
        if map.len() >= self.max_keys {
            // Limpeza simples: remove expirados; se ainda cheio, remove a
            // chave mais antiga (aproximação do maxKeys do node-cache).
            let now = Instant::now();
            map.retain(|_, e| now.duration_since(e.stored_at) < e.ttl);
            if map.len() >= self.max_keys {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, e)| e.stored_at)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(key, TtlEntry::new(value, ttl));
    }

    pub async fn contains(&self, key: &str) -> bool {
        self.get(key).await.is_some()
    }

    pub async fn remove(&self, key: &str) {
        let backend = self.backend.lock().unwrap().clone();
        let backend_key = self.backend_key(key);
        if let Some(backend) = backend {
            let _ = backend.remove(&backend_key).await;
        }
        self.inner.lock().await.remove(key);
    }
}
