# CACHE.md — Cache externo opcional (Redis) com fallback em memória

> Como offloadar os caches do `baileys-socket` para o Redis (ou qualquer
> backend externo) de forma opcional, com fallback automático para a memória
> quando o backend falhar. Sem backend, o comportamento é o atual: tudo em
> memória (`TtlCache`).

## 1. Visão geral

O `TtlCache<T>` do crate `socket` é **híbrido**: mantém o mapa em memória e,
opcionalmente, delega para um `CacheStore` externo. A semântica é:

- `get` → backend primeiro; hit desserializa JSON. Miss ou falha → memória.
- `set` / `set_with_ttl` → tenta o backend (JSON + TTL). Falha → grava na memória.
  Backend saudável **não** polui a memória (economiza RAM do container).
- `remove` → apaga do backend e da memória.

O backend é injetado com [`Client::set_cache_backend`](crates/socket/src/client.rs).
Cada cache tem um namespace que prefixa a chave no backend.

## 2. Escopo — globais x por conexão

Todos os caches podem ir para o backend. A diferença é o namespace da chave:

### Compartilhados (globais) — prefixo `cache:global:`

| Cache | Namespace | TTL | Descrição |
|-------|-----------|-----|-----------|
| `group_meta_cache` | `cache:global:groupmeta` | 3600s | Metadados de grupo por JID |
| `devices_cache` | `cache:global:devices` | 1000s | Fanout de devices por JID |
| `lid_cache` | `cache:global:lid` | 3600s | `@s.whatsapp.net` → `@lid` |
| `on_whatsapp_cache` | `cache:global:onwhatsapp` | 7200s | Existência no WhatsApp por JID |
| `profile_picture_cache` | `cache:global:profilepic` | 7200s | URL de foto de perfil por JID |

### Por conexão — prefixo `cache:instance:{instanceKey}:`

Isolados por instância para não misturar conexões do mesmo container nem de
containers diferentes:

| Cache | Namespace | TTL | Descrição |
|-------|-----------|-----|-----------|
| `sender_key_memory` | `cache:instance:{key}:senderkey` | 86400s | senderIds que já receberam a distribuição (anti-ban) |
| `msg_retry_cache` | `cache:instance:{key}:msgretry` | 3600s | Contador de retries por mensagem |
| `placeholder_resend_cache` | `cache:instance:{key}:placeholder` | 3600s | Evita PDOs duplicados por msg id |
| `force_session_cache` | `cache:instance:{key}:forcesession` | 86400s | JIDs com sessão E2E já forçada |

### Exceção: `send_cache`

O `send_cache` (mensagens para reenvio em retry) **permanece em memória**:
é o hot-path do retry (lido/escrito a cada envio) e sua durabilidade já é
coberta pelo `set_message_store` do app (`msg:{key}:{id}`, TTL 20 dias), que
sobrevive a restart. Offloadá-lo duplicaria esse store.

### Nota: `sender-key` do authState

O store de chaves `sender-key` (`auth:{key}:sender-key-{id}`) **já vai ao Redis**
via `SignalStoreExtension` (`RedisSignalExtension`) — é outro mecanismo, separado
do `sender_key_memory` (memória runtime anti-ban) listado acima.

## 3. API

### Trait `CacheStore`

```rust
use baileys_socket::CacheStore;
use futures_util::future::BoxFuture;

pub trait CacheStore: Send + Sync {
    fn get(&self, key: &str) -> BoxFuture<'static, Option<String>>;
    fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> BoxFuture<'static, bool>;
    fn remove(&self, key: &str) -> BoxFuture<'static, bool>;
}
```

- `get` retorna o valor como string (JSON) ou `None` em miss/falha.
- `set` retorna `false` em falha — é isso que aciona o fallback em memória.
- O crate `socket` **não** depende de Redis; o app injeta qualquer implementação.

### `Client::set_cache_backend`

```rust
pub fn set_cache_backend(&self, instance_key: &str, backend: Arc<dyn CacheStore>);
```

Aplica o backend a todos os caches com os namespaces da seção 2.

## 4. Exemplo prático — RedisCacheStore

```rust
use std::sync::Arc;

use baileys_socket::{CacheStore, Client};
use futures_util::future::BoxFuture;

/// Implementação sobre um cliente Redis do app (aqui, um wrapper simples).
/// Qualquer client serve: o importante é degradar para None/false em falha.
pub struct RedisCacheStore {
    redis: Arc<MyRedisClient>,
}

impl CacheStore for RedisCacheStore {
    fn get(&self, key: &str) -> BoxFuture<'static, Option<String>> {
        let redis = self.redis.clone();
        let key = key.to_string();
        Box::pin(async move { redis.get_string(&key).await })
    }

    fn set(&self, key: &str, value: &str, ttl_seconds: Option<u64>) -> BoxFuture<'static, bool> {
        let redis = self.redis.clone();
        let key = key.to_string();
        let value = value.to_string();
        Box::pin(async move { redis.set_ex(&key, &value, ttl_seconds).await })
    }

    fn remove(&self, key: &str) -> BoxFuture<'static, bool> {
        let redis = self.redis.clone();
        let key = key.to_string();
        Box::pin(async move {
            redis.del(&key).await;
            true
        })
    }
}

// No app, ao criar o client:
// let client = Arc::new(Client::new(session_folder, ClientConfig::default())?);
// if std::env::var("CACHE_BACKEND").ok().as_deref() == Some("redis") {
//     client.set_cache_backend(
//         &instance_key,
//         Arc::new(RedisCacheStore { redis: redis_client.clone() }),
//     );
// }
```

Chaves no Redis (exemplo com `instance_key = "minha-conexao"`):

```
cache:global:groupmeta:123456789-123456@g.us
cache:global:devices:group-{lid}
cache:global:lid:5511999999999@s.whatsapp.net
cache:global:onwhatsapp:5511999999999@s.whatsapp.net
cache:global:profilepic:5511999999999@s.whatsapp.net
cache:instance:minha-conexao:senderkey:123456789-123456@g.us
cache:instance:minha-conexao:msgretry:ABCDEFG123:5511999999999@s.whatsapp.net
cache:instance:minha-conexao:placeholder:ABCDEFG123
cache:instance:minha-conexao:forcesession:5511999999999@s.whatsapp.net
```

## 5. Configuração no containerRust

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `CACHE_BACKEND` | `memory` | `redis` liga o offload; `memory` mantém tudo em memória |

```bash
CACHE_BACKEND=redis REDIS_URL=redis://:senha@redis:6379 ./container-rust
```

O `RedisCacheStore` do containerRust usa o `RedisClient` existente, que já
degrada com timeout de 1500ms e "fail closed". Ou seja:

- Redis fora → `get` retorna `None`, `set` retorna `false` → o `TtlCache`
  grava/lê da memória e **a operação não para**.
- Redis volta → os próximos `set` voltam a popular o Redis normalmente.

## 6. Validação manual

```bash
# 1. Subir com Redis ativo
CACHE_BACKEND=redis ./container-rust

# 2. Conferir as chaves sendo populadas
redis-cli KEYS 'cache:*'

# 3. Derrubar o Redis no meio da operação e enviar mensagens:
#    os envios continuam (fallback em memória).

# 4. Religar o Redis: os caches voltam a ser populados.
```
