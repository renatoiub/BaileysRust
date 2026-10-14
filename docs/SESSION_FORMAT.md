# SESSION_FORMAT.md — Spec de compatibilidade de sessão

> Objetivo: permitir **trocar o container Node pelo `containerRust` (e vice-versa) sem re-escanear o QR**.
> Este documento é a especificação exata do formato de sessão que o `baileys-store` implementa.

Fontes de referência (somente leitura):

- `container/src/services/whatsapp/index.ts` — `useSQLiteAuthState('db/' + instanceKey)`
- `container/src/services/whatsapp/authKeysRedis.ts` — chaves de sinal no Redis
- `Hineken/src/Utils/use-sqlLite.ts` — implementação do store SQLite
- `Hineken/src/Utils/generics.ts` — `BufferJSON.replacer`/`reviver`
- `Hineken/src/Types/Auth.ts` — `SignalDataTypeMap`, `AuthenticationCreds`

---

## 1. Visão geral

| Onde | O que guarda | Formato |
|------|--------------|---------|
| SQLite `db/{key}/db.sqlite` | `creds` + fallback/espelho das chaves | `BufferJSON` |
| Redis | chaves de sinal (`session`, `pre-key`, `sender-key`, ...) | `BufferJSON`, **sem TTL** |

A regra de ouro: **`creds` só vive no SQLite.** As chaves de sinal vivem no Redis, com
fallback transparente para o SQLite (o `authKeysRedis` copia do SQLite o que ainda
não está no Redis, e grava no SQLite se o Redis falhar).

---

## 2. BufferJSON — serialização exata

Definido em `Hineken/src/Utils/generics.ts`:

```ts
export const BufferJSON = {
  replacer: (k, value: any) => {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array || value?.type === 'Buffer') {
      return { type: 'Buffer', data: Buffer.from(value?.data || value).toString('base64') }
    }
    return value
  },
  reviver: (_, value: any) => {
    if (typeof value === 'object' && !!value && (value.buffer === true || value.type === 'Buffer')) {
      const val = value.data || value.value
      return typeof val === 'string' ? Buffer.from(val, 'base64') : Buffer.from(val || [])
    }
    return value
  }
}
```

### 2.1 Regras de escrita (replacer)

- `Buffer`, `Uint8Array` ou objeto já marcado com `type: 'Buffer'` → `{"type":"Buffer","data":"<base64>"}`.
- A base64 é **standard com padding** (`Buffer.toString('base64')`).
- Todos os demais valores (números, strings, objetos, arrays) são serializados normalmente.

### 2.2 Regras de leitura (reviver)

- Objeto com `buffer === true` **ou** `type === 'Buffer'` → converte `data` (ou `value`)
  de base64 para bytes; se não for string, usa o array/valor direto (`Buffer.from(val || [])`).
- **Não** há suporte a `type === 'Buffer'` com `data` como array de números — o Node
  sempre grava `data` como string base64.

### 2.3 Implementação Rust

`baileys-store/src/buffer_json.rs` implementa `replacer`/`reviver` recursivos sobre
`serde_json::Value`, com a mesma semântica. Testes de roundtrip garantem paridade.

---

## 3. SQLite — `db/{key}/db.sqlite`

### 3.1 Schema

```sql
CREATE TABLE IF NOT EXISTS auth_data (
  key TEXT PRIMARY KEY,
  value TEXT
);
```

`value` é sempre o JSON do valor serializado com `BufferJSON.replacer`.

### 3.2 PRAGMAs aplicados na abertura (idênticos ao Node)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA busy_timeout = 60000;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA journal_size_limit = 33554432;
```

### 3.3 Chaves

| Chave | Conteúdo | Observações |
|-------|----------|-------------|
| `creds` | `AuthenticationCreds` | Única que SEMPRE está no SQLite |
| `{category}-{id}` | valor da categoria | Espelho/fallback das chaves de sinal |

Gravação: `INSERT OR REPLACE INTO auth_data (key, value) VALUES (?, ?)`.

Remoção de sessão: quando uma chave `session-{id}` é removida, o Node também apaga
**por padrão LIKE** as sender-keys vinculadas (ver §4.3).

### 3.4 `creds` — `AuthenticationCreds`

Campos (ordem de serialização do JSON é irrelevante; os nomes são os do TS):

```
noiseKey:                    { public: BufferJSON, private: BufferJSON }
pairingEphemeralKeyPair:     { public: BufferJSON, private: BufferJSON }
signedIdentityKey:           { public: BufferJSON, private: BufferJSON }
signedPreKey:                { keyPair: {public, private}, signature: BufferJSON,
                               keyId: number, timestampS?: number }
registrationId:              number          // 0..16383 (14 bits)
advSecretKey:                string          // base64 de 32 bytes
me?:                         Contact         // { id, name?, lid?, notify? }
account?:                    ADVSignedDeviceIdentity (proto)
signalIdentities?:           SignalIdentity[] // [{identifier:{name,deviceId}, identifierKey}]
myAppStateKeyId?:            string
firstUnuploadedPreKeyId:     number
nextPreKeyId:                number
lastAccountSyncTimestamp?:   number
platform?:                   string
processedHistoryMessages:    MinimalMessage[]
accountSyncCounter:          number
accountSettings:             { unarchiveChats: boolean, ... }
registered:                  boolean
pairingCode?:                string
lastPropHash?:               string
routingInfo?:                BufferJSON
nctSalt?:                    BufferJSON
reachoutTimeLock?:           ReachoutTimelockState
```

Inicialização (`initAuthCreds`):

```
noiseKey               = Curve.generateKeyPair()
pairingEphemeralKeyPair= Curve.generateKeyPair()
signedIdentityKey      = Curve.generateKeyPair()
signedPreKey           = signedKeyPair(identityKey, 1)
registrationId         = random 2 bytes & 16383
advSecretKey           = randomBytes(32).toString('base64')
processedHistoryMessages = []
nextPreKeyId = 1
firstUnuploadedPreKeyId = 1
accountSyncCounter = 0
accountSettings = { unarchiveChats: false }
registered = false
```

> Atenção: `signedPreKey.keyId` começa em `1`. `timestampS` só aparece depois que a
> chave é registrada no servidor.

---

## 4. Chaves de sinal — `SignalDataTypeMap`

Definido em `Hineken/src/Types/Auth.ts`:

```ts
export type SignalDataTypeMap = {
  'pre-key': KeyPair                          // { public, private }
  session: Uint8Array                         // record do ratchet (bytes)
  'sender-key': Uint8Array                    // sender key record (bytes)
  'sender-key-memory': { [jid: string]: boolean }
  'app-state-sync-key': proto.Message.IAppStateSyncKeyData
  'app-state-sync-version': LTHashState       // { version, hash, indexValueMap }
  'contacts-tc-token': { token: Buffer, timestamp?: string, senderTimestamp?: number }
  absentMessage: { messageKey: WAMessageKey }
}
```

### 4.1 IDs por categoria

| Categoria | Formato típico do `id` |
|-----------|------------------------|
| `pre-key` | número (string), ex.: `1`, `2`, ... |
| `session` | `{jid}::{deviceId}`, ex.: `5511999998888@s.whatsapp.net::0` |
| `sender-key` | `{jid}` (grupo), ex.: `123456789-1610000000@g.us` |
| `app-state-sync-key` | `regular` (ou outro nome de coleção) |
| `app-state-sync-version` | `regular` |
| `contacts-tc-token` | `contacts` (equivalente ao antigo `tctoken`) |
| `absentMessage` | `{jid}` |

### 4.2 Redis — chaves e convenções

`container/src/services/whatsapp/authKeysRedis.ts`:

```ts
function redisKey(instanceKey: string, category: string, id: string): string {
  return `auth:${instanceKey}:${category}-${id}`;
}
```

- **Chave**: `auth:{instanceKey}:{category}-{id}`.
- **Valor**: `JSON.stringify(value, BufferJSON.replacer)` — exatamente o mesmo JSON do SQLite.
- **Sem TTL** (persistentes; o `setPersistentMany` usa `SET` simples, sem `EX`).
- Exceção de revive: `app-state-sync-key` é revivido como `proto.Message.AppStateSyncKeyData`
  (via `fromObject`) após o `BufferJSON.reviver`.

Fluxo de `get`:

1. `MGET` das chaves (em blocos de 200).
2. Para cada `null`/erro → busca no SQLite (mesma chave `{category}-{id}`).
3. O que veio do SQLite é copiado de volta para o Redis (`SET`, sem TTL).

Fluxo de `set`:

1. `SET` de todas as chaves (pipeline). Se falhar → grava no SQLite.
2. Valores `null`/`undefined` → `DEL` da chave (e SQLite remove).

Fluxo de `remove`:

1. `DEL` das chaves `auth:{key}:{category}-{id}`.
2. Se `category === 'session'`, também remove as sender-keys vinculadas (ver 4.3).
3. Sempre propaga para o SQLite.

### 4.3 Vinculação sender-key ↔ session

Quando uma sessão `session-{id}` é removida (id ex. `5511...@s.whatsapp.net::0`), o Node
também apaga:

```
beforeAt    = id.split('@')[0]
senderKeyId = beforeAt.includes('.')
                ? beforeAt.replace('.', '::')   // ex.: 5511...::0
                : `${beforeAt}::0`
```

E remove:

- Redis: `auth:{key}:{senderKeyId}` (categoria implícita antiga) e `auth:{key}:sender-key-{senderKeyId}`.
- SQLite: `DELETE FROM auth_data WHERE key LIKE '{senderKeyId}%'`.

> Observação: no `authKeysRedis.ts` o `linked` é `senderKeyId(id)` e as chaves deletadas
> são `auth:${instanceKey}:${linked}` e `redisKey(instanceKey, 'sender-key', linked)` —
> ou seja, `auth:{key}:{senderKeyId}` e `auth:{key}:sender-key-{senderKeyId}`.

---

## 5. Contrato do `baileys-store` (Rust)

`crates/store/src/sqlite.rs` + `crates/store/src/buffer_json.rs`:

| Operação Node | API Rust |
|---------------|----------|
| `safeWrite(key, value)` | `SQLiteAuthState::write_value(key, &value)` |
| `safeRead(key)` | `SQLiteAuthState::read_value::<T>(key)` / `read_raw(key)` |
| `safeRemove(key)` | `SQLiteAuthState::remove(key)` |
| `safeRemoveByPattern(pattern)` | `SQLiteAuthState::remove_by_pattern(pattern)` |
| `saveCreds()` | `SQLiteAuthState::save_creds(&creds)` |

O Redis será implementado na Fase 5 (`containerRust`), espelhando `authKeysRedis.ts`,
incluindo o fallback SQLite e a ausência de TTL.

---

## 6. Teste de swap (critério de aceite da Fase 5)

1. Instância `X` conectada no container Node (`db/X/db.sqlite` + Redis).
2. Parar o container Node de `X` **sem logout**.
3. Subir `containerRust` com o mesmo `db/X` e o mesmo Redis.
4. O Rust lê `creds` do SQLite e as chaves do Redis (ou SQLite).
5. A conexão deve reconectar **sem novo QR** e continuar enviando/recebendo.

Critério de falha: qualquer `MESSAGE` que exija novo pareamento ou qualquer escrita
que o Node não consiga ler de volta (JSON dessincronizado) invalida o swap.
