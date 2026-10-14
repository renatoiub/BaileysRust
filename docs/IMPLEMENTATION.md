# IMPLEMENTATION.md — BaileysRust: implementação completa

> BaileysRust é a reimplementação em Rust da biblioteca WhatsApp Web (Hineken/Baileys)
> e do container HTTP. Substitui o Node com paridade de sessão, de protocolo e de API.

## 1. Estrutura do workspace

```
BaileysRust/
  Cargo.toml            # workspace (versões compartilhadas)
  docs/                 # esta documentação
  crates/
    core/               # WABinary, JID, IDs (crockford/registration id)
    codec/              # tokenização binária (decode/encode do WA)
    crypto/             # Curve25519, XEdDSA, HKDF, AES-GCM, media keys
    proto/              # WAProto.proto compilado com prost (bytes idênticos)
    store/              # SQLite auth_data + BufferJSON (compatível com Node)
    socket/             # Noise handshake, WebSocket, QR/pairing, login,
                        # mensagens E2E, grupos, USync, link preview, mídia
    signal/             # ratchet duplo do libsignal (session/sender-key)
    repository/         # criptografia E2E 1:1 e grupo (reencrypt/decrypt)
    media/              # upload/download, thumbnail, FFmpeg, waveform
    call/               # RTP/SRTP, STUN, libopus_mlow FFI, signaling, relays
  spike/                # spike standalone: handshake Noise + frames (Fase 0)
containerRust/
  Cargo.toml            # binário Axum (container HTTP)
  src/
    main.rs             # boot: env, tracing, AppState, RabbitMQ consumer
    state.rs            # AppState (db, redis, instances, call managers)
    routes.rs           # paridade de rotas do container Node
    middleware.rs       # verifyToken / isSession / isSessionOnline
    instances.rs        # InstanceManager + ciclo de vida do Client
    auth_keys.rs        # authKeysRedis (Redis + fallback SQLite)
    redis.rs            # cliente Redis com degradação graciosa
    db.rs               # SQLx MariaDB/MySQL + tabela Instances
    rabbitmq.rs         # producer/consumer com circuit breaker + DLQ
    call_socket.rs      # ponte Client → CallSocket do baileys-call
    error.rs            # AppError + shape `retorno` do Node
  tests/
    session_swap.rs     # teste de swap Node ↔ Rust sem novo QR
```

Regra de ouro: **nunca** editar `manager/`, `container/` ou `Hineken/` (somente
leitura como referência).

---

## 2. Fases (histórico)

| Fase | Escopo | Estado |
|------|--------|--------|
| 0 | Spike do handshake Noise (connect, Conn/Stream) | ✅ |
| 1 | QR/pairing + creds + texto E2E ida e volta | ✅ |
| 2 | Mídia (imagem, áudio, vídeo, doc, thumbnail) | ✅ |
| 3 | Grupos `w:g2`, USync, link preview | ✅ |
| 4 | Calls RTP/SRTP, STUN, opus FFI, signaling, relays | ✅ |
| 4a–4g | Detalhes de call + testes unitários | ✅ |
| 5 | `containerRust` (Axum, RabbitMQ, Redis, MariaDB) + swap | ✅ |
| 6 | Documentação completa | ✅ |

---

## 3. Crates em detalhe

### 3.1 `baileys-core`
- `BinaryNode` + `BinaryContent` (WABinary), atributos de nó e serialização de bytes.
- `jid` — `jidEncode`, `jidDecode`, `jidNormalizedUser`, `isJidGroup`, `isLidUser`,
  sufixos de servidor (`@s.whatsapp.net`, `@g.us`, `@lid`).
- `ids` — `generateRegistrationId` (14 bits), codificação crockford.
- `constants` — delimitadores e constantes do protocolo.

### 3.2 `baileys-codec`
- Decoder/encoder de tokens binários (dicionário de byte único e duplo), idêntico
  ao `WABinary/constants.ts` + `decode.ts`/`encode.ts`.
- Usado pelo Noise handler para deserializar `BinaryNode` recebidos.

### 3.3 `baileys-crypto`
- `Curve` (X25519), `signedKeyPair` (XEdDSA sobre Curve25519) — **vetores de teste
  idênticos ao libsignal**.
- `derive*` — HKDF das chaves de mídia (AES-256-CBC) e de chamadas.

### 3.4 `baileys-proto`
- `WAProto.proto` copiado do Hineken e compilado com `prost-build`.
- `proto::WebMessageInfo`, `proto::Message`, `proto::ContextInfo`, etc. — mesmos
  tags/bytes do protobuf original.

### 3.5 `baileys-store`
- `SQLiteAuthState` — `db/{key}/db.sqlite`, tabela `auth_data(key, value)`,
  PRAGMAs iguais ao Node (WAL, synchronous NORMAL, busy_timeout 60000...).
- `buffer_json` — `replacer`/`reviver` do BufferJSON (buffers ↔ base64).
- `creds` — `AuthenticationCreds` com `#[serde(rename_all = "camelCase")]`
  para leitura/escrita idêntica ao Node.
- Ver [SESSION_FORMAT.md](SESSION_FORMAT.md) para a spec exata.

### 3.6 `baileys-socket`
- `noise.rs` — `NoiseHandler` (WA Noise: Curve25519 + ChaCha20-Poly1305),
  `client_hello`, `parse_server_hello`, enquadramento de frames binários.
- `client.rs` — `Client` com `run()` (WebSocket + handshake), `sink()`,
  `send_node`, `query_node`, eventos (`Qr`, `CredsUpdate`, `Message`,
  `ConnectionUpdate`), envio por conveniência (`send_text`, `send_image`,
  `send_video`, `send_audio`, `send_document`, `send_group_text/message`) e
  helpers de rota.
- `handshake.rs` — `generateLoginNode`, `generateRegistrationNode`,
  `configureSuccessfulPairing`, `ClientConfig`.
- `groups.rs` — operações do namespace `w:g2` + `extractGroupMetadata`.
- `usync.rs` — USync (contatos, status, dispositivos).
- `link_preview.rs` — parser de Open Graph/HTML.
- `media.rs` — montagem de mensagens de mídia (`MediaUpload`, `send_media_message`).

### 3.7 `baileys-signal`
- Port do libsignal: session cipher (chain keys, message keys, skipped keys),
  pre-key, ratchet, group cipher (sender keys). Formato de record **JSON-compatível**
  (serialização do SessionRecord/SenderKeyRecord usada pelo Node).

### 3.8 `baileys-repository`
- `decryptMessage`/`encryptMessage` 1:1 (session cipher) e grupo (sender key),
  `reencryptMessage`, `getSenderKeyDistribution`, derivando `derivePerJidSrtpKey`
  quando o conteúdo é call key.

### 3.9 `baileys-media`
- `MediaType`, `download_media`, `upload_media`, `encrypt_media`/`decrypt_media`
  (AES-256-CBC + HMAC), `image_thumbnail`, `extract_image_dimensions`,
  `ffmpeg_probe`, `extract_video_thumb`, `audio_waveform`, conversão PTT/MP3.

### 3.10 `baileys-call`
- `rtp.rs` — header/packet/session RTP.
- `srtp.rs` — SRTP AES-128-CTR + HMAC-SHA1 (RFC 3711).
- `stun.rs` — allocate, binding, sender subscriptions, SSRC list, WA ping.
- `mlow.rs` — FFI para `libopus_mlow` (encode/decode/CTL) com fallback se ausente.
- `encryption.rs` — `generateCallKey`, `derivePerJidSrtpKey`, `secureSSRC`.
- `signaling.rs` — offer/accept/preaccept/terminate/reject/relaylatency/transport
  + `decryptCallKeyInNode`.
- `udp_relay.rs`/`audio.rs` — transporte UDP relay e engine de áudio.
- `player.rs` — `Player` de demonstração (cpal): toca PCM e faz roundtrip do MLow.
- `state.rs` — `CallInfo` (state machine de chamada).
- `call_manager.rs` — `NativeCallManager` + trait `CallSocket`.

Exemplo executável: `cargo run -p baileys-call --example play -- tone 440 2`
(ou `roundtrip` para validar o codec).

---

## 4. `containerRust` (Fase 5)

### 4.1 Boot
`main.rs` carrega `.env`, inicializa tracing, monta `AppState::build()` (MySQL
tolerante: se o banco não subir, o HTTP sobe degradado), inicia o consumidor
RabbitMQ (também tolerante) e serve o Axum na porta `PORT` (padrão 3000).

### 4.2 Rotas (paridade total com `container/src/routes/index.ts`)

| Prefixo | Rotas |
|---------|-------|
| `/instances` | `list`, `create`, `remove`, `qr`, `scanQr`, `logout`, `info`, `edit`, `flushCache`, `migrate` |
| `/messages` | `sendMessage`, `editMessage`, `deleteMessage`, `reactMessage`, `sendList`, `sendLocation`, `sendLinkPreview`, `ForwardMessage`, `SendContact` |
| `/misc` | `onWhatsapp`, `getProfilePicture`, `updateProfilePicture`, `block`, `getcustomStatus`, `UpdateMyStatus`, `readMessages`, `getContacts`, `getMessage` |
| `/groups` | `all`, `getAlGroups`, `getInfo`, `create`, `leave`, `participants`, `admins`, `updateSettings`, `update`, `updatePicture`, `getInfoUrl`, `joinFromUrl`, `getGrouopUrl`, `flush`, `getAllNews` |
| `/calls` | `RejectCall`, `token` (POST/GET) |

### 4.3 Middlewares
- `verifyToken` — `Authorization: Bearer <BEAREAR_TOKEN>` (validação real apenas
  com `BEAREAR_TOKEN_STRICT=true`, espelhando o comentário do Node).
- `isSession` — exige `key` no body e existência da instância.
- `isSessionOnline` — exige instância online + `bearear_token` da instância
  (com retry de 3×2s, igual ao Node).

### 4.4 Persistência
- SQLite: `DB_ROOT/{key}/db.sqlite` (creds + fallback).
- Redis: `REDIS_URL` (padrão `redis://:{DB_PASSWORD}@redis:6379`), chaves
  `auth:{key}:{category}-{id}` **sem TTL**.
- MariaDB: `Instances` (via SQLx, `DATABASE`/`CONTEINER_ID` como container).

### 4.5 RabbitMQ
Filas `${DATABASE}_messages`, `${DATABASE}_events`, `${DATABASE}_acks`,
`${DATABASE}_webhook_dlq` (duráveis, capped `x-max-length` com `drop-head`).
Circuit breaker: `WEBHOOK_CIRCUIT_FAILURES` (5), `WEBHOOK_CIRCUIT_TIMEOUTS` (2),
`WEBHOOK_CIRCUIT_OPEN_MS` (90000), timeout `WEBHOOK_TIMEOUT_MS` (5000).
Política: timeout/5xx → DLQ sem requeue; 4xx → retry único; senão DLQ.

---

## 5. Compilação e teste

```bash
# check do container
cargo check --manifest-path containerRust/Cargo.toml

# testes do workspace (lib)
cargo test --manifest-path BaileysRust/Cargo.toml --workspace

# exemplos de uso da lib (parear + enviar texto/mídia)
cargo run -p baileys-socket --example basic -- ./session 5511999999999@s.whatsapp.net
cargo run -p baileys-socket --example send_media -- ./session 5511999999999@s.whatsapp.net image foto.png

# teste de swap de sessão (Node ↔ Rust)
cargo test --manifest-path containerRust/Cargo.toml --test session_swap
```

---

## 6. Critérios de aceite

1. `cargo check --manifest-path containerRust/Cargo.toml` sem erros.
2. `cargo test --manifest-path BaileysRust/Cargo.toml --workspace` verde.
3. `cargo test --manifest-path containerRust/Cargo.toml --test session_swap` verde
   (lê creds Node, roundtrip BufferJSON, formato de chave Redis).
4. Nenhuma edição em `manager/`, `container/`, `Hineken/`.
