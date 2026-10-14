# PROTOCOL.md — Protocolo WhatsApp Web em Rust

> Este documento descreve a pilha de protocolo implementada em BaileysRust,
> do handshake Noise ao envio de mensagens E2E e chamadas. É o mapa de como o
> Rust fala com o `web.whatsapp.com/ws/chat`.

## 1. Transporte

- **WebSocket** `wss://web.whatsapp.com/ws/chat?{routingQuery}` (parâmetros
  `E`, `M`, `agent`, etc., conforme o Baileys).
- Frames binários: `[flags(1) | length(2, big-endian) | payload]`.
- Keepalive periódico (nó `presence`/ping do WA).

## 2. Handshake Noise (WA Noise Protocol)

Espelhado em `baileys-socket/src/noise.rs`.

1. **ClientHello**: par efêmero Curve25519 → nó `handshake` com `client_hello`
   (`ephemeral` = 32 bytes de chave pública).
2. **ServerHello**: `ephemeral` do servidor + `static` + `payload` (certificado).
   - Verificação do **serial do certificado** (`WA_CERT_SERIAL`).
3. **ClientFinish**: `static` (chave Noise do dispositivo assinada) + `payload`
   cifrado com ChaCha20-Poly1305:
   - com creds → `login` node;
   - sem creds → `registration` node (primeiro pareamento).
4. Depois do handshake, todos os frames são `BinaryNode` (tokenizados pelo codec).

Detalhes criptográficos:
- `init` = SHA-256 de 32 bytes + identidade/serial (mesmo layout do libsignal/Baileys).
- Ratchet do Noise com `HKDF` + `ChaCha20-Poly1305` para cifrar cada frame.

## 3. Autenticação (QR / pairing)

1. Sem `me` nas creds → `registration` com `clientPayload` (registro).
2. Recebe QR via evento `Qr` (string `ref,key,...`).
3. `scanQr`/`scanPairingCode`:
   - **QR**: extrai `ref` e envia nó `action` `user` → `add` → `iq` → `pair-device`.
   - **Pairing code**: envia nó `action` `user` → `add` → `link_code_companion_reg`.
4. Resposta `pair-success` → `configureSuccessfulPairing` (grava `me`, `platform`,
   `account`) e salva creds.

## 4. Mensagens E2E (1:1)

Espelhado em `baileys-repository` + `baileys-signal`.

- **Session cipher** (X3DH + double ratchet):
  - `encryptMessage` → `enc` node com `v` = 2, `enc` = ciphertext protobuf.
  - Pre-keys: `PreKeySignalMessage` no primeiro envio; depois `SignalMessage`.
- **Registro**: `registrationId` de 14 bits, `nextPreKeyId`, upload de pre-keys
  (`uploadPreKeys`) quando o servidor sinaliza escassez.

## 5. Grupos (`w:g2`)

- `groupCreate`, `groupLeave`, `groupUpdateSubject`, `groupUpdateDescription`,
  `groupParticipantsUpdate`, `groupInvite`, `groupSettingUpdate`, `groupFetchAllParticipating`.
- **Sender keys**: `SenderKeyDistributionMessage` para cada participante; mensagens
  cifradas com `GroupCipher` (sender key).
- Metadata via `extractGroupMetadata` (nó `group` + filhos `description`, `participant`).

## 6. Mídia

- Upload: `upload` via MediaConn/`mms` → `mediaKey` (32 bytes), `url`, `directPath`,
  `fileEncSha256`, `mediaKeyTimestamp`.
- **Cifragem do payload**: AES-256-CBC com chave derivada de `mediaKey` (HKDF):
  `iv = mediaKey[0..16]`, `key = HKDF(mediaKey[16..32], "WhatsApp Video Keys")` para
  imagem/vídeo; variante `"WhatsApp Audio Keys"` para áudio/documento.
- Thumbnails JPEG via `image`, dimensões, waveform de áudio e conversão PTT/MP3
  via FFmpeg (quando disponível).

## 7. Chamadas (voz/vídeo)

- **Sinalização**: `call` → `offer`/`accept`/`preaccept`/`terminate`/`reject`/
  `relaylatency`/`transport`, com `callKey` cifrada de ponta a ponta
  (`decryptCallKeyInNode`).
- **SRTP**: AES-128-CTR + HMAC-SHA1 (chaves derivadas por JID via
  `derivePerJidSrtpKey` — HKDF de 32 bytes → 16 key + 14 salt).
- **Transporte**: relays UDP/SCTP (port de `sctp-relay`/`udp-relay`), STUN
  (allocate/binding/sender-subs/WA ping).
- **Codec**: `libopus_mlow` via FFI (encode/decode/CTL).

## 8. USync / contatos / status

- `usync_query` com protocolos `contact`/`status`/`devices` (modos `full`/`delta`),
  parsing de `USyncResult`, `USyncUser`, `USyncDevice`.

## 9. Formatos de serialização

| Camada | Formato |
|--------|---------|
| Frames WebSocket | binário WA (flags + length + payload) |
| Nós | tokenizados (`baileys-codec`) |
| Protobuf | `WAProto.proto` via prost |
| Sessões/chaves | BufferJSON (base64) no SQLite/Redis |
| Chaves Redis | `auth:{key}:{category}-{id}` (sem TTL) |

Ver [SESSION_FORMAT.md](SESSION_FORMAT.md) e [IMPLEMENTATION.md](IMPLEMENTATION.md).
