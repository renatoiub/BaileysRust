# BaileysRust

Reimplementação em **Rust** da biblioteca WhatsApp Web (Baileys/Hineken) com
**paridade de sessão, protocolo e API** com o container Node. Permite parear,
enviar e receber mensagens E2E (texto, imagem, vídeo, áudio, documento), operar
grupos e fazer chamadas — sem depender de Node.js.

A biblioteca é **síncrona na camada de storage** e roda **100% no SQLite
nativo** (igual ao `useSQLiteAuthState` do Node). Redis/RabbitMQ são acessórios
**opcionais** que o seu app injeta por cima, se quiser.

---

## Crates

| Crate | O que faz |
|-------|-----------|
| `baileys-socket` | `Client` de alto nível: QR/pareamento, login, envio/recebimento E2E, grupos, presença |
| `baileys-store` | SQLite nativo (`auth_data`) + `BufferJSON` (compatível com o Node) |
| `baileys-repository` | Criptografia E2E 1:1 (ratchet) e de grupo (sender key) |
| `baileys-signal` | Port do libsignal (session cipher, pre-key, sender key) |
| `baileys-media` | Upload/download de mídia, FFmpeg (PTT/MP3, thumbnails, waveform) |
| `baileys-core` | WABinary, JID, IDs, constantes |
| `baileys-codec` | Tokenização binária do protocolo |
| `baileys-crypto` | Curve25519, XEdDSA, HKDF, AES-GCM |
| `baileys-proto` | `WAProto.proto` compilado com `prost` |
| `baileys-call` | Chamadas RTP/SRTP + STUN + opus (MLow) |

## Pré-requisitos

- Rust (edition 2021+).
- `ffmpeg` no `PATH` (só para áudio/vídeo: conversão PTT/MP3, thumbnail, waveform).
- `libopus_mlow` (só para chamadas; sem ela o `baileys-call` degrada).

## Quick start

Adicione a dependência no seu `Cargo.toml` (via git ou path):

```toml
[dependencies]
baileys-socket = { git = "https://github.com/renatoiub/BaileysRust.git", package = "baileys-socket" }
tokio = { version = "1", features = ["full"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

> Os crates internos (`baileys-socket` → `baileys-media`, `baileys-store`, ...)
> são resolvidos automaticamente pelo workspace.

### 1. Parear (QR no terminal) e enviar texto

```rust,ignore
use std::sync::Arc;
use baileys_socket::{Client, ClientConfig, ClientEvent, ConnectionUpdate};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // SQLite nativo: db.sqlite é criado aqui. Sem Redis, sem config extra.
    let client = Arc::new(Client::new("./session", ClientConfig::default())?);

    let mut rx = client.subscribe();
    let conn = tokio::spawn(client.clone().run());

    while let Ok(ev) = rx.recv().await {
        match ev {
            ClientEvent::Qr(qr) => {
                // Renderize este payload como QR code (veja examples/basic.rs).
                println!("QR: {qr}");
            }
            ClientEvent::ConnectionUpdate(ConnectionUpdate { connection, .. }) => {
                println!("connection: {connection}");
                if connection == "open" {
                    let sink = client.sink().await.unwrap();
                    let res = client
                        .send_text("5511999999999@s.whatsapp.net", "Olá do BaileysRust!", &sink)
                        .await?;
                    println!("enviado: {}", res.message_id);
                }
            }
            ClientEvent::Message { info, .. } => {
                let text = info
                    .message
                    .and_then(|m| m.extended_text_message)
                    .and_then(|t| t.text)
                    .unwrap_or_default();
                println!("recebido: {text}");
            }
            _ => {}
        }
    }

    let _ = conn.await;
    Ok(())
}
```

### 2. Enviar mídia (imagem / vídeo / áudio / documento)

Os métodos de conveniência cuidam do pipeline completo (conversão FFmpeg →
upload criptografado → `wa::Message` → E2E):

```rust,ignore
let bytes = std::fs::read("foto.png")?;
let sink = client.sink().await.unwrap();

// Imagem (JPEG/PNG/WebP/GIF)
client.send_image(jid, &bytes, "image/png", Some("legenda"), &sink).await?;

// Vídeo (MP4/WebM...) — extrai dimensões/duração e thumbnail via FFmpeg
client.send_video(jid, &video, "video/mp4", Some("legenda"), &sink).await?;

// Áudio: ptt = true → mensagem de voz (OGG/Opus); false → áudio normal (MP3)
client.send_audio(jid, &audio, /* ptt */ true, &sink).await?;

// Documento (PDF, ZIP, ...)
client.send_document(jid, &pdf, "application/pdf", "documento.pdf", None, &sink).await?;
```

### 3. Enviar para grupo

```rust,ignore
// Texto cifrado por sender-key
client.send_group_text("120363...@g.us", "Olá grupo!", &sink).await?;

// Mídia em grupo: monte o wa::Message e use send_group_message
use baileys_proto::proto as wa;
let msg = wa::Message {
    image_message: Some(Box::new(wa::message::ImageMessage {
        /* url, media_key, file_sha256, ... (veja examples) */
        ..Default::default()
    })),
    ..Default::default()
};
client.send_group_message("120363...@g.us", msg, &sink).await?;
```

### 4. Storage externo (Redis) — opcional

Sem configuração, o `Client` usa **apenas SQLite** (fonte durável das creds e
chaves). Para escalar com Redis (igual ao `authKeysRedis.ts` do Node), o seu
app implementa o trait `SignalStoreExtension` e injeta:

```rust,ignore
use std::sync::Arc;
use baileys_repository::SignalStoreExtension;

struct MyRedisExtension { /* seu cliente Redis */ }

impl SignalStoreExtension for MyRedisExtension {
    fn load(&self, category: &str, id: &str) -> Option<String> { /* MGET */ None }
    fn store(&self, category: &str, id: &str, json: &str) -> bool { /* SET */ false }
    fn remove(&self, category: &str, id: &str) -> bool { /* DEL */ false }
}

client.set_store_extension(Arc::new(MyRedisExtension { /* ... */ }));
```

- `load` → `Some(json)` = chave no backend; `None` = cai no SQLite (e a lib
  faz o copy-back chamando `store`).
- `store`/`remove` → `true` = backend tratou; `false` = cai no SQLite.

## Exemplos executáveis

```bash
# Parear via QR e enviar texto
cargo run -p baileys-socket --example basic -- ./session 5511999999999@s.whatsapp.net

# Enviar mídia (sessão já pareada)
cargo run -p baileys-socket --example send_media -- ./session 5511999999999@s.whatsapp.net image foto.png
cargo run -p baileys-socket --example send_media -- ./session 5511999999999@s.whatsapp.net video video.mp4
cargo run -p baileys-socket --example send_media -- ./session 5511999999999@s.whatsapp.net audio audio.wav true
cargo run -p baileys-socket --example send_media -- ./session 5511999999999@s.whatsapp.net doc relatorio.pdf

# Chamadas / áudio: tocar tom na caixa de som (player de exemplo do baileys-call)
cargo run -p baileys-call --example play -- tone 440 2

# Validar o codec MLow: tom → encode → decode → playback
cargo run -p baileys-call --example play -- roundtrip 440 2
```

> Para `roundtrip` (e chamadas), o `baileys-call` precisa da lib nativa
> `libopus_mlow` (`opus_mlow.dll` no Windows, `libopus_mlow.so` no Linux,
> `libopus_mlow.dylib` no macOS). Coloque-a em `native/` ao lado do binário ou
> defina `MLOW_LIB_PATH=/caminho/para/a/lib`. Sem ela, o exemplo `tone` ainda
> funciona (não usa o codec) e o `roundtrip` imprime o erro amigável.

## Testes

```bash
cargo test --workspace
```

## Documentação complementar

- [docs/SESSION_FORMAT.md](docs/SESSION_FORMAT.md) — formato exato de sessão (swap Node ↔ Rust sem novo QR).
- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) — arquitetura completa dos crates.
- [docs/API_COMPAT.md](docs/API_COMPAT.md) — paridade de API com o `containerRust`.
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — notas de protocolo.

## Aviso

Uso sob sua responsabilidade. Projeto não oficial, sem afiliação com o WhatsApp.
