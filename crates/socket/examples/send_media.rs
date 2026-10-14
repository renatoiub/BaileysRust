//! `send_media` — envia imagem, vídeo, áudio e documento com a `baileys-socket`.
//!
//! Supõe que a sessão já esteja pareada (rode `basic` antes, ou use uma
//! sessão existente). Lê os arquivos do disco e usa os métodos de
//! conveniência do `Client` (upload + conversão FFmpeg + E2E).
//!
//! Uso:
//! ```bash
//! cargo run -p baileys-socket --example send_media -- \
//!   <session-dir> <jid> image  <arquivo.png>
//! cargo run -p baileys-socket --example send_media -- \
//!   <session-dir> <jid> video  <arquivo.mp4>
//! cargo run -p baileys-socket --example send_media -- \
//!   <session-dir> <jid> audio  <arquivo.wav> [ptt:true|false]
//! cargo run -p baileys-socket --example send_media -- \
//!   <session-dir> <jid> doc    <arquivo.pdf>
//! ```

use std::sync::Arc;

use baileys_socket::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("uso: send_media <session-dir> <jid> <image|video|audio|doc> <arquivo> [ptt]");
        std::process::exit(2);
    }

    let session_dir = &args[1];
    let jid = &args[2];
    let kind = args[3].as_str();
    let path = &args[4];
    let ptt = args
        .get(5)
        .map(|s| s == "true")
        .unwrap_or(false);

    let bytes = std::fs::read(path)?;
    let client = Arc::new(Client::new(session_dir, ClientConfig::default())?);

    // Reconecta (reusa creds do SQLite) e aguarda o socket abrir.
    let conn_client = client.clone();
    let conn = tokio::spawn(async move { conn_client.clone().run().await });

    let sink = loop {
        if let Some(s) = client.sink().await {
            break s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };

    // Adiciona um pequeno delay após o socket abrir (upload de pre-keys etc).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let result = match kind {
        "image" => {
            let mimetype = mime_for(path, "image/png");
            client.send_image(jid, &bytes, &mimetype, Some("BaileysRust"), &sink).await?
        }
        "video" => {
            let mimetype = mime_for(path, "video/mp4");
            client.send_video(jid, &bytes, &mimetype, Some("BaileysRust"), &sink).await?
        }
        "audio" => client.send_audio(jid, &bytes, ptt, &sink).await?,
        "doc" => {
            let filename = std::path::Path::new(path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("document");
            let mimetype = mime_for(path, "application/octet-stream");
            client.send_document(jid, &bytes, &mimetype, filename, None, &sink).await?
        }
        other => {
            eprintln!("tipo desconhecido: {other}");
            std::process::exit(2);
        }
    };

    println!("enviado! message_id = {}", result.message_id);

    conn.abort();
    Ok(())
}

/// Mime básico pela extensão do arquivo (fallback para o valor padrão).
fn mime_for(path: &str, default: &str) -> String {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_lowercase();
    match ext.as_str() {
        "png" => "image/png".to_string(),
        "jpg" | "jpeg" => "image/jpeg".to_string(),
        "webp" => "image/webp".to_string(),
        "gif" => "image/gif".to_string(),
        "mp4" => "video/mp4".to_string(),
        "mov" => "video/quicktime".to_string(),
        "mp3" => "audio/mpeg".to_string(),
        "ogg" | "oga" => "audio/ogg".to_string(),
        "wav" => "audio/x-wav".to_string(),
        "pdf" => "application/pdf".to_string(),
        "zip" => "application/zip".to_string(),
        _ => default.to_string(),
    }
}
