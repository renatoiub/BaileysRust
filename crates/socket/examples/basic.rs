//! `basic` — fluxo mínimo completo com a `baileys-socket`.
//!
//! 1. Abre um `Client` num diretório de sessão (SQLite nativo, sem Redis).
//! 2. Conecta e imprime o QR no terminal.
//! 3. Após parear, envia um texto para um JID passado por argumento.
//!
//! Uso:
//! ```bash
//! cargo run -p baileys-socket --example basic -- <session-dir> <jid>
//! # ex.: cargo run -p baileys-socket --example basic -- ./session 5511999999999@s.whatsapp.net
//! ```

use std::sync::Arc;

use baileys_socket::{Client, ClientConfig, ClientEvent, ConnectionUpdate};

fn print_qr(qr: &str) {
    let code = qrcode::QrCode::new(qr).expect("QR inválido");
    let rendered = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(1, 1)
        .build();
    println!("{}", rendered);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Provedor criptográfico do rustls (ring) — obrigatório no Windows/alguns Linux.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let session_dir = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "./basic-session".to_string());
    let target_jid = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "5511999999999@s.whatsapp.net".to_string());

    // Client = SQLite nativo (igual ao useSQLiteAuthState do Node). Sem Redis.
    let client = Arc::new(Client::new(&session_dir, ClientConfig::default())?);

    // Watcher de eventos (QR, conexão, mensagens).
    let mut rx = client.subscribe();
    let (qr_tx, mut qr_rx) = tokio::sync::mpsc::channel::<String>(8);

    let watcher = {
        let client = client.clone();
        tokio::spawn(async move {
            let mut paired = false;
            while let Ok(ev) = rx.recv().await {
                match ev {
                    ClientEvent::Qr(qr) => {
                        let _ = qr_tx.send(qr).await;
                    }
                    ClientEvent::ConnectionUpdate(ConnectionUpdate {
                        connection, qr, ..
                    }) => {
                        tracing::info!(connection, "connection.update");
                        if connection == "open" {
                            paired = true;
                            tracing::info!("pareado! JID = {}", client.me_id());
                            // Envia o texto de exemplo.
                            if let Some(sink) = client.sink().await {
                                if let Err(e) = client
                                    .send_text(&target_jid, "Olá do BaileysRust!", &sink)
                                    .await
                                {
                                    tracing::warn!(error = %e, "falha ao enviar texto");
                                }
                            }
                        }
                        if let Some(q) = qr {
                            let _ = qr_tx.send(q).await;
                        }
                    }
                    ClientEvent::Message { info, .. } => {
                        let text = info
                            .message
                            .and_then(|m| m.extended_text_message)
                            .and_then(|t| t.text)
                            .unwrap_or_default();
                        tracing::info!(text, "mensagem recebida");
                    }
                    _ => {}
                }
            }
            paired
        })
    };

    // Task de conexão (loop de reconnect).
    let conn = tokio::spawn(client.clone().run());

    // Imprime cada QR recebido no terminal.
    while let Some(qr) = qr_rx.recv().await {
        print_qr(&qr);
    }

    let _ = watcher.await;
    let _ = conn.await;
    Ok(())
}
