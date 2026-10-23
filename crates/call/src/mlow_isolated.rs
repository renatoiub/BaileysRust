//! Decode MLow em processo filho (port de `MLowIsolatedDecoder` +
//! `mlow-decode-worker.ts`).
//!
//! Se o SILK nativo der assert/abort, só o worker morre — o container segue.
//! O worker é o próprio executável chamado com [`WORKER_ARG`]; o binário
//! precisa chamar [`run_decode_worker_if_requested`] no início do `main`.
//!
//! Protocolo (stdin/stdout, little-endian):
//! - pedido: `u32` tamanho do frame (`u32::MAX` = PLC) + bytes do frame;
//! - resposta: `u32` nº de amostras + amostras `f32`.

use std::io::{Read, Write};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::mlow::{MlowCodec, MlowOptions};

/// Argumento que coloca o executável em modo worker de decode.
pub const WORKER_ARG: &str = "--mlow-decode-worker";

const FRAME_SIZE: usize = 960;
const DECODE_TIMEOUT: Duration = Duration::from_millis(120);
const COOL_DOWN: Duration = Duration::from_millis(300);
const PLC_MARKER: u32 = u32::MAX;

/// Se o processo foi iniciado como worker, roda o laço de decode e sai.
pub fn run_decode_worker_if_requested() {
    if std::env::args().nth(1).as_deref() == Some(WORKER_ARG) {
        let code = match run_decode_worker() {
            Ok(()) => 0,
            Err(_) => 1,
        };
        std::process::exit(code);
    }
}

fn run_decode_worker() -> std::io::Result<()> {
    let mut codec = MlowCodec::new(MlowOptions::default())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    loop {
        let mut len_buf = [0u8; 4];
        if input.read_exact(&mut len_buf).is_err() {
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf);
        let pcm = if len == PLC_MARKER {
            codec.decode(None)
        } else {
            let mut frame = vec![0u8; len as usize];
            input.read_exact(&mut frame)?;
            codec.decode(Some(&frame))
        };

        let mut out = Vec::with_capacity(4 + pcm.len() * 4);
        out.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
        for s in &pcm {
            out.extend_from_slice(&s.to_le_bytes());
        }
        output.write_all(&out)?;
        output.flush()?;
    }
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

/// Decoder MLow isolado num processo filho (respawn automático).
pub struct MlowIsolatedDecoder {
    worker: Option<Worker>,
    destroyed: bool,
    cool_until: Option<Instant>,
    decode_success: u64,
    decode_errors: u64,
    plc_frames: u64,
}

impl Default for MlowIsolatedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl MlowIsolatedDecoder {
    pub fn new() -> Self {
        let mut dec = Self {
            worker: None,
            destroyed: false,
            cool_until: None,
            decode_success: 0,
            decode_errors: 0,
            plc_frames: 0,
        };
        dec.ensure_worker();
        dec
    }

    fn ensure_worker(&mut self) {
        if self.destroyed || self.worker.is_some() {
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[MLowIsolated] current_exe falhou: {e}");
                return;
            }
        };
        let spawned = Command::new(exe)
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn();
        match spawned {
            Ok(mut child) => {
                let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                    tracing::error!("[MLowIsolated] worker sem stdio");
                    return;
                };
                self.worker = Some(Worker { child, stdin, stdout });
            }
            Err(e) => tracing::error!("[MLowIsolated] spawn falhou: {e}"),
        }
    }

    /// Worker morreu/travou: descarta, esfria 300 ms e sobe outro.
    fn drop_worker(&mut self, reason: &str) {
        if let Some(mut w) = self.worker.take() {
            let _ = w.child.start_kill();
        }
        tracing::warn!("[MLowIsolated] worker reiniciado ({reason})");
        self.cool_until = Some(Instant::now() + COOL_DOWN);
        self.ensure_worker();
    }

    /// Frame MLow → PCM f32. `None` = packet-loss concealment.
    pub async fn decode(&mut self, frame: Option<&[u8]>) -> Vec<f32> {
        if self.destroyed {
            return vec![0.0; FRAME_SIZE];
        }
        if let Some(until) = self.cool_until {
            if Instant::now() < until {
                self.plc_frames += 1;
                return vec![0.0; FRAME_SIZE];
            }
            self.cool_until = None;
        }
        self.ensure_worker();
        let Some(worker) = self.worker.as_mut() else {
            self.decode_errors += 1;
            return vec![0.0; FRAME_SIZE];
        };

        let mut req = Vec::with_capacity(4 + frame.map(|f| f.len()).unwrap_or(0));
        match frame {
            Some(f) => {
                req.extend_from_slice(&(f.len() as u32).to_le_bytes());
                req.extend_from_slice(f);
            }
            None => req.extend_from_slice(&PLC_MARKER.to_le_bytes()),
        }

        let result = tokio::time::timeout(DECODE_TIMEOUT, async {
            worker.stdin.write_all(&req).await?;
            worker.stdin.flush().await?;
            let mut len_buf = [0u8; 4];
            worker.stdout.read_exact(&mut len_buf).await?;
            let samples = u32::from_le_bytes(len_buf) as usize;
            if samples > 48_000 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "samples"));
            }
            let mut raw = vec![0u8; samples * 4];
            worker.stdout.read_exact(&mut raw).await?;
            Ok::<Vec<f32>, std::io::Error>(
                raw.chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect(),
            )
        })
        .await;

        match result {
            Ok(Ok(pcm)) => {
                self.decode_success += 1;
                pcm
            }
            Ok(Err(e)) => {
                self.decode_errors += 1;
                self.drop_worker(&format!("io: {e}"));
                vec![0.0; FRAME_SIZE]
            }
            Err(_) => {
                self.decode_errors += 1;
                self.drop_worker("timeout");
                vec![0.0; FRAME_SIZE]
            }
        }
    }

    /// `(success, errors, plc)`.
    pub fn stats(&self) -> (u64, u64, u64) {
        (self.decode_success, self.decode_errors, self.plc_frames)
    }

    pub fn destroy(&mut self) {
        self.destroyed = true;
        if let Some(mut w) = self.worker.take() {
            let _ = w.child.start_kill();
        }
    }
}

impl Drop for MlowIsolatedDecoder {
    fn drop(&mut self) {
        self.destroy();
    }
}
