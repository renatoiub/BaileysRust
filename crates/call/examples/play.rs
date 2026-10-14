//! Player de exemplo do `baileys-call`.
//!
//! Demonstra o codec MLow (`libopus_mlow`) e a engine de áudio tocando um tom
//! na caixa de som.
//!
//! Uso:
//!   cargo run -p baileys-call --example play -- tone 440 2
//!   cargo run -p baileys-call --example play -- roundtrip 440 2
//!
//! `tone` toca um seno direto; `roundtrip` passa o tom por
//! `encode`/`decode` do MLow e toca o resultado (validando a lib nativa).
//! Sem `libopus_mlow`, o `roundtrip` imprime o erro amigável e sai com 0.

use baileys_call::player::Player;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("tone");
    let freq: f32 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(440.0);
    let secs: f32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2.0);

    let mut player = Player::new();

    match mode {
        "tone" => {
            println!("tocando tom de {freq} Hz por {secs}s (sample_rate {})", player.sample_rate());
            player.play_tone(freq, secs, 0.25);
        }
        "roundtrip" => {
            if let Some(err) = player.codec_error() {
                println!("libopus_mlow indisponível: {err}");
                println!("coloque a lib em `native/` ao lado do binário ou defina MLOW_LIB_PATH");
                return;
            }

            let samples: Vec<f32> = (0..(player.sample_rate() as f32 * secs) as usize)
                .map(|i| {
                    let t = i as f32 / player.sample_rate() as f32;
                    (std::f32::consts::TAU * freq * t).sin() * 0.25
                })
                .collect();

            println!(
                "roundtrip: {} amostras → MLow encode/decode → playback",
                samples.len()
            );
            match player.codec_roundtrip(&samples) {
                Ok(decoded) => {
                    if let Some(stats) = player.codec_stats() {
                        println!(
                            "codec stats: decode_success={} decode_errors={} plc_frames={}",
                            stats.0, stats.1, stats.2
                        );
                    }
                    player.play_pcm(&decoded);
                }
                Err(e) => {
                    println!("roundtrip falhou: {e}");
                }
            }
        }
        other => {
            eprintln!("modo desconhecido: {other}");
            eprintln!("uso: play [tone|roundtrip] [freq] [secs]");
            std::process::exit(2);
        }
    }
}
