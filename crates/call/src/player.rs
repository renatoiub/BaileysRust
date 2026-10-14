//! Player de áudio para demonstração do `baileys-call`.
//!
//! Toca PCM (f32) na caixa de som via `cpal` e expõe o roundtrip do codec
//! MLow (`encode` → `decode`) para validar a lib nativa `libopus_mlow`.
//! Se não houver dispositivo de áudio ou a lib nativa, degrada com log.

use crate::audio::AudioEngine;
use crate::mlow::{MlowCodec, MlowOptions};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

/// Player de áudio para o `baileys-call`.
pub struct Player {
    engine: AudioEngine,
    codec: Option<MlowCodec>,
    codec_error: Option<String>,
}

impl Player {
    pub fn new() -> Self {
        let engine = AudioEngine::new(Default::default());
        let (codec, codec_error) = match MlowCodec::new(MlowOptions::default()) {
            Ok(codec) => (Some(codec), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self {
            engine,
            codec,
            codec_error,
        }
    }

    /// `Some(msg)` se a lib nativa não pôde ser carregada.
    pub fn codec_error(&self) -> Option<&str> {
        self.codec_error.as_deref()
    }

    pub fn has_codec(&self) -> bool {
        self.codec.is_some()
    }

    pub fn sample_rate(&self) -> usize {
        self.engine.config().sample_rate
    }

    /// Gera um tom senoidal na engine e o toca.
    pub fn play_tone(&self, frequency: f32, duration_secs: f32, amplitude: f32) {
        self.engine
            .generate_test_tone(frequency, duration_secs, amplitude);
        let mut buffer = Vec::new();
        while !self.engine.is_audio_finished() {
            let chunk = self.engine.next_capture_chunk();
            if chunk.iter().all(|s| *s == 0.0) {
                break;
            }
            buffer.extend_from_slice(&chunk);
        }
        self.play_pcm(&buffer);
    }

    /// Toca PCM f32 mono na saída padrão. Sem dispositivo, só loga.
    pub fn play_pcm(&self, samples: &[f32]) {
        if samples.is_empty() {
            tracing::warn!("play_pcm: sem amostras");
            return;
        }
        let host = cpal::default_host();
        let device = match host.default_output_device() {
            Some(d) => d,
            None => {
                tracing::warn!("play_pcm: sem dispositivo de saída (ignorando playback)");
                return;
            }
        };
        let config = match device.default_output_config() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "play_pcm: sem config de saída");
                return;
            }
        };

        let _ = match config.sample_format() {
            cpal::SampleFormat::F32 => self.play_with_format::<f32>(&device, &config.into(), samples),
            cpal::SampleFormat::I16 => self.play_with_format::<i16>(&device, &config.into(), samples),
            cpal::SampleFormat::U16 => self.play_with_format::<u16>(&device, &config.into(), samples),
            cpal::SampleFormat::I8 => self.play_with_format::<i8>(&device, &config.into(), samples),
            cpal::SampleFormat::I32 => self.play_with_format::<i32>(&device, &config.into(), samples),
            cpal::SampleFormat::I64 => self.play_with_format::<i64>(&device, &config.into(), samples),
            cpal::SampleFormat::U8 => self.play_with_format::<u8>(&device, &config.into(), samples),
            cpal::SampleFormat::U32 => self.play_with_format::<u32>(&device, &config.into(), samples),
            cpal::SampleFormat::U64 => self.play_with_format::<u64>(&device, &config.into(), samples),
            _ => {
                tracing::warn!("play_pcm: formato de saída não suportado");
                return;
            }
        };
    }

    fn play_with_format<T>(&self, device: &cpal::Device, config: &cpal::StreamConfig, samples: &[f32])
    where
        T: cpal::SizedSample + cpal::FromSample<f32>,
    {
        let stream = match device.build_output_stream(
            config,
            {
                let owned: Vec<f32> = samples.to_vec();
                let mut iter = owned.into_iter();
                move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
                    for slot in data.iter_mut() {
                        *slot = T::from_sample(iter.next().unwrap_or(0.0));
                    }
                }
            },
            |err| tracing::warn!(error = %err, "play_pcm: erro no stream"),
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "play_pcm: falha ao abrir stream");
                return;
            }
        };
        if let Err(e) = stream.play() {
            tracing::warn!(error = %e, "play_pcm: falha ao iniciar");
            return;
        }
        // Espera o tempo do áudio + margem antes de encerrar (o stream é
        // descartado ao fim da função).
        let secs = samples.len() as f32 / self.sample_rate() as f32;
        std::thread::sleep(std::time::Duration::from_millis((secs * 1000.0) as u64 + 200));
    }

    /// Roundtrip do codec: PCM → MLow (encode) → PCM (decode).
    pub fn codec_roundtrip(&mut self, samples: &[f32]) -> Result<Vec<f32>, String> {
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| self.codec_error.clone().unwrap_or_else(|| "codec indisponível".into()))?;
        let frame_size = codec.frame_size();
        let mut decoded = Vec::with_capacity(samples.len());
        for chunk in samples.chunks(frame_size) {
            // Opus exige frames completos (960 amostras = 60ms @ 16kHz).
            // O último chunk parcial é completado com silêncio.
            let mut frame = chunk.to_vec();
            if frame.len() < frame_size {
                frame.resize(frame_size, 0.0);
            }
            let encoded = codec
                .encode(&frame)
                .map_err(|e| format!("encode: {e}"))?;
            decoded.extend_from_slice(&codec.decode(Some(&encoded)));
        }
        Ok(decoded)
    }

    /// Stats do codec: (decode_success, decode_errors, plc_frames).
    pub fn codec_stats(&self) -> Option<(u64, u64, u64)> {
        self.codec.as_ref().map(|c| c.get_stats())
    }
}

impl Default for Player {
    fn default() -> Self {
        Self::new()
    }
}
