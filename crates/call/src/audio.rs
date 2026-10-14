//! AudioEngine — captura/playback de áudio PCM (port de `services/call/audio-engine.ts`).

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::AudioEngineConfig;

/// Trait que recebe áudio capturado.
pub trait AudioSender: Send + Sync {
    fn send_captured_audio(&self, data: &[f32]);
}

/// Engine de áudio baseada em buffer circular + captura por tick.
///
/// Em Rust não há `setInterval` — o `run_capture`/`run_playback` são loops
/// tokio que o chamador pode spawnar. Mantém o mesmo comportamento do TS:
/// buffer circular para playback e leitura linear para captura (arquivo ou
/// modo externo com jitter buffer).
pub struct AudioEngine {
    config: AudioEngineConfig,
    state: Mutex<EngineState>,
}

#[derive(Default)]
struct EngineState {
    audio_buffer: Option<Vec<f32>>,
    audio_position: usize,
    audio_finished: bool,
    live_write_pos: usize,
    external_mode: bool,
    ext_started: bool,
    silence_mode: bool,

    circular_buffer: Vec<f32>,
    buffer_write_pos: usize,
    buffer_read_pos: usize,
    buffer_len: usize,

    ext_pre_buffer_size: usize,
    ext_target_buffer: usize,
    ext_high_water: usize,
    ext_skip_count: u64,
}

impl AudioEngine {
    pub fn new(config: AudioEngineConfig) -> Self {
        let ext_pre_buffer_size = (config.sample_rate as f64 * 0.09) as usize;
        let ext_target_buffer = (config.sample_rate as f64 * 0.12) as usize;
        let ext_high_water = (config.sample_rate as f64 * 0.5) as usize;
        Self {
            state: Mutex::new(EngineState {
                circular_buffer: vec![0.0; config.max_buffer_size],
                ext_pre_buffer_size,
                ext_target_buffer,
                ext_high_water,
                ..Default::default()
            }),
            config,
        }
    }

    pub fn config(&self) -> &AudioEngineConfig {
        &self.config
    }

    pub fn set_external_mode(&self, enabled: bool) {
        let mut s = self.state.blocking_lock();
        s.external_mode = enabled;
        s.ext_started = false;
        s.ext_skip_count = 0;
        if enabled {
            let initial_size = self.config.sample_rate * 60;
            s.audio_buffer = Some(vec![0.0; initial_size]);
            s.audio_position = 0;
            s.live_write_pos = 0;
            s.audio_finished = false;
        } else {
            s.audio_buffer = None;
            s.audio_position = 0;
            s.live_write_pos = 0;
        }
    }

    pub fn is_external_mode(&self) -> bool {
        self.state.blocking_lock().external_mode
    }

    pub fn feed_external_audio(&self, data: &[f32]) {
        let mut s = self.state.blocking_lock();
        if s.audio_buffer.is_none() {
            return;
        }

        // Compact: shift unread data to front when read position passes half.
        let mut write_pos = s.live_write_pos;
        let mut read_pos = s.audio_position;
        {
            let buf = s.audio_buffer.as_mut().unwrap();
            if read_pos > buf.len() / 2 {
                let remaining = write_pos.saturating_sub(read_pos);
                if remaining > 0 {
                    buf.copy_within(read_pos..write_pos, 0);
                }
                write_pos = remaining;
                read_pos = 0;
            }

            // Grow buffer if needed.
            if write_pos + data.len() > buf.len() {
                let new_size = (buf.len() * 2).max(write_pos + data.len());
                buf.resize(new_size, 0.0);
            }

            buf[write_pos..write_pos + data.len()].copy_from_slice(data);
        }
        s.live_write_pos = write_pos + data.len();
        s.audio_position = read_pos;
    }

    pub fn is_audio_finished(&self) -> bool {
        self.state.blocking_lock().audio_finished
    }

    /// Carrega PCM f32 (já decodificado pelo chamador via FFmpeg).
    pub fn load_audio(&self, samples: Vec<f32>) {
        let mut s = self.state.blocking_lock();
        s.audio_buffer = Some(samples);
        s.audio_position = 0;
        s.audio_finished = false;
    }

    pub fn has_audio(&self) -> bool {
        let s = self.state.blocking_lock();
        matches!(&s.audio_buffer, Some(b) if !b.is_empty())
    }

    pub fn generate_test_tone(&self, frequency: f32, duration_secs: f32, amplitude: f32) {
        let samples = (self.config.sample_rate as f32 * duration_secs) as usize;
        let mut buffer = Vec::with_capacity(samples);
        let sr = self.config.sample_rate as f32;
        for i in 0..samples {
            let t = i as f32 / sr;
            buffer.push((std::f32::consts::TAU * frequency * t).sin() * amplitude);
        }
        let mut s = self.state.blocking_lock();
        s.audio_buffer = Some(buffer);
        s.audio_position = 0;
        s.audio_finished = false;
    }

    pub fn set_silence_mode(&self, enabled: bool) {
        self.state.blocking_lock().silence_mode = enabled;
    }

    pub fn is_silence_mode(&self) -> bool {
        self.state.blocking_lock().silence_mode
    }

    /// Escreve dados de playback no buffer circular.
    pub fn on_playback_data(&self, audio_data: &[f32]) {
        let mut s = self.state.blocking_lock();
        let max = self.config.max_buffer_size;
        for &sample in audio_data {
            if s.buffer_len >= max {
                break;
            }
            let pos = s.buffer_write_pos;
            s.circular_buffer[pos] = sample;
            s.buffer_write_pos = (pos + 1) % max;
            s.buffer_len += 1;
        }
    }

    /// Lê do buffer circular para reprodução.
    pub fn read_playback(&self, count: usize) -> Vec<f32> {
        let mut s = self.state.blocking_lock();
        let max = self.config.max_buffer_size;
        let mut out = vec![0.0; count];
        for slot in out.iter_mut() {
            if s.buffer_len > 0 {
                let pos = s.buffer_read_pos;
                *slot = s.circular_buffer[pos];
                s.buffer_read_pos = (pos + 1) % max;
                s.buffer_len -= 1;
            }
        }
        out
    }

    /// Próximo chunk de captura (arquivo ou modo externo).
    pub fn next_capture_chunk(&self) -> Vec<f32> {
        let chunk_size = self.config.capture_chunk_size;
        let silence = vec![0.0; chunk_size];

        // Resolve o range de leitura (mutando posições) sem segurar ref do slice.
        let mut s = self.state.blocking_lock();

        let has_buffer = s.audio_buffer.is_some();
        if !has_buffer {
            return silence;
        }
        let buf_len = s.audio_buffer.as_ref().unwrap().len();
        if buf_len == 0 {
            return silence;
        }

        let end_pos = if s.external_mode {
            s.live_write_pos
        } else {
            buf_len
        };

        if end_pos == 0 || (s.audio_finished && !s.external_mode) {
            return silence;
        }

        if s.external_mode {
            let available = end_pos.saturating_sub(s.audio_position);
            if !s.ext_started {
                if available < s.ext_pre_buffer_size {
                    return silence;
                }
                s.ext_started = true;
            }
            if available > s.ext_high_water {
                let skip_to = end_pos.saturating_sub(s.ext_target_buffer);
                s.audio_position = skip_to;
                s.ext_skip_count += 1;
            }
            if s.audio_position >= end_pos {
                return silence;
            }
        }

        let read_pos = s.audio_position;
        let available = end_pos.saturating_sub(read_pos);
        let take = available.min(chunk_size);

        // Copia o chunk inteiro (com possíveis zeros) de uma vez.
        let mut chunk = vec![0.0; chunk_size];
        if let Some(buf) = s.audio_buffer.as_ref() {
            chunk[..take].copy_from_slice(&buf[read_pos..read_pos + take]);
        }
        s.audio_position += take;

        if !s.external_mode && s.audio_position >= end_pos && !s.audio_finished {
            s.audio_finished = true;
        }
        chunk
    }

    /// Tick de captura: entrega o chunk ao `AudioSender`.
    pub fn capture_tick(&self, sender: &dyn AudioSender) {
        let chunk = self.next_capture_chunk();
        sender.send_captured_audio(&chunk);
    }

    pub fn reset_playback_buffer(&self) {
        let mut s = self.state.blocking_lock();
        s.buffer_write_pos = 0;
        s.buffer_read_pos = 0;
        s.buffer_len = 0;
    }

    pub fn stats(&self) -> (u64, usize) {
        let s = self.state.blocking_lock();
        (s.ext_skip_count, s.buffer_len)
    }
}

/// Tipo de sender compartilhado.
pub type SharedAudioSender = Arc<dyn AudioSender>;

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct NullSender;
    impl AudioSender for NullSender {
        fn send_captured_audio(&self, _data: &[f32]) {}
    }

    #[test]
    fn file_capture_reads_sequential() {
        let engine = AudioEngine::new(Default::default());
        let samples: Vec<f32> = (0..1600).map(|i| i as f32 / 16000.0).collect();
        engine.load_audio(samples);

        let c1 = engine.next_capture_chunk();
        let c2 = engine.next_capture_chunk();
        assert_eq!(c1.len(), 320);
        assert_eq!(c2.len(), 320);
        // Não deve ser silêncio: primeiro chunk tem o início.
        assert!(c1.iter().any(|s| *s != 0.0));
    }

    #[test]
    fn playback_circular_buffer() {
        let engine = AudioEngine::new(Default::default());
        engine.on_playback_data(&[0.1, 0.2, 0.3]);
        let out = engine.read_playback(2);
        assert_eq!(out, vec![0.1, 0.2]);
        let out2 = engine.read_playback(2);
        assert_eq!(out2[0], 0.3);
        assert_eq!(out2[1], 0.0);
    }

    #[test]
    fn external_mode_jitter_buffer() {
        let engine = AudioEngine::new(Default::default());
        engine.set_external_mode(true);
        // Pre-buffer ~1440 samples antes de começar.
        engine.feed_external_audio(&vec![0.5; 500]);
        let c = engine.next_capture_chunk();
        assert!(c.iter().all(|s| *s == 0.0));
        engine.feed_external_audio(&vec![0.5; 2000]);
        let c = engine.next_capture_chunk();
        assert!(c.iter().any(|s| *s != 0.0));
    }
}
