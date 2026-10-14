//! FFI para `libopus_mlow` (port de `services/call/mlow-codec.ts`).
//!
//! O MLow é o codec padrão do WhatsApp (PT 120). A biblioteca nativa segue a
//! API do Opus com extensões proprietárias (`SET_USING_SMPL`), e precisa ser
//! carregada dinamicamente (`MLOW_LIB_PATH` ou `native/` ao lado do binário).

use std::ffi::{c_char, c_int, c_void, CStr};
use std::path::PathBuf;

const MLOW_SAMPLE_RATE: i32 = 16000;
const MLOW_CHANNELS: c_int = 1;
const OPUS_APPLICATION_VOIP: c_int = 2048;

const CTL_SET_BITRATE: c_int = 4002;
const CTL_SET_COMPLEXITY: c_int = 4010;
const CTL_SET_SIGNAL: c_int = 4024;
const CTL_SET_INBAND_FEC: c_int = 4012;
#[allow(dead_code)]
const CTL_SET_PACKET_LOSS_PERC: c_int = 4014;
const CTL_SET_DTX: c_int = 4016;
const CTL_SET_USING_SMPL: c_int = 4050;
const CTL_SIGNAL_VOICE: c_int = 3001;

/// Erros do codec MLow.
#[derive(Debug, thiserror::Error)]
pub enum MlowError {
    #[error("libopus_mlow não encontrada (tente MLOW_LIB_PATH)")]
    LibNotFound,
    #[error("falha ao carregar libopus_mlow: {0}")]
    Load(String),
    #[error("symbol não encontrado: {0}")]
    MissingSymbol(&'static str),
    #[error("opus_encoder_create falhou")]
    EncoderCreate,
    #[error("opus_decoder_create falhou")]
    DecoderCreate,
    #[error("encode falhou: {0}")]
    Encode(String),
    #[error("decode falhou: {0}")]
    Decode(String),
}

// Assinaturas da libopus_mlow. As `*_ctl` são variadic em C, mas quando
// chamadas com um único argumento `int`, a ABI (SysV/Windows x64/ARM64)
// passa o valor no mesmo registrador de um argumento fixo — declaramos como
// `(st, request, val)`.
#[allow(non_snake_case)]
struct MlowApi {
    global_create: libloading::Symbol<'static, unsafe extern "C" fn()>,
    decoder_create: libloading::Symbol<
        'static,
        unsafe extern "C" fn(i32, c_int, *mut u8) -> *mut c_void,
    >,
    decoder_ctl:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int>,
    decode: libloading::Symbol<
        'static,
        unsafe extern "C" fn(*mut c_void, *const u8, i32, *mut i16, c_int, c_int) -> c_int,
    >,
    decoder_destroy: libloading::Symbol<'static, unsafe extern "C" fn(*mut c_void)>,
    encoder_create: libloading::Symbol<
        'static,
        unsafe extern "C" fn(i32, c_int, c_int, *mut u8) -> *mut c_void,
    >,
    encoder_ctl:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int>,
    encode: libloading::Symbol<
        'static,
        unsafe extern "C" fn(*mut c_void, *const i16, c_int, *mut u8, i32) -> c_int,
    >,
    encoder_destroy: libloading::Symbol<'static, unsafe extern "C" fn(*mut c_void)>,
    strerror: libloading::Symbol<'static, unsafe extern "C" fn(c_int) -> *const c_char>,
}

/// Localiza a lib nativa (env `MLOW_LIB_PATH` ou `native/`).
pub fn resolve_lib_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("MLOW_LIB_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
    }

    let names: &[&str] = if cfg!(target_os = "macos") {
        &["libopus_mlow.dylib"]
    } else if cfg!(target_os = "windows") {
        if cfg!(target_arch = "aarch64") {
            &["opus_mlow.arm64.dll", "opus_mlow.dll", "libopus_mlow.dll"]
        } else {
            &["opus_mlow.dll", "libopus_mlow.dll"]
        }
    } else if cfg!(target_arch = "aarch64") {
        &["libopus_mlow.arm64.so", "libopus_mlow.so"]
    } else {
        &["libopus_mlow.so", "libopus_mlow.so.0", "libopus_mlow.so.0.0.0"]
    };

    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let cwd = std::env::current_dir().ok()?;

    let mut dirs: Vec<PathBuf> = vec![
        exe_dir.join("native"),
        exe_dir.join("..").join("native"),
        exe_dir.join("services").join("call").join("native"),
        cwd.join("native"),
        cwd.join("src").join("services").join("call").join("native"),
        cwd.join("api").join("services").join("call").join("native"),
    ];
    // container: crates/call/native (fonte) e containerRust/native.
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        dirs.push(PathBuf::from(&manifest).join("native"));
    }
    dirs.push(cwd.join("container").join("src").join("services").join("call").join("native"));
    dirs.push(cwd.join("container").join("api").join("services").join("call").join("native"));

    for dir in dirs {
        for name in names {
            let p = dir.join(name);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Carrega a lib e resolve os símbolos (uma vez por processo).
fn load_api() -> Result<&'static MlowApi, MlowError> {
    use std::sync::OnceLock;
    static API: OnceLock<Result<MlowApi, String>> = OnceLock::new();

    let res = API.get_or_init(|| {
        let path = resolve_lib_path().ok_or_else(|| "lib not found".to_string())?;
        // SAFETY: libloading requer o caminho permanecer válido; `Library` o mantém.
        let lib = unsafe { libloading::Library::new(&path) }.map_err(|e| e.to_string())?;

        // `lib` precisa viver tanto quanto os símbolos — Box leak é a forma
        // simples de dar 'static a ambos (o processo vive até o fim do uso).
        let lib = Box::leak(Box::new(lib));

        macro_rules! sym {
            ($name:expr, $ty:ty) => {
                unsafe { lib.get::<$ty>($name.as_bytes()) }
                    .map_err(|e| format!("{}: {e}", $name))?
            };
        }

        let api = MlowApi {
            global_create: sym!("opus_global_create", unsafe extern "C" fn()),
            decoder_create: sym!(
                "opus_decoder_create",
                unsafe extern "C" fn(i32, c_int, *mut u8) -> *mut c_void
            ),
            decoder_ctl: sym!(
                "opus_decoder_ctl",
                unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int
            ),
            decode: sym!(
                "opus_decode",
                unsafe extern "C" fn(*mut c_void, *const u8, i32, *mut i16, c_int, c_int) -> c_int
            ),
            decoder_destroy: sym!(
                "opus_decoder_destroy",
                unsafe extern "C" fn(*mut c_void)
            ),
            encoder_create: sym!(
                "opus_encoder_create",
                unsafe extern "C" fn(i32, c_int, c_int, *mut u8) -> *mut c_void
            ),
            encoder_ctl: sym!(
                "opus_encoder_ctl",
                unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int
            ),
            encode: sym!(
                "opus_encode",
                unsafe extern "C" fn(*mut c_void, *const i16, c_int, *mut u8, i32) -> c_int
            ),
            encoder_destroy: sym!(
                "opus_encoder_destroy",
                unsafe extern "C" fn(*mut c_void)
            ),
            strerror: sym!("opus_strerror", unsafe extern "C" fn(c_int) -> *const c_char),
        };
        Ok(api)
    });

    match res {
        Ok(api) => Ok(api),
        Err(e) => Err(MlowError::Load(e.clone())),
    }
}

/// Codec MLow — encoder + decoder (in-process).
pub struct MlowCodec {
    encoder: *mut c_void,
    decoder: *mut c_void,
    frame_size: usize,
    max_out: usize,
    decode_errors: u64,
    decode_success: u64,
    plc_frames: u64,
    use_smpl: bool,
}

impl MlowCodec {
    pub fn new(opts: MlowOptions) -> Result<Self, MlowError> {
        let api = load_api()?;
        // Inicialização global (idempotente no nativo, mas chamamos uma vez).
        unsafe { (api.global_create)() };

        let mut err = [0u8; 4];
        let decoder = unsafe {
            (api.decoder_create)(MLOW_SAMPLE_RATE, MLOW_CHANNELS, err.as_mut_ptr())
        };
        if decoder.is_null() {
            return Err(MlowError::DecoderCreate);
        }

        let encoder = unsafe {
            (api.encoder_create)(
                MLOW_SAMPLE_RATE,
                MLOW_CHANNELS,
                OPUS_APPLICATION_VOIP,
                err.as_mut_ptr(),
            )
        };
        if encoder.is_null() {
            unsafe { (api.decoder_destroy)(decoder) };
            return Err(MlowError::EncoderCreate);
        }

        let use_smpl = opts.smpl;
        let codec = Self {
            encoder,
            decoder,
            frame_size: 960,
            max_out: 5760,
            decode_errors: 0,
            decode_success: 0,
            plc_frames: 0,
            use_smpl,
        };

        if codec.use_smpl {
            unsafe {
                (api.decoder_ctl)(codec.decoder, CTL_SET_USING_SMPL, 1);
                (api.encoder_ctl)(codec.encoder, CTL_SET_USING_SMPL, 1);
            }
        }
        unsafe {
            (api.encoder_ctl)(codec.encoder, CTL_SET_BITRATE, opts.bitrate.unwrap_or(6000));
            (api.encoder_ctl)(
                codec.encoder,
                CTL_SET_COMPLEXITY,
                opts.complexity.unwrap_or(5),
            );
            (api.encoder_ctl)(codec.encoder, CTL_SET_SIGNAL, CTL_SIGNAL_VOICE);
            (api.encoder_ctl)(
                codec.encoder,
                CTL_SET_INBAND_FEC,
                if opts.fec { 1 } else { 0 },
            );
            (api.encoder_ctl)(codec.encoder, CTL_SET_DTX, 1);
        }

        Ok(codec)
    }

    /// PCM (f32, [-1,1]) → frame MLow.
    pub fn encode(&self, float32_audio: &[f32]) -> Result<Vec<u8>, MlowError> {
        let api = load_api()?;
        let mut pcm: Vec<i16> = Vec::with_capacity(float32_audio.len());
        for &s in float32_audio {
            let s = s.clamp(-1.0, 1.0);
            pcm.push((s * 32767.0).round() as i16);
        }

        let mut out = vec![0u8; 4000];
        let n = unsafe {
            (api.encode)(
                self.encoder,
                pcm.as_ptr(),
                pcm.len() as c_int,
                out.as_mut_ptr(),
                out.len() as i32,
            )
        };
        if n < 0 {
            return Err(MlowError::Encode(self.strerror(n)));
        }
        out.truncate(n as usize);
        Ok(out)
    }

    /// Frame MLow → PCM (f32). `None` = packet-loss concealment.
    pub fn decode(&mut self, mlow_frame: Option<&[u8]>) -> Vec<f32> {
        let api = match load_api() {
            Ok(a) => a,
            Err(_) => {
                self.decode_errors += 1;
                return vec![0.0f32; self.frame_size];
            }
        };

        let mut out = vec![0i16; self.max_out];
        let samples = match mlow_frame {
            None => {
                self.plc_frames += 1;
                unsafe {
                    (api.decode)(
                        self.decoder,
                        std::ptr::null(),
                        0,
                        out.as_mut_ptr(),
                        self.frame_size as c_int,
                        0,
                    )
                }
            }
            Some(frame) => {
                let n = unsafe {
                    (api.decode)(
                        self.decoder,
                        frame.as_ptr(),
                        frame.len() as i32,
                        out.as_mut_ptr(),
                        self.max_out as c_int,
                        0,
                    )
                };
                if n < 0 {
                    self.decode_errors += 1;
                    return vec![0.0f32; self.frame_size];
                }
                self.decode_success += 1;
                n
            }
        };

        if samples <= 0 {
            return vec![0.0f32; self.frame_size];
        }
        out.truncate(samples as usize);
        out.iter().map(|&s| s as f32 / 32768.0).collect()
    }

    fn strerror(&self, code: c_int) -> String {
        let api = match load_api() {
            Ok(a) => a,
            Err(_) => return format!("opus error {code}"),
        };
        unsafe {
            let ptr = (api.strerror)(code);
            if ptr.is_null() {
                format!("opus error {code}")
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }

    pub fn get_stats(&self) -> (u64, u64, u64) {
        (self.decode_success, self.decode_errors, self.plc_frames)
    }

    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    pub fn frame_duration_ms(&self) -> u64 {
        (self.frame_size as u64 * 1000) / MLOW_SAMPLE_RATE as u64
    }

    pub fn sample_rate(&self) -> i32 {
        MLOW_SAMPLE_RATE
    }

    /// Recria encoder/decoder (após erro nativo).
    pub fn reset(&mut self) -> Result<(), MlowError> {
        let fresh = MlowCodec::new(MlowOptions {
            smpl: self.use_smpl,
            ..Default::default()
        })?;
        *self = fresh;
        Ok(())
    }
}

impl Drop for MlowCodec {
    fn drop(&mut self) {
        if let Ok(api) = load_api() {
            unsafe {
                (api.decoder_destroy)(self.decoder);
                (api.encoder_destroy)(self.encoder);
            }
        }
    }
}

/// Opções do codec MLow.
#[derive(Debug, Clone)]
pub struct MlowOptions {
    pub bitrate: Option<c_int>,
    pub complexity: Option<c_int>,
    pub fec: bool,
    pub smpl: bool,
}

impl Default for MlowOptions {
    fn default() -> Self {
        Self {
            bitrate: Some(6000),
            complexity: Some(5),
            fec: false,
            smpl: true,
        }
    }
}

// MlowCodec é enviável entre threads (ponteiros opacos do nativo).
unsafe impl Send for MlowCodec {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_does_not_panic() {
        // Sem lib no ambiente, retorna None (ou Some se existir).
        let _ = resolve_lib_path();
    }

    #[test]
    fn pcm_clamp_in_encode_is_sound_when_lib_absent() {
        // Se a lib não existe, `encode` falha — não pode panificar.
        let codec = MlowCodec::new(Default::default());
        match codec {
            Ok(c) => {
                let _ = c.encode(&[0.0f32; 320]);
            }
            Err(_) => {
                // esperado em ambientes sem a lib nativa
            }
        }
    }
}
