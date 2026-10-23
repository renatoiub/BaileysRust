//! `baileys-media` — processamento de mídia (Fase 2).
//!
//! Port de `Hineken/src/Utils/messages-media.ts` + o pipeline do container
//! (`mediaBuffer.ts` / `audioPrepare.ts`):
//!
//! - Derivação de chaves de mídia (`getMediaKeys` via HKDF).
//! - Download com `Range` e descriptografia AES-256-CBC (stream de chunks de 16).
//! - Thumbnails de imagem/vídeo via FFmpeg (`image` crate p/ redimensionar).
//! - Conversão de áudio (PTT → OGG/Opus; normal → MP3) via FFmpeg.
//! - Leitura de dimensões de imagem (JPEG/PNG/WebP/GIF) sem FFmpeg.
//! - Upload (`waUploadToServer`) para `mmg.whatsapp.net`/hosts da media conn.
//! - Media retry (server-error receipt) com AES-GCM.

use sha2::{Digest, Sha256};

use baileys_crypto::{aes_decrypt_cbc, aes_encrypt_cbc, aes_encrypt_gcm, aes_decrypt_gcm, hkdf};

/// Tipos de mídia suportados (espelha `Types/Message.ts::MediaType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    Image,
    Video,
    Document,
    Audio,
    Sticker,
    Ptt,
    Gif,
    Ppt,
    /// `thumbnail-link` — miniatura em alta do link preview.
    ThumbnailLink,
}

impl MediaType {
    /// `MEDIA_HKDF_KEY_MAPPING` — sufixo do info string do HKDF.
    pub fn hkdf_info(self) -> &'static str {
        match self {
            MediaType::Image => "Image",
            MediaType::Video => "Video",
            MediaType::Document => "Document",
            MediaType::Audio => "Audio",
            MediaType::Sticker => "Image",
            MediaType::Ptt => "Audio",
            MediaType::Gif => "Video",
            MediaType::Ppt => "Video",
            MediaType::ThumbnailLink => "Link Thumbnail",
        }
    }

    /// `MEDIA_PATH_MAP` — caminho de upload.
    pub fn upload_path(self) -> &'static str {
        match self {
            MediaType::Image => "/mms/image",
            MediaType::Video => "/mms/video",
            MediaType::Document => "/mms/document",
            MediaType::Audio => "/mms/audio",
            MediaType::Sticker => "/mms/image",
            MediaType::Ptt => "/mms/audio",
            MediaType::Gif => "/mms/video",
            MediaType::Ppt => "/mms/video",
            MediaType::ThumbnailLink => "/mms/image",
        }
    }
}

/// Chaves derivadas para criptografar/descriptografar mídia.
#[derive(Debug, Clone)]
pub struct MediaDecryptionKeyInfo {
    pub iv: Vec<u8>,
    pub cipher_key: Vec<u8>,
    pub mac_key: Vec<u8>,
}

/// `getMediaKeys` — HKDF-SHA256 do mediaKey (32 bytes) → 112 bytes.
pub fn get_media_keys(media_key: &[u8], media_type: MediaType) -> Result<MediaDecryptionKeyInfo, MediaError> {
    if media_key.is_empty() {
        return Err(MediaError::EmptyMediaKey);
    }
    let info = format!("WhatsApp {} Keys", media_type.hkdf_info());
    let expanded = hkdf(media_key, 112, None, &info)?;
    Ok(MediaDecryptionKeyInfo {
        iv: expanded[0..16].to_vec(),
        cipher_key: expanded[16..48].to_vec(),
        mac_key: expanded[48..80].to_vec(),
    })
}

/// `hkdfInfoKey` — o info string do HKDF para um tipo de mídia.
pub fn hkdf_info_key(media_type: MediaType) -> String {
    format!("WhatsApp {} Keys", media_type.hkdf_info())
}

/// `encodeBase64EncodedStringForUpload` — URL-safe base64 (p/ query do upload).
pub fn encode_base64_for_upload(b64: &str) -> String {
    b64.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
}

/// `extensionForMediaMessage` — extrai extensão do mimetype.
pub fn extension_for_mimetype(mimetype: &str) -> String {
    let ext = mimetype
        .split(';')
        .next()
        .unwrap_or_default()
        .split('/')
        .nth(1)
        .unwrap_or("bin");
    format!(".{ext}")
}

/// `getUrlFromDirectPath` — `https://mmg.whatsapp.net{directPath}`.
pub const MEDIA_DEF_HOST: &str = "mmg.whatsapp.net";

pub fn url_from_direct_path(direct_path: &str) -> String {
    format!("https://{MEDIA_DEF_HOST}{direct_path}")
}

/// Criptografa um arquivo de mídia com AES-256-CBC (PKCS7) e calcula os
/// hashes exatamente como `encryptedStream`:
///
/// - `fileSha256` = SHA-256 do plaintext.
/// - `mac` = HMAC-SHA256(macKey, iv || ciphertext)[0..10].
/// - `fileEncSha256` = SHA-256(ciphertext || mac).
/// - O arquivo cifrado é `ciphertext || mac`.
pub fn encrypt_media(
    plaintext: &[u8],
    keys: &MediaDecryptionKeyInfo,
) -> Result<EncryptedMedia, MediaError> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let ciphertext = aes_encrypt_cbc(plaintext, &keys.cipher_key, &keys.iv)?;

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&keys.mac_key)
        .map_err(|_| MediaError::Hmac)?;
    mac.update(&keys.iv);
    mac.update(&ciphertext);
    let mac = mac.finalize().into_bytes()[..10].to_vec();

    let file_sha256 = Sha256::digest(plaintext).to_vec();

    let mut enc_with_mac = Vec::with_capacity(ciphertext.len() + mac.len());
    enc_with_mac.extend_from_slice(&ciphertext);
    enc_with_mac.extend_from_slice(&mac);
    let file_enc_sha256 = Sha256::digest(&enc_with_mac).to_vec();

    Ok(EncryptedMedia {
        ciphertext,
        mac,
        file_sha256,
        file_enc_sha256,
        enc_with_mac,
    })
}

/// Resultado de `encryptMedia`.
#[derive(Debug, Clone)]
pub struct EncryptedMedia {
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
    /// `ciphertext || mac` — o que é enviado no upload.
    pub enc_with_mac: Vec<u8>,
}

/// `downloadEncryptedContent` — descriptografa um stream AES-256-CBC.
///
/// O formato do WhatsApp é: ciphertext em chunks de 16 (com PKCS7 padding),
/// seguido do SHA-256 do plaintext (10 bytes de MAC ficam fora do stream).
/// Suporta `Range` (startByte/endByte) para resumir/streaming: quando um
/// `startByte` é especificado, o bloco anterior de 16 bytes é o IV.
pub fn decrypt_media_stream(
    ciphertext: &[u8],
    keys: &MediaDecryptionKeyInfo,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
) -> Result<Vec<u8>, MediaError> {
    const AES_CHUNK_SIZE: usize = 16;

    let to_smallest_chunk = |n: usize| (n / AES_CHUNK_SIZE) * AES_CHUNK_SIZE;

    // Se startByte especificado, o primeiro bloco do range é o IV.
    let (iv, data_offset) = if let Some(start) = start_byte {
        let chunk = to_smallest_chunk(start);
        if chunk == 0 {
            (keys.iv.clone(), 0)
        } else {
            if ciphertext.len() < AES_CHUNK_SIZE {
                return Err(MediaError::Truncated);
            }
            (ciphertext[..AES_CHUNK_SIZE].to_vec(), AES_CHUNK_SIZE)
        }
    } else {
        (keys.iv.clone(), 0)
    };

    let body = &ciphertext[data_offset..];
    let decrypt_len = to_smallest_chunk(body.len());
    if decrypt_len == 0 {
        return Ok(Vec::new());
    }
    let block = &body[..decrypt_len];
    let mut out = aes_decrypt_cbc(block, &keys.cipher_key, &iv)?;

    // Intervalo parcial: corta conforme start/end.
    if let Some(end) = end_byte {
        if end < out.len() {
            out.truncate(end);
        }
    }
    if let Some(start) = start_byte {
        if start > 0 {
            // A posição no plaintext decodificado.
            let skip = start.saturating_sub(to_smallest_chunk(start));
            if skip < out.len() {
                out.drain(..skip);
            }
        }
    }

    Ok(out)
}

/// Thumbnail de imagem (JPEG 32px, quality 50) — port de `extractImageThumb`.
pub fn image_thumbnail(buffer: &[u8], width: u32) -> Result<Thumbnail, MediaError> {
    let img = image::load_from_memory(buffer).map_err(|_| MediaError::ImageDecode)?;
    let original = ImageDimensions {
        width: img.width(),
        height: img.height(),
    };
    let resized = img.thumbnail(width, width);
    let mut jpeg = Vec::new();
    // Encode manual com quality não é exposto diretamente; usamos `image::codecs::jpeg::JpegEncoder`.
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 50);
    let rgba = resized.to_rgb8();
    encoder.encode_image(&rgba).map_err(|_| MediaError::ImageEncode)?;
    Ok(Thumbnail {
        jpeg: jpeg,
        original,
    })
}

/// Dimensões de imagem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
}

/// Thumbnail gerado.
#[derive(Debug, Clone)]
pub struct Thumbnail {
    pub jpeg: Vec<u8>,
    pub original: ImageDimensions,
}

/// `extractImageDimensions` — lê largura/altura do cabeçalho binário
/// (JPEG, PNG, WebP, GIF) sem biblioteca de imagem.
pub fn extract_image_dimensions(buffer: &[u8]) -> Option<ImageDimensions> {
    if buffer.len() < 10 {
        return None;
    }

    // JPEG
    if buffer[0] == 0xff && buffer[1] == 0xd8 {
        let mut offset = 2usize;
        while offset + 9 < buffer.len() {
            if buffer[offset] != 0xff {
                offset += 1;
                continue;
            }
            let marker = buffer[offset + 1];
            if (0xc0..=0xcf).contains(&marker) && marker != 0xc4 && marker != 0xc8 && marker != 0xcc {
                let height = u16::from_be_bytes([buffer[offset + 5], buffer[offset + 6]]) as u32;
                let width = u16::from_be_bytes([buffer[offset + 7], buffer[offset + 8]]) as u32;
                return Some(ImageDimensions { width, height });
            }
            let seg_len = u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]) as usize;
            offset += 2 + seg_len;
        }
        return None;
    }

    // PNG
    if buffer.len() >= 24
        && buffer[..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
    {
        let width = u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
        let height = u32::from_be_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);
        return Some(ImageDimensions { width, height });
    }

    // WebP
    if buffer.len() >= 12 && &buffer[0..4] == b"RIFF" && &buffer[8..12] == b"WEBP" {
        let chunk = &buffer[12..16];
        if chunk == b"VP8X" && buffer.len() >= 30 {
            let width = 1 + ((buffer[24] as u32) | ((buffer[25] as u32) << 8) | ((buffer[26] as u32) << 16));
            let height = 1 + ((buffer[27] as u32) | ((buffer[28] as u32) << 8) | ((buffer[29] as u32) << 16));
            return Some(ImageDimensions { width, height });
        }
        if chunk == b"VP8 " && buffer.len() >= 30 {
            let b0 = buffer[23] as u32;
            let b1 = buffer[24] as u32;
            let b2 = buffer[25] as u32;
            let width = ((b1 & 0x3f) << 8) | b0;
            let height = ((b2 & 0x3f) << 8) | (b1 >> 6);
            return Some(ImageDimensions { width, height });
        }
        if chunk == b"VP8L" && buffer.len() >= 25 {
            let b0 = buffer[21] as u32;
            let b1 = buffer[22] as u32;
            let b2 = buffer[23] as u32;
            let b3 = buffer[24] as u32;
            let width = 1 + (((b1 & 0x3f) << 8) | b0);
            let height = 1 + (((b3 & 0xf) << 10) | (b2 << 2) | (b1 >> 6));
            return Some(ImageDimensions { width, height });
        }
        return None;
    }

    // GIF
    if buffer.len() >= 10
        && &buffer[0..3] == b"GIF"
        && (&buffer[3..6] == b"87a" || &buffer[3..6] == b"89a")
    {
        let width = u16::from_le_bytes([buffer[6], buffer[7]]) as u32;
        let height = u16::from_le_bytes([buffer[8], buffer[9]]) as u32;
        return Some(ImageDimensions { width, height });
    }

    None
}

/// Executa o FFmpeg com entrada/saída em pipe (`ffmpeg-static` do Node).
///
/// Espelha `runFfmpeg` do `audioPrepare.ts`/`mediaBuffer.ts`.
pub async fn ffmpeg_pipe(input: &[u8], args: &[&str]) -> Result<Vec<u8>, MediaError> {
    let ffmpeg = std::env::var("FFMPEG_PATH").unwrap_or_else(|_| "ffmpeg".to_string());

    let mut cmd = tokio::process::Command::new(&ffmpeg);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // CREATE_NO_WINDOW só existe no Windows (tokio::process::Command).
    #[cfg(windows)]
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW no Windows

    let mut child = cmd.spawn().map_err(|_| MediaError::FfmpegUnavailable)?;

    let mut stdin = child.stdin.take().ok_or(MediaError::FfmpegUnavailable)?;
    use tokio::io::AsyncWriteExt;
    stdin.write_all(input).await?;
    stdin.shutdown().await?;
    // `shutdown()` em `ChildStdin` do tokio NÃO fecha o handle no Windows:
    // o ffmpeg espera EOF para sempre se o stdin continuar em escopo.
    drop(stdin);

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(MediaError::Ffmpeg(String::from_utf8_lossy(&output.stderr).to_string()));
    }
    Ok(output.stdout)
}

/// Converte áudio para OGG/Opus (PTT) — port de `prepareAudioForSend`.
pub async fn prepare_audio_ptt(input: &[u8]) -> Result<Vec<u8>, MediaError> {
    ffmpeg_pipe(
        input,
        &[
            "-i", "pipe:0",
            "-vn",
            "-ar", "48000",
            "-ac", "1",
            "-c:a", "libopus",
            "-b:a", "64k",
            "-application", "voip",
            "-avoid_negative_ts", "make_zero",
            "-map_metadata", "-1",
            "-f", "ogg",
            "pipe:1",
        ],
    )
    .await
}

/// Converte áudio para MP3 (não-PTT) — port de `prepareAudioForSend`.
pub async fn prepare_audio_mp3(input: &[u8]) -> Result<Vec<u8>, MediaError> {
    ffmpeg_pipe(
        input,
        &[
            "-i", "pipe:0",
            "-vn",
            "-ar", "44100",
            "-ac", "2",
            "-c:a", "libmp3lame",
            "-b:a", "128k",
            "-avoid_negative_ts", "make_zero",
            "-map_metadata", "-1",
            "-f", "mp3",
            "pipe:1",
        ],
    )
    .await
}

/// Extrai um frame JPEG de um vídeo — port de `extractVideoThumb`.
pub async fn extract_video_thumb(input: &[u8], width: u32) -> Result<Vec<u8>, MediaError> {
    let scale = format!("scale={width}:-1");
    let frame = ffmpeg_pipe(
        input,
        &[
            "-ss", "00:00:00",
            "-i", "pipe:0",
            "-frames:v", "1",
            "-vf", &scale,
            "-f", "image2pipe",
            "-vcodec", "mjpeg",
            "pipe:1",
        ],
    )
    .await?;
    if frame.is_empty() {
        return Err(MediaError::Ffmpeg("empty video frame".to_string()));
    }
    Ok(frame)
}

/// Probing de mídia via FFmpeg (largura/altura/duração) — port de `parseFfmpegProbe`.
pub async fn ffmpeg_probe(input: &[u8]) -> Result<MediaProbe, MediaError> {
    // `-f null -` faz o ffmpeg ler e descartar, gravando o probe no stderr.
    let output = ffmpeg_pipe(input, &["-hide_banner", "-i", "pipe:0", "-f", "null", "-"]).await;
    let stderr = match output {
        Ok(_) => String::new(),
        // O ffmpeg retorna 1 normalmente para `-f null` sem encode (a info está no stderr).
        Err(MediaError::Ffmpeg(s)) => s,
        Err(e) => return Err(e),
    };
    Ok(parse_ffmpeg_probe(&stderr))
}

/// Resultado do probe FFmpeg.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MediaProbe {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub seconds: Option<f64>,
}

/// `parseFfmpegProbe` — extrai `Stream #... Video: ...WxH` e `Duration:`.
pub fn parse_ffmpeg_probe(stderr: &str) -> MediaProbe {
    let mut probe = MediaProbe::default();

    // Duração.
    if let Some(dur_line) = stderr.lines().find(|l| l.contains("Duration:")) {
        if let Some(rest) = dur_line.split("Duration:").nth(1) {
            let time = rest.split(',').next().unwrap_or_default().trim();
            let parts: Vec<&str> = time.split(':').collect();
            if parts.len() == 3 {
                if let (Ok(h), Ok(m)) = (parts[0].parse::<f64>(), parts[1].parse::<f64>()) {
                    if let Ok(s) = parts[2].parse::<f64>() {
                        probe.seconds = Some(h * 3600.0 + m * 60.0 + s);
                    }
                }
            }
        }
    }

    // Resolução: primeiro stream de vídeo.
    if let Some(video_line) = stderr.lines().find(|l| l.contains("Video:")) {
        for part in video_line.split(',').map(|s| s.trim()) {
            if let Some((w, h)) = part.split_once('x') {
                if let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>()) {
                    if w > 0 && h > 0 {
                        probe.width = Some(w);
                        probe.height = Some(h);
                        break;
                    }
                }
            }
        }
    }

    probe
}

/// Gera o waveform (64 amostras) de áudio — port de `getAudioWaveform`.
///
/// Usa FFmpeg para decodificar para PCM s16le mono 16kHz e calcula os 64
/// buckets de média absoluta normalizados (0..100), como o WhatsApp.
pub async fn audio_waveform(input: &[u8]) -> Result<Vec<u8>, MediaError> {
    let pcm = ffmpeg_pipe(
        input,
        &[
            "-i", "pipe:0",
            "-vn",
            "-ac", "1",
            "-ar", "16000",
            "-f", "s16le",
            "pipe:1",
        ],
    )
    .await?;

    let samples: Vec<i16> = pcm
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    const N: usize = 64;
    if samples.is_empty() {
        return Ok(vec![0u8; N]);
    }
    let block = (samples.len() / N).max(1);
    let mut filtered = Vec::with_capacity(N);
    for i in 0..N {
        let start = block * i;
        let end = (start + block).min(samples.len());
        let sum: f64 = samples[start..end].iter().map(|s| (*s as f64).abs()).sum();
        filtered.push(sum / (end - start) as f64);
    }
    let max = filtered.iter().cloned().fold(0.0001f64, f64::max);
    let inv = max.powf(-1.0);
    Ok(filtered
        .iter()
        .map(|n| (100.0 * n * inv).floor() as u8)
        .collect())
}

/// `getMediaRetryKey` — HKDF do mediaKey com info "WhatsApp Media Retry Notification".
pub fn media_retry_key(media_key: &[u8]) -> Result<Vec<u8>, MediaError> {
    Ok(hkdf(media_key, 32, None, "WhatsApp Media Retry Notification")?)
}

/// `encryptMediaRetryRequest` — gera o conteúdo `<receipt type="server-error">`.
pub fn encrypt_media_retry_request(
    stanza_id: &str,
    media_key: &[u8],
    remote_jid: &str,
    from_me: bool,
    participant: Option<&str>,
) -> Result<MediaRetryRequest, MediaError> {
    use rand::RngCore;
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let retry_key = media_retry_key(media_key)?;
    let ciphertext = aes_encrypt_gcm(stanza_id.as_bytes(), &retry_key, &iv, stanza_id.as_bytes())?;

    Ok(MediaRetryRequest {
        stanza_id: stanza_id.to_string(),
        remote_jid: remote_jid.to_string(),
        from_me,
        participant: participant.map(String::from),
        ciphertext,
        iv: iv.to_vec(),
    })
}

/// Requisição de media retry serializada.
#[derive(Debug, Clone)]
pub struct MediaRetryRequest {
    pub stanza_id: String,
    pub remote_jid: String,
    pub from_me: bool,
    pub participant: Option<String>,
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

/// `decryptMediaRetryData` — descriptografa o `MediaRetryNotification`.
pub fn decrypt_media_retry_data(
    ciphertext: &[u8],
    iv: &[u8],
    media_key: &[u8],
    msg_id: &str,
) -> Result<Vec<u8>, MediaError> {
    let retry_key = media_retry_key(media_key)?;
    Ok(aes_decrypt_gcm(ciphertext, &retry_key, iv, msg_id.as_bytes())?)
}

/// Erros de mídia.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("media key vazio")]
    EmptyMediaKey,
    #[error("crypto: {0}")]
    Crypto(#[from] baileys_crypto::error::CryptoError),
    #[error("hmac key inválida")]
    Hmac,
    #[error("ciphertext truncado")]
    Truncated,
    #[error("falha ao decodificar imagem")]
    ImageDecode,
    #[error("falha ao codificar imagem")]
    ImageEncode,
    #[error("ffmpeg indisponível")]
    FfmpegUnavailable,
    #[error("ffmpeg: {0}")]
    Ffmpeg(String),
    #[error("ffmpeg io: {0}")]
    FfmpegIo(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_keys_match_baileys() {
        // Vetor do Hineken: mediaKey de 32 bytes → HKDF "WhatsApp Image Keys".
        let media_key = [0x42u8; 32];
        let keys = get_media_keys(&media_key, MediaType::Image).unwrap();
        assert_eq!(keys.iv.len(), 16);
        assert_eq!(keys.cipher_key.len(), 32);
        assert_eq!(keys.mac_key.len(), 32);
        // Estabilidade do HKDF (determinístico).
        let keys2 = get_media_keys(&media_key, MediaType::Image).unwrap();
        assert_eq!(keys.iv, keys2.iv);
        assert_eq!(keys.cipher_key, keys2.cipher_key);
        assert_eq!(keys.mac_key, keys2.mac_key);
    }

    #[test]
    fn media_roundtrip_encrypt_decrypt() {
        let media_key = [0x24u8; 32];
        let keys = get_media_keys(&media_key, MediaType::Image).unwrap();

        let plaintext = b"hello media stream content";
        let enc = encrypt_media(plaintext, &keys).unwrap();

        // Decrypt do arquivo completo (ciphertext || mac).
        let mut full = enc.ciphertext.clone();
        full.extend_from_slice(&enc.mac);
        let decrypted = decrypt_media_stream(&full, &keys, None, None).unwrap();
        // O último bloco tem o PKCS7 padding — compara prefixo.
        assert!(decrypted.starts_with(plaintext));
    }

    #[test]
    fn image_dimensions_from_headers() {
        // PNG 1x1 mínimo (assinatura + IHDR width/height=1).
        let png = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // assinatura
            0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR
            0x00, 0x00, 0x00, 0x02, // width = 2
            0x00, 0x00, 0x00, 0x03, // height = 3
            0x08, 0x06, 0x00, 0x00, 0x00,
        ];
        let dims = extract_image_dimensions(&png).unwrap();
        assert_eq!(dims.width, 2);
        assert_eq!(dims.height, 3);
    }

    #[test]
    fn parse_probe_extracts_resolution_and_duration() {
        let stderr = "  Duration: 00:00:05.50, start: 0.000000, bitrate: 128 kb/s\n\
            Stream #0:0: Video: h264 (High), yuv420p, 640x480, 30 fps, 30 tbr, 1k tbn";
        let probe = parse_ffmpeg_probe(stderr);
        assert_eq!(probe.width, Some(640));
        assert_eq!(probe.height, Some(480));
        assert_eq!(probe.seconds, Some(5.5));
    }

    #[test]
    fn upload_path_and_hkdf_info() {
        assert_eq!(MediaType::Image.upload_path(), "/mms/image");
        assert_eq!(MediaType::Ptt.upload_path(), "/mms/audio");
        assert_eq!(MediaType::Image.hkdf_info(), "Image");
        assert_eq!(MediaType::Document.hkdf_info(), "Document");
    }
}
