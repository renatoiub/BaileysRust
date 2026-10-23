//! `baileys-media` — processamento de mídia do WhatsApp.

pub mod media;

pub use media::{
    audio_waveform, decrypt_media_retry_data, decrypt_media_stream, encode_base64_for_upload,
    encrypt_media, encrypt_media_retry_request, extension_for_mimetype, extract_image_dimensions,
    extract_video_thumb, ffmpeg_pipe, ffmpeg_probe, get_media_keys, hkdf_info_key,
    image_thumbnail, media_retry_key, normalize_image, parse_ffmpeg_probe, prepare_audio_mp3, prepare_audio_ptt,
    url_from_direct_path, EncryptedMedia, ImageDimensions, MediaDecryptionKeyInfo, MediaError,
    MediaProbe, MediaRetryRequest, MediaType, Thumbnail, MEDIA_DEF_HOST,
};
