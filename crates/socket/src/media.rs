//! Construtores de mensagens de mídia (`wa::Message`).
//!
//! Espelham `prepareWAMessageMedia` + `generateWAMessageContent` do Hineken,
//! montando o campo correto (`imageMessage`, `videoMessage`, `audioMessage`,
//! `documentMessage`) com os dados de upload já resolvidos.

use baileys_proto::proto as wa;

use crate::client::MediaUpload;

/// `mediaKeyTimestamp` em segundos (campo obrigatório dos protos de mídia).
fn media_key_timestamp() -> i64 {
    baileys_core::ids::unix_timestamp_seconds() as i64
}

/// Monta uma mensagem de imagem.
pub fn image_message(
    upload: &MediaUpload,
    mimetype: &str,
    width: u32,
    height: u32,
    caption: Option<&str>,
    jpeg_thumbnail: Option<Vec<u8>>,
) -> wa::Message {
    let ts = media_key_timestamp();
    let msg = wa::message::ImageMessage {
        url: Some(upload.media_url.clone()),
        mimetype: Some(mimetype.to_string()),
        caption: caption.map(String::from),
        file_sha256: Some(upload.file_sha256.clone()),
        file_length: Some(upload.file_length),
        height: Some(height),
        width: Some(width),
        media_key: Some(upload.media_key.clone()),
        file_enc_sha256: Some(upload.file_enc_sha256.clone()),
        direct_path: Some(upload.direct_path.clone()),
        media_key_timestamp: Some(ts),
        jpeg_thumbnail,
        ..Default::default()
    };
    wa::Message {
        image_message: Some(Box::new(msg)),
        ..Default::default()
    }
}

/// Monta uma mensagem de vídeo.
pub fn video_message(
    upload: &MediaUpload,
    mimetype: &str,
    width: u32,
    height: u32,
    seconds: u32,
    caption: Option<&str>,
    jpeg_thumbnail: Option<Vec<u8>>,
) -> wa::Message {
    let ts = media_key_timestamp();
    let msg = wa::message::VideoMessage {
        url: Some(upload.media_url.clone()),
        mimetype: Some(mimetype.to_string()),
        file_sha256: Some(upload.file_sha256.clone()),
        file_length: Some(upload.file_length),
        seconds: Some(seconds),
        media_key: Some(upload.media_key.clone()),
        caption: caption.map(String::from),
        height: Some(height),
        width: Some(width),
        file_enc_sha256: Some(upload.file_enc_sha256.clone()),
        direct_path: Some(upload.direct_path.clone()),
        media_key_timestamp: Some(ts),
        jpeg_thumbnail,
        ..Default::default()
    };
    wa::Message {
        video_message: Some(Box::new(msg)),
        ..Default::default()
    }
}

/// Monta uma mensagem de áudio (PTT ou normal).
pub fn audio_message(
    upload: &MediaUpload,
    mimetype: &str,
    seconds: u32,
    ptt: bool,
    waveform: Option<Vec<u8>>,
) -> wa::Message {
    let ts = media_key_timestamp();
    let msg = wa::message::AudioMessage {
        url: Some(upload.media_url.clone()),
        mimetype: Some(mimetype.to_string()),
        file_sha256: Some(upload.file_sha256.clone()),
        file_length: Some(upload.file_length),
        seconds: Some(seconds),
        ptt: Some(ptt),
        media_key: Some(upload.media_key.clone()),
        file_enc_sha256: Some(upload.file_enc_sha256.clone()),
        direct_path: Some(upload.direct_path.clone()),
        media_key_timestamp: Some(ts),
        waveform,
        ..Default::default()
    };
    wa::Message {
        audio_message: Some(Box::new(msg)),
        ..Default::default()
    }
}

/// Monta uma mensagem de documento.
pub fn document_message(
    upload: &MediaUpload,
    mimetype: &str,
    filename: &str,
    caption: Option<&str>,
    jpeg_thumbnail: Option<Vec<u8>>,
) -> wa::Message {
    let ts = media_key_timestamp();
    let msg = wa::message::DocumentMessage {
        url: Some(upload.media_url.clone()),
        mimetype: Some(mimetype.to_string()),
        file_sha256: Some(upload.file_sha256.clone()),
        file_length: Some(upload.file_length),
        media_key: Some(upload.media_key.clone()),
        file_name: Some(filename.to_string()),
        file_enc_sha256: Some(upload.file_enc_sha256.clone()),
        direct_path: Some(upload.direct_path.clone()),
        media_key_timestamp: Some(ts),
        jpeg_thumbnail,
        caption: caption.map(String::from),
        ..Default::default()
    };
    wa::Message {
        document_message: Some(Box::new(msg)),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload() -> MediaUpload {
        MediaUpload {
            media_key: vec![1u8; 32],
            file_enc_sha256: vec![2u8; 32],
            file_sha256: vec![3u8; 32],
            file_length: 1234,
            media_url: "https://mmg.whatsapp.net/d/f/abc".to_string(),
            direct_path: "/d/f/abc".to_string(),
        }
    }

    #[test]
    fn image_message_fields() {
        let m = image_message(&upload(), "image/jpeg", 800, 600, Some("cap"), Some(vec![9, 9]));
        let img = m.image_message.unwrap();
        assert_eq!(img.width, Some(800));
        assert_eq!(img.height, Some(600));
        assert_eq!(img.caption.as_deref(), Some("cap"));
        assert_eq!(img.media_key.as_deref(), Some(&[1u8; 32][..]));
        assert!(img.media_key_timestamp.unwrap() > 0);
    }

    #[test]
    fn audio_message_ptt() {
        let m = audio_message(&upload(), "audio/ogg; codecs=opus", 5, true, Some(vec![0; 64]));
        let audio = m.audio_message.unwrap();
        assert_eq!(audio.ptt, Some(true));
        assert_eq!(audio.seconds, Some(5));
        assert_eq!(audio.waveform.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn document_message_filename() {
        let m = document_message(&upload(), "application/pdf", "doc.pdf", None, None);
        let doc = m.document_message.unwrap();
        assert_eq!(doc.file_name.as_deref(), Some("doc.pdf"));
    }
}
