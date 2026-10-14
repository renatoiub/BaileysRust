//! Link preview — port de `Utils/link-preview.ts` (Fase 3).
//!
//! Extrai a primeira URL do texto, busca título/descrição/imagem (Open Graph)
//! e gera o thumbnail. A versão Rust faz a busca HTTP básica + parse de
//! `<meta>` tags (og:title, og:description, og:image, title).

use baileys_proto::proto as wa;

/// Informações de link preview (espelha `WAUrlInfo`).
#[derive(Debug, Clone, Default)]
pub struct UrlInfo {
    pub canonical_url: Option<String>,
    pub matched_text: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub original_thumbnail_url: Option<String>,
    pub jpeg_thumbnail: Option<Vec<u8>>,
}

/// `generateLinkPreviewIfRequired` — detecta URL no texto.
///
/// Port de `Utils/messages.ts::generateLinkPreviewIfRequired`: apenas a
/// primeira URL (`https?://...`) é usada.
pub fn detect_url(text: &str) -> Option<String> {
    for word in text.split_whitespace() {
        if word.starts_with("http://") || word.starts_with("https://") {
            // Remove pontuação final (`,` `.` `)` etc.).
            let trimmed = word.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '/' && c != '-' && c != '_' && c != '&' && c != '=' && c != '?');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Busca o link preview (título, descrição e thumbnail) via HTTP.
///
/// Faz o fetch da URL e extrai as tags Open Graph/Twitter/HTML padrão.
/// Retorna `None` se a URL for inválida ou o fetch falhar.
pub async fn fetch_url_info(url: &str) -> Option<UrlInfo> {
    let normalized = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
        .timeout(std::time::Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .ok()?;

    let resp = client.get(&normalized).send().await.ok()?;
    let final_url = resp.url().to_string();
    let html = resp.text().await.ok()?;

    let mut info = UrlInfo {
        canonical_url: Some(final_url),
        matched_text: Some(url.to_string()),
        ..Default::default()
    };

    // Extrai meta tags.
    let mut og_image: Option<String> = None;
    let mut twitter_image: Option<String> = None;

    for meta in parse_meta_tags(&html) {
        match meta.name.to_lowercase().as_str() {
            "og:title" => {
                if info.title.is_none() {
                    info.title = meta.content;
                }
            }
            "og:description" => {
                if info.description.is_none() {
                    info.description = meta.content;
                }
            }
            "og:image" => {
                if og_image.is_none() {
                    og_image = meta.content;
                }
            }
            "twitter:title" => {
                if info.title.is_none() {
                    info.title = meta.content;
                }
            }
            "twitter:description" => {
                if info.description.is_none() {
                    info.description = meta.content;
                }
            }
            "twitter:image" => {
                if twitter_image.is_none() {
                    twitter_image = meta.content;
                }
            }
            "description" => {
                if info.description.is_none() {
                    info.description = meta.content;
                }
            }
            _ => {}
        }
    }

    // Fallback: <title> tag.
    if info.title.is_none() {
        info.title = extract_tag_content(&html, "title");
    }

    let thumbnail_url = og_image.or(twitter_image);
    info.original_thumbnail_url = thumbnail_url.clone();

    // Gera o thumbnail JPEG (192px) se houver imagem.
    if let Some(img_url) = thumbnail_url {
        if let Some(bytes) = fetch_image_thumbnail(&client, &img_url).await {
            info.jpeg_thumbnail = Some(bytes);
        }
    }

    if info.title.is_some() {
        Some(info)
    } else {
        None
    }
}

/// Converte `UrlInfo` no campo `matchedText`/`jpegThumbnail` do
/// `ExtendedTextMessage` (compatível com o Baileys).
pub fn apply_link_preview(ext: &mut wa::message::ExtendedTextMessage, info: &UrlInfo) {
    ext.matched_text = info.matched_text.clone();
    ext.jpeg_thumbnail = info.jpeg_thumbnail.clone();
    if let Some(canonical) = &info.canonical_url {
        let mut ctx = ext
            .context_info
            .clone()
            .map(|b| *b)
            .unwrap_or_default();
        let mut ad = ctx
            .external_ad_reply
            .clone()
            .unwrap_or_default();
        ad.source_url = Some(canonical.clone());
        ad.title = info.title.clone();
        ad.body = info.description.clone();
        ad.thumbnail = info.jpeg_thumbnail.clone();
        ctx.external_ad_reply = Some(ad);
        ext.context_info = Some(Box::new(ctx));
    }
}

/// Resultado de uma meta tag.
struct MetaTag {
    name: String,
    content: Option<String>,
}

/// Parse simples de `<meta name/property content>` do HTML.
fn parse_meta_tags(html: &str) -> Vec<MetaTag> {
    let mut out = Vec::new();
    let lower = html.to_lowercase();

    let mut search_from = 0usize;
    while let Some(start) = lower[search_from..].find("<meta") {
        let start = search_from + start;
        let Some(rel_end) = lower[start..].find('>') else { break };
        let end = start + rel_end;
        let tag = &html[start..end + 1];
        let tag_lower = &lower[start..end + 1];

        let attr = |key: &str| -> Option<String> {
            let key_pat = format!("{key}=");
            let Some(idx) = tag_lower.find(&key_pat) else { return None };
            let after = &tag[idx + key_pat.len()..];
            let quote = after.chars().next()?;
            if quote != '"' && quote != '\'' {
                return None;
            }
            let inner = &after[1..];
            let end_quote = inner.find(quote)?;
            Some(html_unescape(&inner[..end_quote]))
        };

        let name = attr("name").or_else(|| attr("property")).unwrap_or_default();
        if !name.is_empty() {
            out.push(MetaTag {
                name,
                content: attr("content"),
            });
        }

        search_from = end + 1;
        if search_from >= html.len() {
            break;
        }
    }
    out
}

/// Extrai o conteúdo de uma tag HTML simples.
fn extract_tag_content(html: &str, tag: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let open = format!("<{tag}");
    let idx = lower.find(&open)?;
    let close = lower[idx..].find('>')? + idx;
    let close_tag = format!("</{tag}>");
    let end = lower[close..].find(&close_tag)? + close;
    let content = &html[close + 1..end];
    Some(html_unescape(content.trim()))
}

/// Decodifica entidades HTML básicas.
fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// Baixa uma imagem e gera o thumbnail (JPEG 192px).
async fn fetch_image_thumbnail(client: &reqwest::Client, url: &str) -> Option<Vec<u8>> {
    let resp = client.get(url).send().await.ok()?;
    let bytes = resp.bytes().await.ok()?;
    let img = image::load_from_memory(&bytes).ok()?;
    let resized = img.thumbnail(192, 192).to_rgb8();
    let mut jpeg = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 50);
    encoder.encode_image(&resized).ok()?;
    Some(jpeg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_urls_in_text() {
        assert_eq!(
            detect_url("olha isso https://example.com/foo legal").as_deref(),
            Some("https://example.com/foo")
        );
        assert_eq!(detect_url("sem url aqui"), None);
        assert_eq!(detect_url("https://a.com, veja"), Some("https://a.com".to_string()));
    }

    #[test]
    fn parses_meta_tags() {
        let html = r#"<html><head><title>Titulo</title>
            <meta property="og:title" content="OG Titulo">
            <meta name="description" content="Uma descricao &amp; mais">
            <meta property="og:image" content="https://img.example.com/foto.jpg">
            </head></html>"#;
        let tags = parse_meta_tags(html);
        assert!(tags.iter().any(|t| t.name == "og:title" && t.content.as_deref() == Some("OG Titulo")));
        assert!(tags.iter().any(|t| t.name == "description" && t.content.as_deref() == Some("Uma descricao & mais")));
        assert!(tags.iter().any(|t| t.name == "og:image" && t.content.as_deref() == Some("https://img.example.com/foto.jpg")));
    }

    #[test]
    fn extracts_title_content() {
        let html = "<html><head><title> Meu Site </title></head></html>";
        assert_eq!(extract_tag_content(html, "title").as_deref(), Some("Meu Site"));
    }
}
