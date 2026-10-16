//! `baileys-proto` — definições protobuf do WhatsApp.
//!
//! O módulo `proto` é gerado pelo `prost-build` a partir do `WAProto.proto`
//! (cópia exata do `Hineken/WAProto/WAProto.proto`).

/// Módulo gerado (prost). Package = `proto`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

/// FileDescriptorSet gerado no build — usado pelo `#[prost_reflect(...)]`
/// de cada mensagem e pelo serializer JSON (`proto_to_json_value`).
const FILE_DESCRIPTOR_SET_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

pub use proto::*;

/// JSON serializer espelhando o `JSON.stringify(msg)` do Node (camelCase,
/// enums como string, campos omitidos quando vazios).
///
/// O Node entrega os webhooks com o proto serializado em camelCase (ex.:
/// `messageTimestamp`, `messageStubType`). Aqui usamos `prost-reflect`
/// (FileDescriptorSet gerado no build) para produzir o JSON canônico proto3,
/// que é exatamente o formato que o Baileys usa nos webhooks.
pub fn proto_to_json_value(msg: &impl prost_reflect::ReflectMessage) -> serde_json::Value {
    use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};

    static POOL: std::sync::OnceLock<DescriptorPool> = std::sync::OnceLock::new();

    let pool = POOL.get_or_init(|| {
        let bytes: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
        DescriptorPool::decode(bytes).expect("file_descriptor_set.bin inválido")
    });

    let full_name = {
        let descriptor = msg.descriptor();
        descriptor.full_name().to_string()
    };
    let Some(descriptor) = pool.get_message_by_name(&full_name) else {
        // Fallback: bytes do proto em base64 (nunca deve acontecer).
        return serde_json::json!({
            "__protoBytes": msg.encode_to_vec(),
        });
    };

    let bytes = msg.encode_to_vec();
    let dynamic = match DynamicMessage::decode(descriptor.clone(), bytes.as_slice()) {
        Ok(m) => m,
        Err(_) => DynamicMessage::new(descriptor),
    };
    let options = SerializeOptions::new()
        .stringify_64_bit_integers(false)
        .use_enum_numbers(false)
        .use_proto_field_name(false)
        .skip_default_fields(true);
    let mut serializer = serde_json::Serializer::new(Vec::new());
    let result = dynamic.serialize_with_options(&mut serializer, &options);
    let Ok(()) = result else {
        return serde_json::Value::Null;
    };
    let Ok(out) = String::from_utf8(serializer.into_inner()) else {
        return serde_json::Value::Null;
    };
    serde_json::from_str(&out).unwrap_or(serde_json::Value::Null)
}

/// Decodifica um JSON no formato do Node (camelCase + BufferJSON) de volta
/// para uma mensagem prost (`WebMessageInfo`, `Message`, etc.).
///
/// O Node grava `JSON.stringify(msg, BufferJSON.replacer)`, onde campos
/// `bytes` viram `{"type":"Buffer","data":"<base64>"}`. O `prost-reflect`
/// espera string base64 para `bytes`, então convertemos esses objetos antes
/// de desserializar via `DynamicMessage`.
pub fn proto_from_json_str<T>(text: &str) -> Option<T>
where
    T: prost::Message + prost_reflect::ReflectMessage + Default,
{
    use prost_reflect::{DeserializeOptions, DescriptorPool, DynamicMessage};

    static POOL: std::sync::OnceLock<DescriptorPool> = std::sync::OnceLock::new();

    let pool = POOL.get_or_init(|| {
        let bytes: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
        DescriptorPool::decode(bytes).expect("file_descriptor_set.bin inválido")
    });

    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let converted = buffer_objects_to_base64(&json);
    let canonical = serde_json::to_string(&converted).ok()?;

    let full_name = T::default().descriptor().full_name().to_string();
    let descriptor = pool.get_message_by_name(&full_name)?;

    let mut de = serde_json::Deserializer::from_str(&canonical);
    let options = DeserializeOptions::new().deny_unknown_fields(false);
    let dynamic = DynamicMessage::deserialize_with_options(descriptor, &mut de, &options).ok()?;
    if de.end().is_err() {
        return None;
    }

    use prost::Message;
    let bytes = dynamic.encode_to_vec();
    T::decode(bytes.as_slice()).ok()
}

/// Converte objetos BufferJSON (`{"type":"Buffer","data":...}`) em string
/// base64 pura — o formato que o `prost-reflect` aceita para campos `bytes`.
/// Também aceita `{"buffer":true,"data":...}` (variação do reviver).
fn buffer_objects_to_base64(value: &serde_json::Value) -> serde_json::Value {
    use base64::Engine;

    match value {
        serde_json::Value::Object(map) => {
            let is_buffer = map.get("type").and_then(|v| v.as_str()) == Some("Buffer")
                || map.get("buffer").and_then(|v| v.as_bool()) == Some(true);
            if is_buffer {
                let data = map.get("data").or_else(|| map.get("value"));
                let base64 = match data {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(serde_json::Value::Array(arr)) => {
                        let bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        base64::engine::general_purpose::STANDARD.encode(&bytes)
                    }
                    _ => String::new(),
                };
                return serde_json::Value::String(base64);
            }
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), buffer_objects_to_base64(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(buffer_objects_to_base64).collect())
        }
        other => other.clone(),
    }
}
