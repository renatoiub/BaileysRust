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
