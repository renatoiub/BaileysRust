//! build.rs do `baileys-proto`.
//!
//! O `WAProto.proto` usa `syntax = "proto3"` mas contém campos `required`
//! (legado do protobufjs). O `prost-build` só aceita `optional`, então
//! pré-processamos o arquivo convertendo `required` → `optional` em memória
//! e compilamos a partir de um arquivo temporário no OUT_DIR.

use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("proto")
        .join("WAProto.proto");

    let src = std::fs::read_to_string(&proto_path).expect("WAProto.proto não encontrado");
    // Converte `required` → `optional` (prost é proto3-only).
    let mut patched = src.replace("required ", "optional ");
    // O WAProto.proto usa enums proto3 cujo primeiro valor não é zero
    // (ex.: `FULL = 1;`), o que o protoc rejeita. Injetamos um dummy `= 0`
    // como primeiro membro desses enums (não altera os valores existentes).
    patched = fix_enum_zero_values(&patched);

    let out_dir = std::env::var("OUT_DIR")?;
    let out_proto = std::path::Path::new(&out_dir).join("WAProto.proto");
    std::fs::write(&out_proto, patched.as_bytes())?;

    // Usa o protoc vendido pelo protobuf-src (não exige instalação no host).
    std::env::set_var("PROTOC", protobuf_src::protoc());

    let mut config = prost_build::Config::new();
    // Deriva `ReflectMessage` em todas as mensagens (para o serializer JSON
    // camelCase do `lib.rs` — paridade com o `JSON.stringify` do Node) e
    // gera o FileDescriptorSet.
    let mut builder = prost_reflect_build::Builder::new();
    builder
        .file_descriptor_set_bytes("crate::FILE_DESCRIPTOR_SET_BYTES")
        .file_descriptor_set_path(
            std::path::Path::new(&out_dir).join("file_descriptor_set.bin"),
        );
    builder
        .configure(&mut config, &[&out_proto], &[out_proto.parent().unwrap()])
        .expect("falha ao configurar prost-reflect");

    config.compile_protos(&[&out_proto], &[out_proto.parent().unwrap()])?;

    let mut marker = std::fs::File::create(std::path::Path::new(&out_dir).join("proto-built"))?;
    writeln!(marker, "ok")?;

    Ok(())
}

/// Adiciona um membro `__UNUSED_ZERO_N__ = 0;` no início de enums proto3 cujo
/// primeiro valor não é zero (exigência do protoc para enums abertos).
/// O nome é único por enum (escopo C++), evitando colisões.
fn fix_enum_zero_values(src: &str) -> String {
    let mut out = String::with_capacity(src.len() + 4096);
    let mut lines = src.lines().peekable();
    let mut in_enum = false;
    let mut counter = 0u32;

    while let Some(line) = lines.next() {
        let trimmed = line.trim();

        if trimmed.starts_with("enum ") {
            in_enum = true;
            counter += 1;
            out.push_str(line);
            out.push('\n');
            continue;
        }

        if in_enum {
            // Fim do bloco enum.
            if trimmed == "}" {
                in_enum = false;
                out.push_str(line);
                out.push('\n');
                continue;
            }
            // Primeira declaração de valor: verifica se começa em != 0.
            if !trimmed.is_empty() && !trimmed.starts_with("//") {
                let first_value = trimmed
                    .split('=')
                    .nth(1)
                    .map(|v| v.trim_end_matches(';').trim().to_string())
                    .unwrap_or_default();
                if first_value != "0" {
                    out.push_str(&format!("    __UNUSED_ZERO_{counter}__ = 0;\n"));
                }
                in_enum = false; // só o primeiro membro importa
            }
        }

        out.push_str(line);
        out.push('\n');
    }

    out
}
