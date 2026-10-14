//! Serialização `BufferJSON` — formato exato do Baileys.
//!
//! Espelha `Utils/generics.ts` (`BufferJSON.replacer`/`reviver`):
//!
//! - **replacer**: `Buffer`/`Uint8Array`/`{type:'Buffer'}` → `{"type":"Buffer","data":"<base64>"}`.
//! - **reviver**: objeto com `buffer === true` ou `type === 'Buffer'` → bytes.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

/// Serializa um valor com o replacer BufferJSON.
pub fn stringify<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let json = serde_json::to_value(value)?;
    let converted = replacer(&json);
    serde_json::to_string(&converted)
}

/// Desserializa um valor com o reviver BufferJSON.
pub fn parse<T: DeserializeOwned>(s: &str) -> Result<T, serde_json::Error> {
    let json: Value = serde_json::from_str(s)?;
    let revived = reviver(&json);
    serde_json::from_value(revived)
}

/// Revive uma string JSON (retorna `Value` com buffers como arrays de bytes).
pub fn revive_str(s: &str) -> Result<Value, serde_json::Error> {
    let json: Value = serde_json::from_str(s)?;
    Ok(reviver(&json))
}

/// Replacer recursivo (buffers → `{"type":"Buffer","data":base64}`).
pub fn replacer(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            // Um objeto marcado como buffer.
            if is_buffer_obj(map) {
                let data = map.get("data").or_else(|| map.get("value"));
                let base64 = match data {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Array(arr)) => {
                        let bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        base64_encode(&bytes)
                    }
                    _ => String::new(),
                };
                return serde_json::json!({ "type": "Buffer", "data": base64 });
            }
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), replacer(v));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(replacer).collect()),
        other => other.clone(),
    }
}

/// Reviver recursivo (objetos buffer → array de bytes).
pub fn reviver(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            if map.get("buffer") == Some(&Value::Bool(true))
                || map.get("type") == Some(&Value::String("Buffer".to_string()))
            {
                let val = map.get("data").or_else(|| map.get("value"));
                return match val {
                    Some(Value::String(s)) => match base64_decode(s) {
                        Some(bytes) => Value::Array(bytes.iter().map(|&b| Value::from(b)).collect()),
                        None => Value::Array(vec![]),
                    },
                    Some(Value::Array(arr)) => Value::Array(arr.clone()),
                    _ => Value::Array(vec![]),
                };
            }
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), reviver(v));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(reviver).collect()),
        other => other.clone(),
    }
}

fn is_buffer_obj(map: &serde_json::Map<String, Value>) -> bool {
    // No replacer original: value?.type === 'Buffer' indica que já foi serializado
    // como buffer (ou é um Buffer/Uint8Array real).
    map.get("type") == Some(&Value::String("Buffer".to_string()))
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_roundtrip() {
        let input = serde_json::json!({
            "noiseKey": {
                "public": {"type": "Buffer", "data": "AQIDBA=="},
                "private": {"type": "Buffer", "data": "BQYHCA=="}
            },
            "registrationId": 123
        });

        // replacer de um valor já em formato Buffer deve manter o formato.
        let converted = replacer(&input);
        let s = serde_json::to_string(&converted).unwrap();
        assert!(s.contains("\"type\":\"Buffer\""));
        assert!(s.contains("AQIDBA=="));

        // reviver transforma em array de bytes.
        let revived = reviver(&input);
        let noise_key = revived.get("noiseKey").unwrap();
        assert!(noise_key.get("public").unwrap().is_array());
    }

    #[test]
    fn reviver_accepts_buffer_true() {
        let input = serde_json::json!({
            "k": {"buffer": true, "data": "AQID"}
        });
        let revived = reviver(&input);
        assert!(revived.get("k").unwrap().is_array());
    }
}
