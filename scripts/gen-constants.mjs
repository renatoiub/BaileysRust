// Gera constants.rs a partir do constants.ts real do Hineken.
// Uso: node gen-constants.mjs <caminho-constants.ts> <saida.rs>
// Garante que as tabelas de tokens são idênticas ao Baileys (sem erro de transcrição).
import { readFileSync, writeFileSync } from 'node:fs';

const [, , tsPath, outPath] = process.argv;
if (!tsPath || !outPath) {
  console.error('uso: node gen-constants.mjs <constants.ts> <saida.rs>');
  process.exit(1);
}

let src = readFileSync(tsPath, 'utf8');

// Só precisamos de TAGS, DOUBLE_BYTE_TOKENS e SINGLE_BYTE_TOKENS,
// que vêm antes do TOKEN_MAP (que usa TS types em runtime).
const tokenMapIdx = src.indexOf('export const TOKEN_MAP');
if (tokenMapIdx >= 0) {
  src = src.slice(0, tokenMapIdx);
}

src = src
  .replace(/export const/g, 'const')
  .replace(/ as const/g, '');

// constants.ts tem apenas TAGS, DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS, TOKEN_MAP.
// TOKEN_MAP usa loops; precisamos apenas das três constantes. Avalia num sandbox mínimo.
const sandbox = {};
const fn = new Function('sandbox', `
  with (sandbox) {
    ${src}
    sandbox.__TAGS = TAGS;
    sandbox.__DBT = DOUBLE_BYTE_TOKENS;
    sandbox.__SBT = SINGLE_BYTE_TOKENS;
  }
`);
fn(sandbox);

const { __TAGS, __DBT, __SBT } = sandbox;

if (!__SBT || !__DBT || !__TAGS) {
  console.error('falha ao extrair tokens do constants.ts');
  process.exit(1);
}

const rustStr = (s) => JSON.stringify(s);
const emit = (lines) => writeFileSync(outPath, lines.join('\n') + '\n', 'utf8');

const lines = [];
lines.push('//! Tags e tabelas de tokens do WABinary.');
lines.push('//!');
lines.push('//! GERADO AUTOMATICAMENTE a partir de `Hineken/src/WABinary/constants.ts`.');
lines.push('//! NÃO editar à mão — rode `node gen-constants.mjs` para regenerar.');
lines.push('');
lines.push('pub mod tags {');
for (const [k, v] of Object.entries(__TAGS)) {
  lines.push(`    pub const ${k}: u8 = ${v};`);
}
lines.push('}');
lines.push('');

lines.push('/// Tokens de byte único (índice = tag).');
lines.push('pub static SINGLE_BYTE_TOKENS: &[&str] = &[');
for (const t of __SBT) {
  lines.push(`    ${rustStr(t)},`);
}
lines.push('];');
lines.push('');

lines.push('/// Tokens de byte duplo (índice = dicionário, depois índice).');
lines.push('pub static DOUBLE_BYTE_TOKENS: &[&[&str]] = &[');
for (const dict of __DBT) {
  lines.push('    &[');
  for (const t of dict) {
    lines.push(`        ${rustStr(t)},`);
  }
  lines.push('    ],');
}
lines.push('];');
lines.push('');

lines.push('/// Mapa de token → (dict opcional, índice), construído em runtime.');
lines.push('pub fn token_map() -> std::collections::HashMap<String, (Option<usize>, usize)> {');
lines.push('    let mut map = std::collections::HashMap::new();');
lines.push('    for (i, token) in SINGLE_BYTE_TOKENS.iter().enumerate() {');
lines.push('        map.insert((*token).to_string(), (None, i));');
lines.push('    }');
lines.push('    for (i, dict) in DOUBLE_BYTE_TOKENS.iter().enumerate() {');
lines.push('        for (j, token) in dict.iter().enumerate() {');
lines.push('            map.insert((*token).to_string(), (Some(i), j));');
lines.push('        }');
lines.push('    }');
lines.push('    map');
lines.push('}');
lines.push('');
lines.push('#[cfg(test)]');
lines.push('mod tests {');
lines.push('    use super::*;');
lines.push('');
lines.push('    #[test]');
lines.push('    fn single_byte_token_count() {');
lines.push('        assert_eq!(SINGLE_BYTE_TOKENS.len(), 236);');
lines.push('    }');
lines.push('');
lines.push('    #[test]');
lines.push('    fn double_byte_token_dicts() {');
lines.push('        assert_eq!(DOUBLE_BYTE_TOKENS.len(), 4);');
lines.push('        assert!(!DOUBLE_BYTE_TOKENS[0].is_empty());');
lines.push('    }');
lines.push('');
lines.push('    #[test]');
lines.push('    fn token_map_has_common() {');
lines.push('        let map = token_map();');
lines.push('        assert!(map.contains_key("iq"));');
lines.push('        assert!(map.contains_key("message"));');
lines.push('        assert!(map.contains_key("pair-device"));');
lines.push('    }');
lines.push('}');

emit(lines);
console.log(`OK: ${__SBT.length} single-byte, ${__DBT.length} dicts, ${__DBT.reduce((a, d) => a + d.length, 0)} double-byte tokens`);
