//! Constantes do protocolo espelhando o `Defaults/index.ts` do Baileys.

/// Nome do protocolo Noise. Deve ter exatamente 32 bytes.
pub const NOISE_MODE: &[u8; 32] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

/// Versão do dicionário de tokens (DICT_VERSION).
pub const DICT_VERSION: u8 = 3;

/// Byte de prefixo de chave pública (`KEY_BUNDLE_TYPE = Buffer.from([5])`).
pub const KEY_BUNDLE_TYPE: [u8; 1] = [5];

/// Header do Noise WA: `[87, 65, 6, DICT_VERSION]` (0x57='W', 0x41='A').
pub const NOISE_WA_HEADER: [u8; 4] = [87, 65, 6, DICT_VERSION];

/// Serial do certificado esperado no handshake.
pub const WA_CERT_SERIAL: u32 = 0;

/// Prefixos de assinatura ADV.
pub const WA_ADV_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 0];
pub const WA_ADV_DEVICE_SIG_PREFIX: [u8; 2] = [6, 1];
pub const WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 5];
pub const WA_ADV_HOSTED_DEVICE_SIG_PREFIX: [u8; 2] = [6, 6];

/// URL do WebSocket do WhatsApp Web.
pub const WA_WEB_SOCKET_URL: &str = "wss://web.whatsapp.com/ws/chat";

/// Origem padrão.
pub const DEFAULT_ORIGIN: &str = "https://web.whatsapp.com";

/// Contagem mínima/inicial de pre-keys.
pub const MIN_PREKEY_COUNT: u32 = 5;
pub const INITIAL_PREKEY_COUNT: u32 = 30;

/// Versão do WhatsApp Web espelhando `DEFAULT_WA_VERSION` do container Node
/// (`container/src/services/systemSettings/index.ts`).
pub const WA_VERSION: [u32; 3] = [2, 3000, 1048289394];

/// Prefixos de tag de mensagem/query.
pub const DEF_CALLBACK_PREFIX: &str = "CB:";
pub const DEF_TAG_PREFIX: &str = "TAG:";

/// Prefixo fixo de IDs de mensagem MD.
pub const MD_ID_PREFIX: &str = "3EB0";
