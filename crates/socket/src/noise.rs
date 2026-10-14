//! Handshake Noise — port fiel de `Hineken/src/Utils/noise-handler.ts`.

use baileys_codec::{decode_binary_node, encode_binary_node};
use baileys_core::constants::{NOISE_MODE, NOISE_WA_HEADER};
use baileys_core::BinaryNode;
use baileys_crypto::{
    aes_decrypt_gcm, aes_encrypt_gcm, hkdf, sha256, Curve, KeyPair,
};
use baileys_proto::proto as wa_proto;
use prost::Message as _;

/// Erros do noise handler.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("certification match failed")]
    CertificationFailed,
    #[error("crypto: {0}")]
    Crypto(#[from] baileys_crypto::error::CryptoError),
    #[error("decode: {0}")]
    Decode(#[from] baileys_codec::DecodeError),
    #[error("prost decode: {0}")]
    Prost(#[from] prost::DecodeError),
    #[error("frame too short")]
    FrameTooShort,
}

fn generate_iv(counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

/// Estado do handshake Noise (`makeNoiseHandler`).
pub struct NoiseHandler {
    /// Par efêmero da conexão.
    pub key_pair: KeyPair,
    pub noise_header: [u8; 4],

    hash: Vec<u8>,
    salt: Vec<u8>,
    enc_key: Vec<u8>,
    dec_key: Vec<u8>,
    read_counter: u32,
    write_counter: u32,
    is_finished: bool,
    sent_intro: bool,
    in_bytes: Vec<u8>,

    /// Routing info opcional (prefixo ED).
    routing_info: Option<Vec<u8>>,
}

impl NoiseHandler {
    /// Cria o handler, espelhando o construtor do Baileys.
    pub fn new(key_pair: KeyPair, routing_info: Option<Vec<u8>>) -> Self {
        let data = NOISE_MODE;
        // data.byteLength === 32 ? data : sha256(data) — NOISE_MODE tem 32 bytes.
        let hash = data.to_vec();
        let salt = hash.clone();
        let enc_key = hash.clone();
        let dec_key = hash.clone();

        let mut handler = Self {
            key_pair,
            noise_header: NOISE_WA_HEADER,
            hash,
            salt,
            enc_key,
            dec_key,
            read_counter: 0,
            write_counter: 0,
            is_finished: false,
            sent_intro: false,
            in_bytes: Vec::new(),
            routing_info,
        };

        // O construtor do Baileys faz `authenticate(NOISE_HEADER)` e
        // `authenticate(publicKey)` após inicializar o hash.
        let header = handler.noise_header;
        handler.authenticate(&header);
        let public = handler.key_pair.public.clone();
        handler.authenticate(&public);

        handler
    }

    /// `authenticate` — adiciona dados ao hash enquanto o handshake não terminou.
    fn authenticate(&mut self, data: &[u8]) {
        if !self.is_finished {
            let mut combined = Vec::with_capacity(self.hash.len() + data.len());
            combined.extend_from_slice(&self.hash);
            combined.extend_from_slice(data);
            self.hash = sha256(&combined);
        }
    }

    /// `encrypt`
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let result = aes_encrypt_gcm(
            plaintext,
            &self.enc_key,
            &generate_iv(self.write_counter),
            &self.hash,
        )?;
        self.write_counter += 1;
        self.authenticate(&result);
        Ok(result)
    }

    /// `decrypt`
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let iv = generate_iv(if self.is_finished {
            self.read_counter
        } else {
            self.write_counter
        });
        let result = aes_decrypt_gcm(ciphertext, &self.dec_key, &iv, &self.hash)?;
        if self.is_finished {
            self.read_counter += 1;
        } else {
            self.write_counter += 1;
        }
        self.authenticate(ciphertext);
        Ok(result)
    }

    async fn local_hkdf(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), NoiseError> {
        let key = hkdf(data, 64, Some(&self.salt), "")?;
        Ok((key[..32].to_vec(), key[32..].to_vec()))
    }

    async fn mix_into_key(&mut self, data: &[u8]) -> Result<(), NoiseError> {
        let (write, read) = self.local_hkdf(data).await?;
        self.salt = write;
        self.enc_key = read.clone();
        self.dec_key = read;
        self.read_counter = 0;
        self.write_counter = 0;
        Ok(())
    }

    pub async fn finish_init(&mut self) -> Result<(), NoiseError> {
        let (write, read) = self.local_hkdf(&[]).await?;
        self.enc_key = write;
        self.dec_key = read;
        self.hash = Vec::new();
        self.read_counter = 0;
        self.write_counter = 0;
        self.is_finished = true;
        Ok(())
    }

    /// `processHandshake` — processa o ServerHello e retorna a `keyEnc`.
    pub async fn process_handshake(
        &mut self,
        server_hello: &wa_proto::handshake_message::ServerHello,
        noise_key: &KeyPair,
    ) -> Result<Vec<u8>, NoiseError> {
        let ephemeral = server_hello
            .ephemeral
            .as_ref()
            .ok_or(NoiseError::FrameTooShort)?;
        self.authenticate(ephemeral);
        self.mix_into_key(&Curve::shared_key(&self.key_pair.private, ephemeral)?)
            .await?;

        let static_content = server_hello
            .r#static
            .as_ref()
            .ok_or(NoiseError::FrameTooShort)?;
        let dec_static = self.decrypt(static_content)?;
        self.mix_into_key(&Curve::shared_key(&self.key_pair.private, &dec_static)?)
            .await?;

        let payload = server_hello
            .payload
            .as_ref()
            .ok_or(NoiseError::FrameTooShort)?;
        let cert_decoded = self.decrypt(payload)?;

        let cert_chain = wa_proto::CertChain::decode(cert_decoded.as_slice())?;
        let intermediate = cert_chain
            .intermediate
            .ok_or(NoiseError::CertificationFailed)?;
        let details_bytes = intermediate
            .details
            .ok_or(NoiseError::CertificationFailed)?;
        let details = wa_proto::cert_chain::noise_certificate::Details::decode(
            details_bytes.as_slice(),
        )?;
        let issuer_serial = details.issuer_serial.unwrap_or(0);
        if issuer_serial != crate::WA_CERT_SERIAL {
            return Err(NoiseError::CertificationFailed);
        }

        let key_enc = self.encrypt(&noise_key.public)?;
        self.mix_into_key(&Curve::shared_key(&noise_key.private, ephemeral)?)
            .await?;

        Ok(key_enc)
    }

    /// `encodeFrame` — codifica um frame com header + length.
    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let data = if self.is_finished {
            self.encrypt(data)?
        } else {
            data.to_vec()
        };

        let mut header: Vec<u8> = Vec::new();
        if let Some(routing_info) = &self.routing_info {
            header.push(b'E');
            header.push(b'D');
            header.push(0);
            header.push(1);
            let len = routing_info.len();
            header.push((len >> 16) as u8);
            header.push(((len & 0xFFFF) >> 8) as u8);
            header.push((len & 0xFF) as u8);
            header.extend_from_slice(routing_info);
            header.extend_from_slice(&self.noise_header);
        } else {
            header.extend_from_slice(&self.noise_header);
        }

        let intro_size = if self.sent_intro { 0 } else { header.len() };
        let mut frame = Vec::with_capacity(intro_size + 3 + data.len());
        if !self.sent_intro {
            frame.extend_from_slice(&header);
            self.sent_intro = true;
        }
        frame.push((data.len() >> 16) as u8);
        frame.push(((data.len() >> 8) & 0xFF) as u8);
        frame.push((data.len() & 0xFF) as u8);
        frame.extend_from_slice(&data);

        Ok(frame)
    }

    /// `decodeFrame` — separa os frames recebidos e chama `on_frame`.
    ///
    /// Os frames são `BinaryNode` (após handshake) ou bytes crus.
    pub fn decode_frame(
        &mut self,
        new_data: &[u8],
        on_frame: &mut dyn FnMut(Frame),
    ) -> Result<(), NoiseError> {
        self.in_bytes.extend_from_slice(new_data);

        loop {
            if self.in_bytes.len() < 3 {
                break;
            }
            let size = ((self.in_bytes[0] as usize) << 16)
                | ((self.in_bytes[1] as usize) << 8)
                | (self.in_bytes[2] as usize);
            if self.in_bytes.len() < size + 3 {
                break;
            }

            let frame = self.in_bytes[3..size + 3].to_vec();
            self.in_bytes.drain(..size + 3);

            let frame = if self.is_finished {
                let decrypted = self.decrypt(&frame)?;
                let node = decode_binary_node(&decrypted)?;
                Frame::Node(node)
            } else {
                Frame::Raw(frame)
            };

            on_frame(frame);
        }

        Ok(())
    }
}

/// Frame decodificado.
pub enum Frame {
    Node(BinaryNode),
    Raw(Vec<u8>),
}

/// Serial do certificado esperado no handshake (WA_CERT_DETAILS.SERIAL).
pub const WA_CERT_SERIAL: u32 = 0;

/// Encoda um nó binário (para envio).
pub fn encode_node(node: &BinaryNode) -> Vec<u8> {
    encode_binary_node(node)
}

/// Gera a mensagem de ClientHello para o handshake.
pub fn client_hello(ephemeral_public: &[u8]) -> Vec<u8> {
    use prost::Message;
    let hello = wa_proto::HandshakeMessage {
        client_hello: Some(wa_proto::handshake_message::ClientHello {
            ephemeral: Some(ephemeral_public.to_vec()),
            r#static: None,
            payload: None,
        }),
        server_hello: None,
        client_finish: None,
    };
    hello.encode_to_vec()
}

/// Decodifica a resposta ServerHello do servidor.
pub fn parse_server_hello(data: &[u8]) -> Result<wa_proto::handshake_message::ServerHello, NoiseError> {
    use prost::Message;
    let handshake = wa_proto::HandshakeMessage::decode(data)?;
    handshake
        .server_hello
        .ok_or(NoiseError::FrameTooShort)
}
