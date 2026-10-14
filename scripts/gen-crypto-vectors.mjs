// Gera vetores de teste criptográficos a partir do libsignal/curve25519-js REAIS.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const curve = require('C:/projetos/apibaileys/container/node_modules/libsignal/src/curve.js');

function hex(b) {
  return Buffer.from(b).toString('hex');
}

// --- Vetores determinísticos: derive pub a partir de seed ---
const seedA = Buffer.alloc(32, 0x42);
const seedB = Buffer.alloc(32, 0x24);

// getPublicFromPrivateKey(seed) → pub com prefixo 05 (33 bytes)
const pubA33 = Buffer.from(curve.getPublicFromPrivateKey(seedA));
const pubB33 = Buffer.from(curve.getPublicFromPrivateKey(seedB));
const pubA = pubA33.slice(1); // 32 bytes
const pubB = pubB33.slice(1);

const vectors = {};
vectors.pubA = hex(pubA);
vectors.pubB = hex(pubB);

vectors.sharedKeyAB = hex(curve.calculateAgreement(pubB33, seedA));
vectors.sharedKeyBA = hex(curve.calculateAgreement(pubA33, seedB));

// XEdDSA sign (calculateSignature usa curve25519-js sign, determinístico)
const msg = Buffer.from('whatsapp-noise-test-message');
const sigA = Buffer.from(curve.calculateSignature(seedA, msg));
vectors.signature = {
  private: hex(seedA),
  msg: hex(msg),
  signature: hex(sigA),
};

// Caso real de signedPreKey: assina pub com prefixo 05
const sigSPK = Buffer.from(curve.calculateSignature(seedA, pubB33));
vectors.signedPreKey = {
  identityPrivate: hex(seedA),
  signedPublicWithPrefix: hex(pubB33),
  signature: hex(sigSPK),
};

// verify checks
vectors.verify = {
  ok: curve.verifySignature(pubA33, msg, sigA),
  wrongKey: curve.verifySignature(pubB33, msg, sigA),
  tampered: curve.verifySignature(pubA33, Buffer.from('tampered-message'), sigA),
};

// Fuzz: várias chaves, para cobrir interação paridade/sign-bit
vectors.fuzz = [];
for (let i = 0; i < 12; i++) {
  const seed = Buffer.alloc(32, i);
  const pub33 = Buffer.from(curve.getPublicFromPrivateKey(seed));
  const m = Buffer.from('msg-' + i);
  const sig = curve.calculateSignature(seed, m);
  vectors.fuzz.push({
    seed: hex(seed),
    public: hex(pub33.slice(1)),
    msg: hex(m),
    signature: hex(sig),
    verifyOk: curve.verifySignature(pub33, m, sig),
  });
}

console.log(JSON.stringify(vectors, null, 2));
