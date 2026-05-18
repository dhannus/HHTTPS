/**
 * Privacy Pass Key Management — VOPRF P-384/SHA-384 (Token Type 0x0002)
 *
 * Generates a persistent VOPRF key pair on first run.
 * Keys are saved to ./keys/ and reloaded on restart — issued tokens remain valid.
 *
 * IMPORTANT: These keys are completely independent of the HHTTPS ES256 keys
 * in ../keys.js. They MUST NOT share storage, rotation, or trust relationships.
 * This separation preserves Privacy Pass unlinkability guarantees per RFC 9576.
 *
 * Token Type 0x0002 (privately verifiable, VOPRF-based) is chosen because it
 * requires less key infrastructure than 0x0001 (Blind RSA) and is sufficient
 * for single-issuer deployments. 0x0001 can be added later for federation.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname }                                       from 'path';
import { fileURLToPath }                                       from 'url';
import { createHash }                                          from 'crypto';

import { Oprf, generateKeyPair } from '@cloudflare/voprf-ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR  = join(__dirname, 'keys');

const PRIV_FILE = join(KEYS_DIR, 'voprf-private.bin');
const PUB_FILE  = join(KEYS_DIR, 'voprf-public.bin');
const META_FILE = join(KEYS_DIR, 'meta.json');

// Token Type 0x0002 — VOPRF(P-384, SHA-384) per RFC 9578 §6
export const TOKEN_TYPE = 0x0002;
export const SUITE      = Oprf.Suite.P384_SHA384;
export const SUITE_NAME = 'P384-SHA384';
export const MODE       = Oprf.Mode.VOPRF;

// Sizes per RFC 9578 §6 / RFC 9497 for P-384:
export const Ne = 49;   // Serialized element (compressed EC point)
export const Ns = 48;   // Serialized scalar / SHA-384 output / authenticator size

let _privateKey = null;  // Uint8Array, Ns bytes
let _publicKey  = null;  // Uint8Array, Ne bytes
let _tokenKeyId = null;  // Buffer, SHA-256(public_key), 32 bytes
let _notBefore  = null;  // Unix seconds

/**
 * truncated_token_key_id per RFC 9578 §6.1 is the least significant byte of
 * SHA-256(public_key). Clients use it to identify which issuer key was used.
 */
export function truncatedKeyId() {
  return _tokenKeyId[_tokenKeyId.length - 1];
}

export async function loadOrCreateKeys() {
  mkdirSync(KEYS_DIR, { recursive: true });

  if (existsSync(PRIV_FILE) && existsSync(PUB_FILE) && existsSync(META_FILE)) {
    _privateKey = readFileSync(PRIV_FILE);
    _publicKey  = readFileSync(PUB_FILE);
    const meta  = JSON.parse(readFileSync(META_FILE, 'utf8'));
    _tokenKeyId = Buffer.from(meta.tokenKeyId, 'base64');
    _notBefore  = meta.notBefore;
    console.log(`   [PRIVACY-PASS] Keys loaded from disk (suite: ${SUITE_NAME})`);
  } else {
    // Real VOPRF P-384 key pair generation via @cloudflare/voprf-ts
    const kp = await generateKeyPair(SUITE);
    _privateKey = Buffer.from(kp.privateKey);
    _publicKey  = Buffer.from(kp.publicKey);
    _tokenKeyId = createHash('sha256').update(_publicKey).digest();
    _notBefore  = Math.floor(Date.now() / 1000);

    writeFileSync(PRIV_FILE, _privateKey, { mode: 0o600 });
    writeFileSync(PUB_FILE,  _publicKey,  { mode: 0o644 });
    writeFileSync(META_FILE, JSON.stringify({
      tokenType:  TOKEN_TYPE,
      suite:      SUITE_NAME,
      mode:       'VOPRF',
      tokenKeyId: _tokenKeyId.toString('base64'),
      notBefore:  _notBefore,
    }, null, 2), { mode: 0o644 });

    console.log(`   [PRIVACY-PASS] New VOPRF ${SUITE_NAME} key pair generated`);
  }
}

export function getPublicKey()  { return _publicKey; }
export function getPrivateKey() { return _privateKey; }
export function getTokenKeyId() { return _tokenKeyId; }
export function getNotBefore()  { return _notBefore; }

/**
 * Public key in the format expected by the Privacy Pass issuer directory:
 * base64url-encoded compressed elliptic curve point per RFC 9578 §6.4.
 */
export function getPublicKeyB64Url() {
  return _publicKey.toString('base64url');
}
