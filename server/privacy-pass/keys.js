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
 * Token Type 0x0002 (privately verifiable, VOPRF-based) is chosen for the MVP
 * because it requires less key infrastructure than 0x0001 (Blind RSA) and is
 * sufficient for single-issuer deployments. 0x0001 can be added later for
 * federation.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname }                                       from 'path';
import { fileURLToPath }                                       from 'url';
import { createHash, randomBytes }                             from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR  = join(__dirname, 'keys');

const PRIV_FILE = join(KEYS_DIR, 'voprf-private.bin');
const PUB_FILE  = join(KEYS_DIR, 'voprf-public.bin');
const META_FILE = join(KEYS_DIR, 'meta.json');

// Token Type 0x0002 — VOPRF(P-384, SHA-384) per RFC 9578 §6
export const TOKEN_TYPE = 0x0002;
export const SUITE_NAME = 'P384-SHA384';

let _privateKey = null;  // 48-byte scalar
let _publicKey  = null;  // 49-byte compressed EC point
let _tokenKeyId = null;  // SHA-256(public_key), 32 bytes
let _notBefore  = null;  // Unix seconds

/**
 * Compute the truncated_token_key_id used in TokenRequest per RFC 9578 §6.1.
 * This is the least significant byte of the SHA-256 of the public key.
 */
export function truncatedKeyId() {
  return _tokenKeyId[_tokenKeyId.length - 1];
}

/**
 * Generate a fresh VOPRF P-384 key pair using the @cloudflare/voprf-ts library.
 * This function is async because the library's KeyGen is async.
 *
 * NOTE: This is a placeholder implementation. The real VOPRF KeyGen requires
 * the library. Until the library is wired up, we generate placeholder bytes
 * that are correctly sized but cryptographically invalid. The well-known
 * endpoint will still work for discovery testing.
 */
async function generateVoprfKeyPair() {
  // TODO: Replace with real VOPRF KeyGen once @cloudflare/voprf-ts is installed.
  //
  // Real implementation will look like:
  //
  //   import { Oprf, generateKeyPair } from '@cloudflare/voprf-ts';
  //   const suite = Oprf.Suite.P384_SHA384;
  //   const mode  = Oprf.Mode.VOPRF;
  //   const { privateKey, publicKey } = await generateKeyPair(suite, mode);
  //   return { privateKey, publicKey };

  // Placeholder bytes — DO NOT USE FOR REAL ISSUANCE.
  // 48-byte scalar (P-384 private key size), 49-byte compressed point (public).
  console.warn('   [PRIVACY-PASS] Generating PLACEHOLDER keys. Real VOPRF KeyGen pending.');
  return {
    privateKey: randomBytes(48),
    publicKey:  Buffer.concat([Buffer.from([0x03]), randomBytes(48)]),  // compressed marker
  };
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
    const { privateKey, publicKey } = await generateVoprfKeyPair();

    _privateKey = privateKey;
    _publicKey  = publicKey;
    _tokenKeyId = createHash('sha256').update(_publicKey).digest();
    _notBefore  = Math.floor(Date.now() / 1000);

    writeFileSync(PRIV_FILE, _privateKey, { mode: 0o600 });
    writeFileSync(PUB_FILE,  _publicKey,  { mode: 0o644 });
    writeFileSync(META_FILE, JSON.stringify({
      tokenType:  TOKEN_TYPE,
      suite:      SUITE_NAME,
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
