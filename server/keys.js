/**
 * HHTTPS Key Management — ES256 (ECDSA P-256)
 *
 * Generates a persistent EC key pair on first run.
 * Keys are saved to ./keys/ and reloaded on restart — tokens remain valid.
 * The public key is exposed via /.well-known/jwks.json so external services
 * can verify HHTTPS tokens without calling our API (true federation).
 *
 * Why ES256 instead of HS256?
 *   HS256 (symmetric): only this server can verify → all consumers must call /validate
 *   ES256 (asymmetric): anyone with public key can verify → scales, federates, offline-verifiable
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync }      from 'fs';
import { join, dirname }                                            from 'path';
import { fileURLToPath }                                            from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR  = join(__dirname, 'keys');

const PRIV_FILE = join(KEYS_DIR, 'private.pem');
const PUB_FILE  = join(KEYS_DIR, 'public.pem');
const KID_FILE  = join(KEYS_DIR, 'kid.txt'); // Key ID — stable identifier

let _privateKey = null;
let _publicKey  = null;
let _kid        = null;

export function loadOrCreateKeys() {
  mkdirSync(KEYS_DIR, { recursive: true });

  if (existsSync(PRIV_FILE) && existsSync(PUB_FILE) && existsSync(KID_FILE)) {
    // Load existing keys
    _privateKey = createPrivateKey(readFileSync(PRIV_FILE));
    _publicKey  = createPublicKey(readFileSync(PUB_FILE));
    _kid        = readFileSync(KID_FILE, 'utf8').trim();
    console.log(`   Keys loaded from disk (kid: ${_kid})`);
  } else {
    // Generate fresh key pair
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding:  { type: 'spki',  format: 'pem' }
    });

    _kid = Math.random().toString(36).slice(2, 10); // short stable ID

    writeFileSync(PRIV_FILE, privateKey,     { mode: 0o600 }); // owner-only
    writeFileSync(PUB_FILE,  publicKey,      { mode: 0o644 });
    writeFileSync(KID_FILE,  _kid,           { mode: 0o644 });

    _privateKey = createPrivateKey(privateKey);
    _publicKey  = createPublicKey(publicKey);
    console.log(`   New ES256 key pair generated (kid: ${_kid})`);
  }
}

// ─── Sign a JWT with the private key (ES256) ──────────────────────────────────
import jwt from 'jsonwebtoken';

export function signToken(payload, options = {}) {
  return jwt.sign(payload, _privateKey, {
    algorithm: 'ES256',
    keyid:     _kid,
    ...options
  });
}

// ─── Verify a JWT with the public key ─────────────────────────────────────────
export function verifyToken(token) {
  return jwt.verify(token, _publicKey, { algorithms: ['ES256'] });
}

// ─── JWKS JSON for /.well-known/jwks.json ─────────────────────────────────────
export function getJWKS() {
  const jwk = _publicKey.export({ format: 'jwk' });
  return {
    keys: [{
      ...jwk,
      use: 'sig',
      alg: 'ES256',
      kid: _kid
    }]
  };
}

export function getPublicKey()  { return _publicKey; }
export function getPrivateKey() { return _privateKey; }
export function getKid()        { return _kid; }
