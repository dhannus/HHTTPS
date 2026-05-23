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
 *
 * Key rotation (graceful):
 *   The active signing key lives in keys/private.pem + keys/public.pem with a
 *   dated key id in keys/kid.txt (format: hhttps-YYYY-qN). Previously retired
 *   public keys are kept in keys/retired/<kid>.pem and continue to be published
 *   in the JWKS so that tokens signed before a rotation remain verifiable until
 *   they expire. Call rotateKeys() to mint a new active key and retire the old
 *   public key. Nothing is ever silently dropped — retired keys must be removed
 *   manually once no outstanding token could still reference them.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'fs';
import { join, dirname, basename }                                  from 'path';
import { fileURLToPath }                                            from 'url';
import jwt                                                          from 'jsonwebtoken';

const __dirname   = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR    = join(__dirname, 'keys');
const RETIRED_DIR = join(KEYS_DIR, 'retired');

const PRIV_FILE = join(KEYS_DIR, 'private.pem');
const PUB_FILE  = join(KEYS_DIR, 'public.pem');
const KID_FILE  = join(KEYS_DIR, 'kid.txt'); // Key ID — stable, dated identifier

// Active signing key
let _privateKey = null;
let _publicKey  = null;
let _kid        = null;

// Retired public keys still published in the JWKS: Map<kid, KeyObject>
const _retired = new Map();

// ─── Dated key id helper ──────────────────────────────────────────────────────
// Produces a planabler, human-readable id like "hhttps-2026-q2" so operators can
// reason about rotation. A short random suffix guarantees uniqueness if two keys
// are minted in the same quarter.
function makeKid(date = new Date()) {
  const year    = date.getUTCFullYear();
  const quarter = Math.floor(date.getUTCMonth() / 3) + 1;
  const suffix  = Math.random().toString(36).slice(2, 6);
  return `hhttps-${year}-q${quarter}-${suffix}`;
}

// ─── Load retired public keys (if any) ────────────────────────────────────────
function loadRetiredKeys() {
  _retired.clear();
  if (!existsSync(RETIRED_DIR)) return;
  for (const file of readdirSync(RETIRED_DIR)) {
    if (!file.endsWith('.pem')) continue;
    const kid = basename(file, '.pem');
    try {
      _retired.set(kid, createPublicKey(readFileSync(join(RETIRED_DIR, file))));
    } catch {
      // Skip unreadable/foreign files without crashing startup.
    }
  }
}

export function loadOrCreateKeys() {
  mkdirSync(KEYS_DIR, { recursive: true });

  if (existsSync(PRIV_FILE) && existsSync(PUB_FILE) && existsSync(KID_FILE)) {
    // Load existing active key
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

    _kid = makeKid();

    writeFileSync(PRIV_FILE, privateKey, { mode: 0o600 }); // owner-only
    writeFileSync(PUB_FILE,  publicKey,  { mode: 0o644 });
    writeFileSync(KID_FILE,  _kid,       { mode: 0o644 });

    _privateKey = createPrivateKey(privateKey);
    _publicKey  = createPublicKey(publicKey);
    console.log(`   New ES256 key pair generated (kid: ${_kid})`);
  }

  loadRetiredKeys();
  if (_retired.size > 0) {
    console.log(`   ${_retired.size} retired public key(s) still published in JWKS`);
  }
}

// ─── Rotate: mint a new active key, retire the current public key ─────────────
// After rotation, new tokens are signed with the new key while tokens signed
// with the previous key still verify (its public key moves to keys/retired/ and
// stays in the JWKS). Returns { oldKid, newKid }.
export function rotateKeys() {
  if (!_privateKey) loadOrCreateKeys();

  // Retire the current public key
  mkdirSync(RETIRED_DIR, { recursive: true });
  const oldKid    = _kid;
  const oldPubPem = _publicKey.export({ type: 'spki', format: 'pem' });
  writeFileSync(join(RETIRED_DIR, `${oldKid}.pem`), oldPubPem, { mode: 0o644 });
  _retired.set(oldKid, createPublicKey(oldPubPem));

  // Mint a new active key
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding:  { type: 'spki',  format: 'pem' }
  });
  const newKid = makeKid();

  writeFileSync(PRIV_FILE, privateKey, { mode: 0o600 });
  writeFileSync(PUB_FILE,  publicKey,  { mode: 0o644 });
  writeFileSync(KID_FILE,  newKid,     { mode: 0o644 });

  _privateKey = createPrivateKey(privateKey);
  _publicKey  = createPublicKey(publicKey);
  _kid        = newKid;

  console.log(`   Key rotated: ${oldKid} → ${newKid} (old key retired, still in JWKS)`);
  return { oldKid, newKid };
}

// ─── Permanently drop a retired key from the JWKS ─────────────────────────────
// Call only once no outstanding token signed with this kid can still be valid
// (i.e. after at least one full token-TTL has elapsed since rotation).
export function forgetRetiredKey(kid) {
  const file = join(RETIRED_DIR, `${kid}.pem`);
  if (existsSync(file)) {
    // We do not delete on the operator's behalf; we only stop publishing it.
    _retired.delete(kid);
    return true;
  }
  return false;
}

// ─── Sign a JWT with the active private key (ES256) ───────────────────────────
export function signToken(payload, options = {}) {
  return jwt.sign(payload, _privateKey, {
    algorithm: 'ES256',
    keyid:     _kid,
    ...options
  });
}

// ─── Verify a JWT against the active OR any retired public key ────────────────
// Selects the key by the token header's `kid` when present, so verification keeps
// working across a rotation. Falls back to the active key when no kid is given.
export function verifyToken(token) {
  const decodedHeader = jwt.decode(token, { complete: true })?.header || {};
  const kid = decodedHeader.kid;

  let key = _publicKey;
  if (kid && kid !== _kid && _retired.has(kid)) {
    key = _retired.get(kid);
  }
  return jwt.verify(token, key, { algorithms: ['ES256'] });
}

// ─── JWKS JSON for /.well-known/jwks.json ─────────────────────────────────────
// Publishes the active key first, followed by every retired key still in the
// grace period, so third-party verifiers can validate tokens signed before the
// most recent rotation (RFC 7517).
export function getJWKS() {
  const toJwk = (pubKey, kid) => ({
    ...pubKey.export({ format: 'jwk' }),
    use: 'sig',
    alg: 'ES256',
    kid
  });

  const keys = [toJwk(_publicKey, _kid)];
  for (const [kid, pubKey] of _retired) {
    keys.push(toJwk(pubKey, kid));
  }
  return { keys };
}

export function getPublicKey()  { return _publicKey; }
export function getPrivateKey() { return _privateKey; }
export function getKid()        { return _kid; }
export function getRetiredKids() { return [..._retired.keys()]; }
