/**
 * Privacy Pass Key Management — multi-role VOPRF P-384/SHA-384
 *
 * Each HHTTPS role has its own VOPRF key pair, so that a token issued for
 * role X is structurally distinguishable from a token for role Y while
 * preserving per-issuer-key anonymity (every journalist's tokens belong to
 * the same anonymity set, but cannot be linked to tokens of other roles).
 *
 * There is also a "default" issuer for role-less human-only tokens.
 *
 * Persistence layout:
 *   ./keys/default/voprf-private.bin   (default issuer)
 *   ./keys/default/voprf-public.bin
 *   ./keys/default/meta.json
 *   ./keys/r/<role>/voprf-private.bin   (per-role issuer)
 *   ./keys/r/<role>/voprf-public.bin
 *   ./keys/r/<role>/meta.json
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname }                                       from 'path';
import { fileURLToPath }                                       from 'url';
import { createHash }                                          from 'crypto';

import { Oprf, generateKeyPair } from '@cloudflare/voprf-ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR  = join(__dirname, 'keys');

export const TOKEN_TYPE = 0x0002;
export const SUITE      = Oprf.Suite.P384_SHA384;
export const SUITE_NAME = 'P384-SHA384';
export const MODE       = Oprf.Mode.VOPRF;
export const Ne         = 49;
export const Ns         = 48;

// HHTTPS roles that get their own issuer key. The default issuer (no role) is
// always present in addition. To add a new role, just add it here — the next
// server start will generate the key automatically and persist it.
export const ROLES = [
  'citizen', 'journalist', 'student', 'teacher', 'researcher', 'creative',
  'developer', 'medical_professional', 'caregiver', 'lawyer', 'notary',
  'civil_servant', 'politician', 'business', 'craftsman',
];

// In-memory registry of all issuers, keyed by role name (or 'default')
const _issuers = new Map();

function issuerDir(role) {
  return role === 'default' ? join(KEYS_DIR, 'default') : join(KEYS_DIR, 'r', role);
}

async function loadOrCreateOne(role) {
  const dir      = issuerDir(role);
  const privFile = join(dir, 'voprf-private.bin');
  const pubFile  = join(dir, 'voprf-public.bin');
  const metaFile = join(dir, 'meta.json');

  mkdirSync(dir, { recursive: true });

  if (existsSync(privFile) && existsSync(pubFile) && existsSync(metaFile)) {
    const priv = readFileSync(privFile);
    const pub  = readFileSync(pubFile);
    const meta = JSON.parse(readFileSync(metaFile, 'utf8'));
    const issuer = {
      role,
      privateKey: priv,
      publicKey:  pub,
      tokenKeyId: Buffer.from(meta.tokenKeyId, 'base64'),
      notBefore:  meta.notBefore,
    };
    _issuers.set(role, issuer);
    console.log(`   [PRIVACY-PASS] role=${role} keys loaded from disk`);
    return issuer;
  }

  const kp        = await generateKeyPair(SUITE);
  const priv      = Buffer.from(kp.privateKey);
  const pub       = Buffer.from(kp.publicKey);
  const keyId     = createHash('sha256').update(pub).digest();
  const notBefore = Math.floor(Date.now() / 1000);

  writeFileSync(privFile, priv, { mode: 0o600 });
  writeFileSync(pubFile,  pub,  { mode: 0o644 });
  writeFileSync(metaFile, JSON.stringify({
    role,
    tokenType:  TOKEN_TYPE,
    suite:      SUITE_NAME,
    mode:       'VOPRF',
    tokenKeyId: keyId.toString('base64'),
    notBefore,
  }, null, 2), { mode: 0o644 });

  const issuer = { role, privateKey: priv, publicKey: pub, tokenKeyId: keyId, notBefore };
  _issuers.set(role, issuer);
  console.log(`   [PRIVACY-PASS] role=${role} new VOPRF ${SUITE_NAME} key pair generated`);
  return issuer;
}

export async function loadOrCreateKeys() {
  mkdirSync(KEYS_DIR, { recursive: true });
  // Default issuer (role-less, "human only")
  await loadOrCreateOne('default');
  // One issuer per role
  for (const r of ROLES) {
    await loadOrCreateOne(r);
  }
  console.log(`   [PRIVACY-PASS] ${_issuers.size} issuers ready (1 default + ${ROLES.length} role-specific)`);
}

/**
 * Return the issuer descriptor for a given role.
 * Pass 'default' (or no argument) for the role-less issuer.
 * Throws if the role is unknown.
 */
export function getIssuer(role = 'default') {
  const i = _issuers.get(role);
  if (!i) throw new Error(`Unknown issuer role: ${role}`);
  return i;
}

export function listIssuers() {
  return Array.from(_issuers.keys());
}

export function truncatedKeyId(role = 'default') {
  const i = getIssuer(role);
  return i.tokenKeyId[i.tokenKeyId.length - 1];
}

export function getPublicKeyB64Url(role = 'default') {
  return getIssuer(role).publicKey.toString('base64url');
}

/**
 * Find an issuer by the truncated_token_key_id contained in a TokenRequest.
 * Returns the issuer descriptor or null.
 *
 * Used by the issuer endpoint to figure out which key to use without the
 * caller having to specify the role explicitly when sending an RFC-format
 * TokenRequest.
 */
export function findIssuerByTruncatedKeyId(truncated) {
  for (const issuer of _issuers.values()) {
    if (issuer.tokenKeyId[issuer.tokenKeyId.length - 1] === truncated) {
      return issuer;
    }
  }
  return null;
}
