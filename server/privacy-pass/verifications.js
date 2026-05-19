/**
 * Privacy Pass verifications: attribute storage and email verification flow.
 *
 * Email handling is hash-only. We compute SHA-256(lowercased email + salt) and
 * store the hash, never the plaintext. The salt is ENV-configurable; if not
 * set, falls back to a hardcoded constant (operational note: rotate the salt
 * carefully — any rotation invalidates all existing email_hash matches).
 */

import crypto from 'crypto';
import { ROLE_REQUIREMENTS, checkEligibility, computeTrustScore, emailDomainMatchesRole } from './role-requirements.js';
import { ROLES, VERIFICATION_LEVELS } from '../roles.js';

const EMAIL_SALT = process.env.HHTTPS_EMAIL_HASH_SALT || 'hhttps-pp-v1-email-hash-salt';

export function hashEmail(email) {
  const normalized = email.trim().toLowerCase();
  return crypto.createHash('sha256').update(EMAIL_SALT + ':' + normalized).digest('hex');
}

export function emailDomain(email) {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1).toLowerCase() : '';
}

// ─── Attribute verifications ─────────────────────────────────────────────────

export async function listVerifications(credentialId, role) {
  const db = await import('../db.js');
  const { rows } = await db.pool().query(
    `SELECT method, email_domain, trust_score, verified_at
       FROM pp_attribute_verifications
      WHERE credential_id = $1
        AND role          = $2
        AND revoked_at    IS NULL`,
    [credentialId, role]
  );
  return rows;
}

export async function recordVerification(credentialId, role, method, opts = {}) {
  const db = await import('../db.js');
  const trustScore = VERIFICATION_LEVELS[method]?.trustScore ?? 30;

  await db.pool().query(
    `INSERT INTO pp_attribute_verifications
       (credential_id, role, method, email_hash, email_domain, attribute_data, trust_score)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (credential_id, role, method) DO UPDATE
       SET email_hash     = EXCLUDED.email_hash,
           email_domain   = EXCLUDED.email_domain,
           attribute_data = EXCLUDED.attribute_data,
           trust_score    = EXCLUDED.trust_score,
           verified_at    = NOW(),
           revoked_at     = NULL`,
    [
      credentialId,
      role,
      method,
      opts.emailHash    ?? null,
      opts.emailDomain  ?? null,
      opts.data ? JSON.stringify(opts.data) : null,
      trustScore,
    ]
  );
}

export async function eligibilityFor(credentialId, role) {
  // WebAuthn is implicit — they got here, so they have webauthn.
  const completed = ['webauthn'];

  const verifications = await listVerifications(credentialId, role);
  for (const v of verifications) {
    if (!completed.includes(v.method)) completed.push(v.method);
  }

  const result = checkEligibility(role, completed);
  return {
    ...result,
    completed,
    trustScore: result.ok ? result.trustScore : computeTrustScore(completed),
    requirements: ROLE_REQUIREMENTS[role] || null,
  };
}

// ─── Email verification flow ─────────────────────────────────────────────────

const EMAIL_VERIFY_TTL_MS = 15 * 60 * 1000;  // 15 minutes

export async function createEmailPending({ credentialId, role, email, method, domain }) {
  const db = await import('../db.js');
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  await db.pool().query(
    `INSERT INTO pp_email_pending
       (token_hash, credential_id, role, email_hash, email_domain, method, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '15 minutes')`,
    [tokenHash, credentialId, role, hashEmail(email), domain, method]
  );

  return { rawToken, expiresInMs: EMAIL_VERIFY_TTL_MS };
}

export async function consumeEmailPending(rawToken) {
  const db = await import('../db.js');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  const { rows } = await db.pool().query(
    `DELETE FROM pp_email_pending
      WHERE token_hash = $1
        AND expires_at > NOW()
      RETURNING credential_id, role, email_hash, email_domain, method`,
    [tokenHash]
  );

  if (rows.length === 0) return null;
  return rows[0];
}

// ─── Recovery codes ──────────────────────────────────────────────────────────

const RECOVERY_CODE_COUNT  = 10;
const RECOVERY_CODE_LENGTH = 10;  // base32 characters → ~50 bits entropy

function generateRecoveryCode() {
  // Crockford base32 (no I, L, O, U) to avoid ambiguous chars
  const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const bytes = crypto.randomBytes(RECOVERY_CODE_LENGTH);
  let s = '';
  for (let i = 0; i < RECOVERY_CODE_LENGTH; i++) {
    s += ALPHABET[bytes[i] % ALPHABET.length];
    if (i === 4) s += '-';
  }
  return s;
}

export function hashRecoveryCode(code) {
  return crypto.createHash('sha256').update(code.toUpperCase().replace(/-/g, '')).digest('hex');
}

export async function generateRecoveryCodesForUser(userId) {
  const db = await import('../db.js');
  const codes = [];

  // Invalidate any unused existing codes for this user first
  await db.pool().query(
    `DELETE FROM pp_recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
    [userId]
  );

  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const c = generateRecoveryCode();
    codes.push(c);
    await db.pool().query(
      `INSERT INTO pp_recovery_codes (code_hash, user_id) VALUES ($1, $2)`,
      [hashRecoveryCode(c), userId]
    );
  }
  return codes;
}

export async function consumeRecoveryCode(rawCode, fromIp = null) {
  const db = await import('../db.js');
  const codeHash = hashRecoveryCode(rawCode);

  const { rows } = await db.pool().query(
    `UPDATE pp_recovery_codes
        SET used_at = NOW(), used_from_ip = $2
      WHERE code_hash = $1
        AND used_at IS NULL
      RETURNING user_id`,
    [codeHash, fromIp]
  );

  if (rows.length === 0) return null;
  return rows[0].user_id;
}

export async function countRemainingRecoveryCodes(userId) {
  const db = await import('../db.js');
  const { rows } = await db.pool().query(
    `SELECT COUNT(*)::int AS n FROM pp_recovery_codes
      WHERE user_id = $1 AND used_at IS NULL`,
    [userId]
  );
  return rows[0]?.n || 0;
}

// ─── Admin allowlist ─────────────────────────────────────────────────────────

const ADMIN_CREDENTIALS = (process.env.HHTTPS_ADMIN_CREDENTIALS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

export function isAdminCredential(credentialId) {
  return ADMIN_CREDENTIALS.includes(credentialId);
}

export function adminCredentialCount() {
  return ADMIN_CREDENTIALS.length;
}
