/**
 * HHTTPS v4.1 — Database Access Layer
 *
 * Replaces all in-memory Maps with PostgreSQL-backed persistence.
 * Uses connection pooling for performance and prepared statements for safety.
 *
 * Required environment variables (from .env):
 *   DB_HOST     — default: localhost
 *   DB_PORT     — default: 5432
 *   DB_NAME     — default: hhttps
 *   DB_USER     — default: hhttps
 *   DB_PASSWORD — required
 *
 * The pool is shared across all queries. Reconnects automatically.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
const { Pool } = pg;

const SQL_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'sql');

let _pool = null;

export function init() {
  if (_pool) return _pool;

  _pool = new Pool({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME     || 'hhttps',
    user:     process.env.DB_USER     || 'hhttps',
    password: process.env.DB_PASSWORD,
    max:                20,           // pool size
    idleTimeoutMillis:  30000,
    connectionTimeoutMillis: 5000
  });

  _pool.on('error', (err) => {
    console.error('[DB] Unexpected pool error:', err.message);
  });

  return _pool;
}

export function pool() { return _pool || init(); }

// Convenience query wrapper with logging on errors
export async function q(text, params = []) {
  try {
    const result = await pool().query(text, params);
    return result;
  } catch (err) {
    console.error(`[DB] Query failed: ${err.message}`);
    console.error(`[DB] SQL: ${text}`);
    throw err;
  }
}

// ─── CREDENTIALS ──────────────────────────────────────────────────────────────

export const credentials = {
  async create({ credentialId, userId, publicKey, counter, transports, deviceType, backedUp }) {
    await q(
      `INSERT INTO credentials (credential_id, user_id, public_key, counter, transports, device_type, backed_up)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [credentialId, userId, publicKey, counter, transports || [], deviceType, backedUp]
    );
  },

  async get(credentialId) {
    const { rows } = await q(`SELECT * FROM credentials WHERE credential_id = $1`, [credentialId]);
    return rows[0] ? this._normalize(rows[0]) : null;
  },

  async findByUserId(userId) {
    const { rows } = await q(`SELECT * FROM credentials WHERE user_id = $1`, [userId]);
    return rows.map(r => this._normalize(r));
  },

  async updateCounter(credentialId, counter) {
    await q(
      `UPDATE credentials SET counter = $1, last_used_at = NOW() WHERE credential_id = $2`,
      [counter, credentialId]
    );
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM credentials`);
    return rows[0].n;
  },

  _normalize(r) {
    return {
      credentialId:        r.credential_id,
      userId:              r.user_id,
      credentialPublicKey: r.public_key,        // BYTEA → Buffer
      counter:             Number(r.counter),
      transports:          r.transports || [],
      deviceType:          r.device_type,
      backedUp:            r.backed_up,
      registeredAt:        r.registered_at
    };
  }
};

// ─── CHALLENGES ───────────────────────────────────────────────────────────────

export const challenges = {
  async create(challengeId, challenge, userId, context, ttlMs = 120_000) {
    await q(
      `INSERT INTO challenges (challenge_id, challenge, user_id, context, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + ($5 || ' milliseconds')::interval)
       ON CONFLICT (challenge_id) DO UPDATE SET
         challenge = EXCLUDED.challenge,
         user_id = EXCLUDED.user_id,
         context = EXCLUDED.context,
         expires_at = EXCLUDED.expires_at,
         created_at = NOW()`,
      [challengeId, challenge, userId, context, ttlMs]
    );
  },

  async get(challengeId) {
    const { rows } = await q(
      `SELECT challenge, user_id, expires_at FROM challenges
       WHERE challenge_id = $1 AND expires_at > NOW()`,
      [challengeId]
    );
    if (!rows[0]) return null;
    return {
      challenge: rows[0].challenge,
      userId:    rows[0].user_id,
      expires:   new Date(rows[0].expires_at).getTime()
    };
  },

  async delete(challengeId) {
    await q(`DELETE FROM challenges WHERE challenge_id = $1`, [challengeId]);
  }
};

// ─── SESSIONS ─────────────────────────────────────────────────────────────────

export const sessions = {
  async create(sessionId, data, ttlMs = 600_000) {
    // Phase 8 (P-4/W-4): `pseudonym` is written on INSERT (D3: it travels
    // anchor → session → token) — no follow-up UPDATE needed.
    await q(
      `INSERT INTO sessions (
        session_id, user_id, credential_id, device_type, backed_up,
        verified, trust_score, pseudonym, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + ($9 || ' milliseconds')::interval)`,
      [
        sessionId, data.userId, data.credentialId, data.deviceType, data.backedUp,
        data.verified !== false, data.trustScore || 60, data.pseudonym || null, ttlMs
      ]
    );
  },

  async get(sessionId) {
    const { rows } = await q(
      `SELECT * FROM sessions WHERE session_id = $1 AND expires_at > NOW()`,
      [sessionId]
    );
    return rows[0] ? this._normalize(rows[0]) : null;
  },

  async update(sessionId, patch) {
    const allowedColumns = {
      emailVerified:   'email_verified',
      emailLevel:      'email_level',
      emailDomain:     'email_domain',
      emailTrustBonus: 'email_trust_bonus',
      emailCategory:   'email_category',
      emailsSent:      'emails_sent',
      githubVerified:    'github_verified',
      githubTrustBonus:  'github_trust_bonus',
      role:            'role',
      roleLevel:       'role_level',
      trustScore:      'trust_score',
      // Phase 8: rebinding the session to the stable identity anchor (D2)
      userId:          'user_id',
      pseudonym:       'pseudonym'
    };
    const sets = []; const vals = []; let i = 1;
    for (const [k, v] of Object.entries(patch)) {
      const col = allowedColumns[k];
      if (col) { sets.push(`${col} = $${i}`); vals.push(v); i++; }
    }
    if (!sets.length) return;
    vals.push(sessionId);
    await q(`UPDATE sessions SET ${sets.join(', ')} WHERE session_id = $${i}`, vals);
  },

  async incrementEmailsSent(sessionId) {
    const { rows } = await q(
      `UPDATE sessions SET emails_sent = emails_sent + 1 WHERE session_id = $1
       RETURNING emails_sent`, [sessionId]
    );
    return rows[0]?.emails_sent || 0;
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM sessions WHERE expires_at > NOW()`);
    return rows[0].n;
  },

  _normalize(r) {
    return {
      sessionId:       r.session_id,
      userId:          r.user_id,
      credentialId:    r.credential_id,
      deviceType:      r.device_type,
      backedUp:        r.backed_up,
      verified:        r.verified,
      emailVerified:   r.email_verified,
      emailLevel:      r.email_level,
      emailDomain:     r.email_domain,
      emailTrustBonus: r.email_trust_bonus,
      emailCategory:   r.email_category,
      emailsSent:      r.emails_sent,
      githubVerified:   r.github_verified,
      githubTrustBonus: r.github_trust_bonus,
      role:            r.role,
      roleLevel:       r.role_level,
      trustScore:      r.trust_score,
      pseudonym:       r.pseudonym ?? null,
      expires:         new Date(r.expires_at).getTime()
    };
  }
};

// ─── TOKENS ───────────────────────────────────────────────────────────────────

export const tokens = {
  async create({ jti, type, userId, role, roleLevel, trustScore, method, deviceType, operatorId, ttlMs }) {
    await q(
      `INSERT INTO tokens (jti, type, user_id, role, role_level, trust_score, method, device_type, operator_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + ($10 || ' milliseconds')::interval)`,
      [jti, type, userId, role, roleLevel, trustScore, method, deviceType, operatorId, ttlMs]
    );
  },

  async exists(jti) {
    const { rows } = await q(
      `SELECT 1 FROM tokens WHERE jti = $1 AND expires_at > NOW()`, [jti]
    );
    return rows.length > 0;
  },

  async get(jti) {
    const { rows } = await q(`SELECT * FROM tokens WHERE jti = $1 AND expires_at > NOW()`, [jti]);
    return rows[0] || null;
  },

  async delete(jti) {
    await q(`DELETE FROM tokens WHERE jti = $1`, [jti]);
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM tokens WHERE expires_at > NOW()`);
    return rows[0].n;
  }
};

// ─── REFRESH TOKENS ───────────────────────────────────────────────────────────

export const refreshTokens = {
  async create({ jti, userId, credentialId, role, ttlMs }) {
    await q(
      `INSERT INTO refresh_tokens (jti, user_id, credential_id, role, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + ($5 || ' milliseconds')::interval)`,
      [jti, userId, credentialId, role, ttlMs]
    );
  },

  async get(jti) {
    const { rows } = await q(
      `SELECT * FROM refresh_tokens WHERE jti = $1 AND expires_at > NOW()`, [jti]
    );
    return rows[0] || null;
  },

  async delete(jti) {
    await q(`DELETE FROM refresh_tokens WHERE jti = $1`, [jti]);
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM refresh_tokens WHERE expires_at > NOW()`);
    return rows[0].n;
  }
};

// ─── REVOKED TOKENS ───────────────────────────────────────────────────────────

export const revokedTokens = {
  async add(jti, role, reason) {
    await q(
      `INSERT INTO revoked_tokens (jti, role, reason) VALUES ($1, $2, $3)
       ON CONFLICT (jti) DO NOTHING`,
      [jti, role, reason || null]
    );
  },

  async has(jti) {
    const { rows } = await q(`SELECT 1 FROM revoked_tokens WHERE jti = $1`, [jti]);
    return rows.length > 0;
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM revoked_tokens`);
    return rows[0].n;
  }
};

// ─── EMAIL VERIFICATIONS ──────────────────────────────────────────────────────

export const emailVerifications = {
  // The `code` column holds the sha256 of the 6-digit verification code that
  // the user types into the original tab. It coexists with `token` (used by
  // the legacy magic-link fallback at the bottom of the email). One ALTER
  // is run on boot — see ensureSchema below.
  async create({ token, code, email, domain, level, trustBonus, category, sessionId, ttlMs = 900_000 }) {
    await q(
      `INSERT INTO email_verifications (token, code, email, domain, level, trust_bonus, category, session_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + ($9 || ' milliseconds')::interval)`,
      [token, code || null, email, domain, level, trustBonus, category, sessionId, ttlMs]
    );
  },

  // Magic-link path (legacy fallback). Consumes by token only.
  async getAndConsume(token) {
    const { rows } = await q(
      `UPDATE email_verifications SET used = TRUE
       WHERE token = $1 AND used = FALSE AND expires_at > NOW()
       RETURNING *`,
      [token]
    );
    return rows[0] || null;
  },

  // F-1 (K-1): a re-send in the same session invalidates every older open
  // row of that session, so a code/token for address A can never be played
  // against a context that meanwhile points to address B.
  async invalidateForSession(sessionId) {
    await q(
      `UPDATE email_verifications SET used = TRUE
       WHERE session_id = $1 AND used = FALSE`,
      [sessionId]
    );
  },

  // Code path (primary). Binds to session_id as defence-in-depth: a code
  // posted from a different browser/session cannot consume the row.
  async getAndConsumeByCode(codeHash, sessionId) {
    const { rows } = await q(
      `UPDATE email_verifications SET used = TRUE
       WHERE code = $1 AND session_id = $2 AND used = FALSE AND expires_at > NOW()
       RETURNING *`,
      [codeHash, sessionId]
    );
    return rows[0] || null;
  }
};

// Ensure the `code` column exists. Idempotent, fires once on import.
// Lives next to emailVerifications so the schema stays close to the code
// that uses it.
let _codeColumnEnsured = false;
async function ensureCodeColumn() {
  if (_codeColumnEnsured) return;
  try {
    await q(`ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS code TEXT`);
    _codeColumnEnsured = true;
  } catch (e) {
    console.error('[db] ensureCodeColumn:', e.message);
  }
}
// Fire-and-forget on module load — pg client is already initialised.
ensureCodeColumn().catch(() => {});

// ─── BOOT-DDL MIGRATIONS ──────────────────────────────────────────────────────
//
// Some migration files under sql/ are applied by the server itself at boot
// (F-7 / K-6 / P-2): only their DDL section (tables / columns / indexes,
// idempotent), only when an applied-check shows the schema is missing, and
// main() awaits the whole list before listening. Operator sections (data
// updates, grants) are never run automatically.
//
// Phase 8: sql/migration-phase-8-email-anchored-identity.sql is the single
// reference (for operators AND for the boot). The file has two sections
// separated by the marker below: BOOT-DDL above it, OPERATOR below it.
const PHASE8_MIGRATION_FILE = 'migration-phase-8-email-anchored-identity.sql';
const PHASE8_BOOT_DDL_END   = '-- >>> BOOT-DDL END';

/** The DDL-only section of the phase-8 migration file (everything above the marker). */
export function phase8BootDdl() {
  return bootDdlOf({ file: PHASE8_MIGRATION_FILE, endMarker: PHASE8_BOOT_DDL_END });
}

/** true when the phase-8 DDL is already present (last column added + cache table). */
export async function phase8SchemaApplied() {
  const { rows } = await q(
    `SELECT
       EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name = 'authorization_codes' AND column_name = 'verified_methods') AS col,
       to_regclass('identity_claims_cache') IS NOT NULL AS tbl`
  );
  return rows[0]?.col === true && rows[0]?.tbl === true;
}

/** true when authorization_codes.state/nonce/pkce_challenge are already TEXT (#31). */
export async function authCodesTextApplied() {
  const { rows } = await q(
    `SELECT count(*)::int AS n FROM information_schema.columns
      WHERE table_name = 'authorization_codes'
        AND column_name IN ('state', 'nonce', 'pkce_challenge')
        AND data_type = 'text'`
  );
  return rows[0]?.n === 3;
}

/**
 * Boot-DDL list, in apply order. Each entry: the file under sql/, optionally
 * an `endMarker` (only the text above it is run), and an applied-check —
 * either a list of [table, column] pairs that must all exist, or a custom
 * `applied()` predicate.
 */
export const BOOT_DDL_FILES = [
  { file: PHASE8_MIGRATION_FILE, endMarker: PHASE8_BOOT_DDL_END, applied: phase8SchemaApplied,
    note: 'DDL only — run the OPERATOR section of the migration file for the data update' },
  // #7: machineOperators.create writes key_jkt; the column never had a migration.
  { file: 'migration-phase-4b-machine-key-jkt.sql', columns: [['machine_operators', 'key_jkt']] },
  // #31: state/nonce/pkce_challenge were VARCHAR(128); longer client values broke the login.
  { file: 'migration-phase-3a1-authcodes-text.sql', applied: authCodesTextApplied },
];

function bootDdlOf({ file, endMarker }) {
  const text = fs.readFileSync(path.join(SQL_DIR, file), 'utf8');
  if (!endMarker) return text;
  const idx = text.indexOf(endMarker);
  if (idx < 0) throw new Error(`[db] ${file}: marker "${endMarker}" not found`);
  return text.slice(0, idx);
}

async function columnsExist(pairs) {
  for (const [table, column] of pairs) {
    const { rows } = await q(
      `SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
      [table, column]
    );
    if (!rows.length) return false;
  }
  return true;
}

async function bootDdlApplied(entry) {
  if (entry.applied) return entry.applied();
  return columnsExist(entry.columns || []);
}

// Memoised: returns the same promise on repeated calls; a failure clears the
// memo so an explicit retry is possible. NOT started on import — the caller
// (server.js main) awaits it explicitly.
let _bootReady = null;
export function ensureBootSchema() {
  if (_bootReady) return _bootReady;
  _bootReady = (async () => {
    try {
      for (const entry of BOOT_DDL_FILES) {
        if (await bootDdlApplied(entry)) continue;
        // pg sends a parameter-less query over the simple protocol, which allows
        // several statements in one round trip.
        await q(bootDdlOf(entry));
        console.log(`[db] boot schema applied: ${entry.file}${entry.note ? ` (${entry.note})` : ''}`);
      }
    } catch (e) {
      console.error('[db] ensureBootSchema:', e.message);
      _bootReady = null;
      throw e;
    }
  })();
  return _bootReady;
}

/** Backwards-compatible name: runs the whole boot-DDL list (phase 8 included). */
export const ensurePhase8Schema = ensureBootSchema;

// identity_anchors: HMAC(email) → stable user_id + pseudonym (D1/D2/D3)
export const identityAnchors = {
  /**
   * Atomic resolve-or-create. On a fresh hash the given userId/pseudonym are
   * stored and `created` is true. If the anchor already exists, ONLY
   * last_seen_at is touched and the STORED userId/pseudonym are returned
   * (`created: false`) — the caller must rebind the session to them (AK-2/8).
   */
  async resolveOrCreate({ emailHash, userId, pseudonym }) {
    let rows;
    try {
      ({ rows } = await q(
        `INSERT INTO identity_anchors (email_hash, user_id, pseudonym)
         VALUES ($1, $2, $3)
         ON CONFLICT (email_hash) DO UPDATE SET last_seen_at = NOW()
         RETURNING user_id, pseudonym, (xmax = 0) AS created`,
        [emailHash, userId, pseudonym]
      ));
    } catch (e) {
      // F-6 (K-5/S-6): ON CONFLICT covers email_hash only. A UNIQUE(user_id)
      // violation means this userId is already anchored to ANOTHER address —
      // surface it as a typed conflict, not as a generic 500.
      if (e.code === '23505') {
        const err = new Error('email_already_bound');
        err.code = 'email_already_bound';
        err.status = 409;
        throw err;
      }
      throw e;
    }
    const r = rows[0];
    return { userId: r.user_id, pseudonym: r.pseudonym, created: r.created === true };
  },

  async getByUserId(userId) {
    const { rows } = await q(`SELECT * FROM identity_anchors WHERE user_id = $1`, [userId]);
    return rows[0] ? this._normalize(rows[0]) : null;
  },

  _normalize(r) {
    return {
      emailHash:  r.email_hash,
      userId:     r.user_id,
      pseudonym:  r.pseudonym,
      createdAt:  r.created_at,
      lastSeenAt: r.last_seen_at
    };
  }
};

// identity_claims_cache: plaintext email + pseudonym + verified_methods per
// user_id, kept until transferred to the platform, expiring after ≤ 7 days (D5)
export const identityClaimsCache = {
  async upsert({ userId, email, pseudonym, verifiedMethods, ttlMs = 7 * 24 * 3600 * 1000 }) {
    await q(
      `INSERT INTO identity_claims_cache (user_id, email, pseudonym, verified_methods, updated_at, expires_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW() + ($5 || ' milliseconds')::interval)
       ON CONFLICT (user_id) DO UPDATE SET
         email            = EXCLUDED.email,
         pseudonym        = EXCLUDED.pseudonym,
         verified_methods = EXCLUDED.verified_methods,
         updated_at       = NOW(),
         expires_at       = EXCLUDED.expires_at`,
      [userId, email, pseudonym || null, JSON.stringify(verifiedMethods || []), ttlMs]
    );
  },

  /** @returns {{userId, email, pseudonym, verifiedMethods: string[]}|null} null if missing or expired */
  async get(userId) {
    const { rows } = await q(
      `SELECT user_id, email, pseudonym, verified_methods
       FROM identity_claims_cache WHERE user_id = $1 AND expires_at > NOW()`,
      [userId]
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      userId:          r.user_id,
      email:           r.email,
      pseudonym:       r.pseudonym,
      verifiedMethods: parseJsonArray(r.verified_methods)
    };
  }
};

function parseJsonArray(text) {
  if (!text) return [];
  try {
    const v = JSON.parse(text);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

// ─── ROLES DECLARED ───────────────────────────────────────────────────────────

export const rolesDeclared = {
  async upsert(userId, role, roleLevel, trustScore) {
    await q(
      `INSERT INTO roles_declared (user_id, role, role_level, trust_score)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE SET
         role = EXCLUDED.role, role_level = EXCLUDED.role_level,
         trust_score = EXCLUDED.trust_score, updated_at = NOW()`,
      [userId, role, roleLevel, trustScore]
    );
  },

  async get(userId) {
    const { rows } = await q(`SELECT * FROM roles_declared WHERE user_id = $1`, [userId]);
    return rows[0] || null;
  },

  async distribution() {
    const { rows } = await q(
      `SELECT role, COUNT(*)::int AS n FROM roles_declared GROUP BY role ORDER BY n DESC`
    );
    return rows;
  }
};

// ─── MACHINE OPERATORS ────────────────────────────────────────────────────────

export const machineOperators = {
  async create({ operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash, role, roleLabel, roleIcon, keyJkt }) {
    await q(
      `INSERT INTO machine_operators (operator_id, operator_name, operator_url, purpose, contact_email, api_key_hash, role, role_label, role_icon, key_jkt)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash, role || null, roleLabel || null, roleIcon || null, keyJkt || null]
    );
  },

  async get(operatorId) {
    const { rows } = await q(
      `SELECT * FROM machine_operators WHERE operator_id = $1 AND active = TRUE`,
      [operatorId]
    );
    return rows[0] || null;
  },

  async incrementTokensIssued(operatorId) {
    await q(
      `UPDATE machine_operators SET tokens_issued = tokens_issued + 1, last_used_at = NOW()
       WHERE operator_id = $1`, [operatorId]
    );
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM machine_operators WHERE active = TRUE`);
    return rows[0].n;
  }
};

// ─── WEBHOOKS ─────────────────────────────────────────────────────────────────

export const webhooks = {
  async create({ id, url, events, secret }) {
    await q(
      `INSERT INTO webhooks (webhook_id, url, events, secret) VALUES ($1, $2, $3, $4)`,
      [id, url, events, secret]
    );
  },

  async list() {
    const { rows } = await q(`SELECT * FROM webhooks WHERE active = TRUE ORDER BY created_at DESC`);
    return rows.map(r => ({
      id:           r.webhook_id,
      url:          r.url,
      events:       r.events,
      secret:       r.secret,
      failures:     r.failures,
      deliveries:   r.deliveries,
      lastDelivery: r.last_delivery_at,
      createdAt:    r.created_at
    }));
  },

  async findForEvent(event) {
    const { rows } = await q(
      `SELECT * FROM webhooks WHERE active = TRUE AND $1 = ANY(events)`, [event]
    );
    return rows.map(r => ({
      id: r.webhook_id, url: r.url, events: r.events, secret: r.secret,
      failures: r.failures, deliveries: r.deliveries
    }));
  },

  async delete(id) {
    const { rowCount } = await q(`DELETE FROM webhooks WHERE webhook_id = $1`, [id]);
    return rowCount > 0;
  },

  async recordDelivery(webhookId, event, status, statusCode = null, attempt = 1) {
    await q(
      `INSERT INTO webhook_deliveries (webhook_id, event, status, status_code, attempt)
       VALUES ($1, $2, $3, $4, $5)`,
      [webhookId, event, status, statusCode, attempt]
    );
    if (status === 'success') {
      await q(
        `UPDATE webhooks SET deliveries = deliveries + 1, failures = 0, last_delivery_at = NOW()
         WHERE webhook_id = $1`, [webhookId]
      );
    } else {
      await q(`UPDATE webhooks SET failures = failures + 1 WHERE webhook_id = $1`, [webhookId]);
    }
  },

  async deactivateIfFailing(webhookId, threshold = 10) {
    const { rows } = await q(`SELECT failures FROM webhooks WHERE webhook_id = $1`, [webhookId]);
    if (rows[0]?.failures >= threshold) {
      await q(`UPDATE webhooks SET active = FALSE WHERE webhook_id = $1`, [webhookId]);
      return true;
    }
    return false;
  }
};

// ─── SIGNATURES (Phase 2.5: domain-bound slugs) ───────────────────────────────

export const signatures = {
  async create({ id, signerId, role, roleLabel, roleIcon, trustScore,
                 level, levelLabel, bindingType, boundDomain,
                 textHashStrict, textHashLoose, textLength, textPreview,
                 issuer }) {
    await q(
      `INSERT INTO signatures
       (id, signer_id, role, role_label, role_icon, trust_score,
        level, level_label, binding_type, bound_domain,
        text_hash_strict, text_hash_loose, text_length, text_preview, issuer)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [id, signerId, role, roleLabel || null, roleIcon || null, trustScore,
       level || null, levelLabel || null, bindingType, boundDomain || null,
       textHashStrict, textHashLoose, textLength, textPreview || null,
       issuer || 'hhttps://hhttps.org']
    );
  },

  async get(id) {
    const { rows } = await q(`SELECT * FROM signatures WHERE id = $1`, [id]);
    return rows[0] || null;
  },

  async getMany(ids) {
    if (!Array.isArray(ids) || ids.length === 0) return [];
    const { rows } = await q(
      `SELECT * FROM signatures WHERE id = ANY($1::varchar[])`,
      [ids]
    );
    return rows;
  },

  async slugExists(id) {
    const { rows } = await q(`SELECT 1 FROM signatures WHERE id = $1`, [id]);
    return rows.length > 0;
  },

  async isReservedSlug(id) {
    const { rows } = await q(`SELECT 1 FROM reserved_slugs WHERE slug = $1`, [id.toLowerCase()]);
    return rows.length > 0;
  },

  async incrementVerify(id) {
    await q(
      `UPDATE signatures
       SET verify_count = verify_count + 1, last_verified_at = NOW()
       WHERE id = $1`,
      [id]
    );
  },

  async setFirstSeen(id, domain) {
    await q(
      `UPDATE signatures
       SET first_seen_domain = $2, first_seen_at = NOW()
       WHERE id = $1 AND first_seen_at IS NULL`,
      [id, domain]
    );
  },

  async revoke(id, signerId, reason) {
    const { rows } = await q(
      `UPDATE signatures
       SET revoked_at = NOW(), revoke_reason = $3
       WHERE id = $1 AND signer_id = $2 AND revoked_at IS NULL
       RETURNING id`,
      [id, signerId, reason || null]
    );
    return rows.length > 0;
  },

  async listBySigner(signerId, limit = 50) {
    const { rows } = await q(
      `SELECT * FROM signatures
       WHERE signer_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [signerId, limit]
    );
    return rows;
  },

  async count() {
    const { rows } = await q(`SELECT COUNT(*)::int AS n FROM signatures`);
    return rows[0].n;
  }
};

// ─── OAUTH 2.0 / OIDC (Phase 3a) ──────────────────────────────────────────────

export const oauthClients = {
  async create({ clientId, clientSecretHash, name, description, homepageUrl,
                 redirectUris, allowedScopes, subjectType, logoUrl,
                 contactEmail, ownerUserId }) {
    await q(
      `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, description, homepage_url,
        redirect_uris, allowed_scopes, subject_type, logo_url,
        contact_email, owner_user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [clientId, clientSecretHash || null, name, description || null,
       homepageUrl || null,
       JSON.stringify(redirectUris || []),
       JSON.stringify(allowedScopes || ['openid', 'role', 'email']),
       subjectType || 'pairwise',
       logoUrl || null, contactEmail || null, ownerUserId || null]
    );
  },

  async get(clientId) {
    const { rows } = await q(
      `SELECT * FROM oauth_clients WHERE client_id = $1 AND is_active = TRUE`,
      [clientId]
    );
    if (!rows[0]) return null;
    const r = rows[0];
    try { r.redirect_uris  = JSON.parse(r.redirect_uris); } catch (e) { r.redirect_uris = []; }
    try { r.allowed_scopes = JSON.parse(r.allowed_scopes); } catch (e) { r.allowed_scopes = []; }
    return r;
  },

  async listByOwner(ownerUserId) {
    const { rows } = await q(
      `SELECT * FROM oauth_clients WHERE owner_user_id = $1 ORDER BY created_at DESC`,
      [ownerUserId]
    );
    return rows.map(r => {
      try { r.redirect_uris  = JSON.parse(r.redirect_uris); } catch (e) { r.redirect_uris = []; }
      try { r.allowed_scopes = JSON.parse(r.allowed_scopes); } catch (e) { r.allowed_scopes = []; }
      return r;
    });
  },

  async setVerified(clientId, verifiedBy) {
    await q(
      `UPDATE oauth_clients SET verified = TRUE, verified_at = NOW(), verified_by = $2
       WHERE client_id = $1`,
      [clientId, verifiedBy]
    );
  },

  async touchLastUsed(clientId) {
    await q(`UPDATE oauth_clients SET last_used_at = NOW() WHERE client_id = $1`, [clientId]);
  },

  // ──────── Phase 3b — Developer Self-Service ────────

  /** Create a draft client (called from /developers/clients). */
  async createDraft({ clientId, name, description, homepageUrl, redirectUris,
                      contactEmail, impressumUrl, logoUrl, ownerUserId,
                      domainEmailMatch, emailToken, emailTokenExpiresAt, dnsToken }) {
    await q(
      `INSERT INTO oauth_clients
        (client_id, name, description, homepage_url, redirect_uris,
         allowed_scopes, subject_type, contact_email, impressum_url, logo_url,
         owner_user_id, verification_status, domain_email_match,
         email_token, email_token_expires_at, dns_token,
         verified, is_active)
       VALUES ($1, $2, $3, $4, $5,
               $6, 'pairwise', $7, $8, $9,
               $10, 'email_pending', $11,
               $12, $13, $14,
               FALSE, TRUE)`,
      [clientId, name, description || null, homepageUrl,
       JSON.stringify(redirectUris || []),
       JSON.stringify(['openid', 'role', 'email']),
       contactEmail, impressumUrl || null, logoUrl || null,
       ownerUserId, !!domainEmailMatch,
       emailToken, emailTokenExpiresAt, dnsToken || null]
    );
  },

  /** Look up a client by its current email confirmation token. */
  async getByEmailToken(token) {
    const { rows } = await q(
      `SELECT * FROM oauth_clients
        WHERE email_token = $1
          AND email_token_expires_at > NOW()
          AND is_active = TRUE`,
      [token]
    );
    if (!rows[0]) return null;
    const r = rows[0];
    try { r.redirect_uris  = JSON.parse(r.redirect_uris); } catch (e) { r.redirect_uris = []; }
    try { r.allowed_scopes = JSON.parse(r.allowed_scopes); } catch (e) { r.allowed_scopes = []; }
    return r;
  },

  /** Mark email as confirmed. Moves status from 'email_pending' → 'unverified'. */
  async confirmEmail(clientId) {
    await q(
      `UPDATE oauth_clients
          SET email_verified_at = NOW(),
              email_token = NULL,
              email_token_expires_at = NULL,
              verification_status = 'unverified'
        WHERE client_id = $1
          AND verification_status = 'email_pending'`,
      [clientId]
    );
  },

  /** Regenerate the email confirmation token (e.g. user clicked "resend"). */
  async refreshEmailToken(clientId, newToken, newExpiry) {
    await q(
      `UPDATE oauth_clients
          SET email_token = $2,
              email_token_expires_at = $3
        WHERE client_id = $1`,
      [clientId, newToken, newExpiry]
    );
  },

  /** Update contact email (and recompute domain_email_match externally). */
  async updateContactEmail(clientId, email, domainEmailMatch, emailToken, expires) {
    await q(
      `UPDATE oauth_clients
          SET contact_email = $2,
              domain_email_match = $3,
              email_token = $4,
              email_token_expires_at = $5,
              email_verified_at = NULL,
              verification_status = CASE
                WHEN verification_status = 'verified' THEN 'unverified'
                ELSE 'email_pending'
              END
        WHERE client_id = $1`,
      [clientId, email, !!domainEmailMatch, emailToken, expires]
    );
  },

  /** Update general metadata (name, description, redirect_uris, etc.) — must
   *  preserve verification_status. */
  async updateMetadata(clientId, { name, description, redirectUris, logoUrl, impressumUrl }) {
    await q(
      `UPDATE oauth_clients
          SET name          = COALESCE($2, name),
              description   = COALESCE($3, description),
              redirect_uris = COALESCE($4, redirect_uris),
              logo_url      = COALESCE($5, logo_url),
              impressum_url = COALESCE($6, impressum_url)
        WHERE client_id = $1`,
      [clientId, name || null, description || null,
       redirectUris ? JSON.stringify(redirectUris) : null,
       logoUrl || null, impressumUrl || null]
    );
  },

  /** Mark DNS as verified. */
  async setDnsVerified(clientId) {
    await q(
      `UPDATE oauth_clients
          SET dns_verified_at    = NOW(),
              dns_last_checked_at = NOW()
        WHERE client_id = $1`,
      [clientId]
    );
  },

  /** Record a failed DNS check (just bumps the last_checked timestamp). */
  async touchDnsCheck(clientId) {
    await q(
      `UPDATE oauth_clients
          SET dns_last_checked_at = NOW()
        WHERE client_id = $1`,
      [clientId]
    );
  },

  /** Move client to 'pending_review' state — owner is asking for verification.
   *  Caller must have verified all preconditions (email confirmed, domain
   *  match, DNS verified). */
  async submitForReview(clientId, { ownerRole, ownerTrust }) {
    await q(
      `UPDATE oauth_clients
          SET verification_status = 'pending_review',
              submitted_for_review_at = NOW(),
              owner_role_at_submit  = $2,
              owner_trust_at_submit = $3
        WHERE client_id = $1
          AND verification_status = 'unverified'`,
      [clientId, ownerRole || null, ownerTrust || null]
    );
  },

  /** Admin approves a pending client. */
  async adminApprove(clientId, adminUserId) {
    await q(
      `UPDATE oauth_clients
          SET verification_status = 'verified',
              verified            = TRUE,
              verified_at         = NOW(),
              verified_by         = $2,
              reviewed_at         = NOW(),
              rejection_reason    = NULL
        WHERE client_id = $1`,
      [clientId, adminUserId]
    );
  },

  /** Admin rejects a pending client. */
  async adminReject(clientId, adminUserId, reason) {
    await q(
      `UPDATE oauth_clients
          SET verification_status = 'rejected',
              verified            = FALSE,
              reviewed_at         = NOW(),
              verified_by         = $2,
              rejection_reason    = $3
        WHERE client_id = $1`,
      [clientId, adminUserId, reason]
    );
  },

  /** Admin suspends an active client. */
  async adminSuspend(clientId, adminUserId, reason) {
    await q(
      `UPDATE oauth_clients
          SET verification_status = 'suspended',
              verified            = FALSE,
              reviewed_at         = NOW(),
              verified_by         = $2,
              rejection_reason    = $3
        WHERE client_id = $1`,
      [clientId, adminUserId, reason]
    );
  },

  /** All clients pending admin review, sorted: developer-role first, then by submission age. */
  async listPendingReview() {
    const { rows } = await q(
      `SELECT * FROM oauth_clients
        WHERE verification_status = 'pending_review'
        ORDER BY
          (owner_role_at_submit = 'developer') DESC,
          owner_trust_at_submit DESC NULLS LAST,
          submitted_for_review_at ASC`
    );
    return rows.map(r => {
      try { r.redirect_uris  = JSON.parse(r.redirect_uris); } catch (e) { r.redirect_uris = []; }
      try { r.allowed_scopes = JSON.parse(r.allowed_scopes); } catch (e) { r.allowed_scopes = []; }
      return r;
    });
  },

  /** All clients owned by a user (any status, including draft). */
  async listAllByOwner(ownerUserId) {
    const { rows } = await q(
      `SELECT * FROM oauth_clients
        WHERE owner_user_id = $1
        ORDER BY created_at DESC`,
      [ownerUserId]
    );
    return rows.map(r => {
      try { r.redirect_uris  = JSON.parse(r.redirect_uris); } catch (e) { r.redirect_uris = []; }
      try { r.allowed_scopes = JSON.parse(r.allowed_scopes); } catch (e) { r.allowed_scopes = []; }
      return r;
    });
  },

  /** Count clients created by an owner in last 24h — for rate limiting. */
  async countRecentByOwner(ownerUserId, hoursBack = 24) {
    const { rows } = await q(
      `SELECT COUNT(*)::int AS n FROM oauth_clients
        WHERE owner_user_id = $1
          AND created_at > NOW() - ($2 || ' hours')::interval`,
      [ownerUserId, String(hoursBack)]
    );
    return rows[0].n;
  },

  /** Permanently delete a draft (only allowed for draft / email_pending). */
  async deleteIfDraft(clientId, ownerUserId) {
    const { rowCount } = await q(
      `DELETE FROM oauth_clients
        WHERE client_id = $1
          AND owner_user_id = $2
          AND verification_status IN ('draft', 'email_pending')`,
      [clientId, ownerUserId]
    );
    return rowCount > 0;
  }
};

// ─── Admins (Phase 3b) ────────────────────────────────────────────────────
export const admins = {
  async isAdmin(userId) {
    if (!userId) return false;
    const { rows } = await q(
      `SELECT 1 FROM admins WHERE user_id = $1 LIMIT 1`,
      [userId]
    );
    return rows.length > 0;
  },

  async grant(userId, grantedBy, note) {
    await q(
      `INSERT INTO admins (user_id, granted_by, note)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO NOTHING`,
      [userId, grantedBy || null, note || null]
    );
  },

  async revoke(userId) {
    const { rowCount } = await q(
      `DELETE FROM admins WHERE user_id = $1`,
      [userId]
    );
    return rowCount > 0;
  },

  async list() {
    const { rows } = await q(
      `SELECT user_id, granted_at, granted_by, note FROM admins ORDER BY granted_at ASC`
    );
    return rows;
  }
};

// ─── Client stats (Phase 3b) ──────────────────────────────────────────────
// Privacy-by-design: per-day per-client per-role-bucket counts. No user IDs.
export const clientStats = {
  /** Record a successful login. Called from /hhttps/oauth/token. */
  async recordLogin(clientId, role, trustScore) {
    const trustBucket = trustScore >= 70 ? 'high' : (trustScore >= 40 ? 'medium' : 'low');
    const roleBucket  = role || 'unknown';
    await q(
      `INSERT INTO client_stats_daily (client_id, day, role_bucket, trust_bucket, login_count)
       VALUES ($1, CURRENT_DATE, $2, $3, 1)
       ON CONFLICT (client_id, day, role_bucket, trust_bucket)
       DO UPDATE SET login_count = client_stats_daily.login_count + 1`,
      [clientId, roleBucket, trustBucket]
    );
  },

  /** Get aggregated stats for a client. Returns array of daily buckets. */
  async getDaily(clientId, days = 30) {
    const { rows } = await q(
      `SELECT day, role_bucket, trust_bucket, login_count
         FROM client_stats_daily
        WHERE client_id = $1
          AND day >= CURRENT_DATE - ($2 || ' days')::interval
        ORDER BY day DESC, role_bucket, trust_bucket`,
      [clientId, String(days)]
    );
    return rows;
  },

  /** Total login count for a client (lifetime). */
  async getTotal(clientId) {
    const { rows } = await q(
      `SELECT COALESCE(SUM(login_count), 0)::int AS n
         FROM client_stats_daily
        WHERE client_id = $1`,
      [clientId]
    );
    return rows[0].n;
  }
};

// ─── Admin actions audit log (Phase 3b) ───────────────────────────────────
export const adminActions = {
  async log(actionType, targetType, targetId, adminUserId, details) {
    await q(
      `INSERT INTO admin_actions (action_type, target_type, target_id, admin_user_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [actionType, targetType, targetId, adminUserId, details ? JSON.stringify(details) : null]
    );
  },

  async listForTarget(targetType, targetId, limit = 20) {
    const { rows } = await q(
      `SELECT * FROM admin_actions
        WHERE target_type = $1 AND target_id = $2
        ORDER BY created_at DESC
        LIMIT $3`,
      [targetType, targetId, limit]
    );
    return rows;
  },

  async listRecent(limit = 50) {
    const { rows } = await q(
      `SELECT * FROM admin_actions
        ORDER BY created_at DESC
        LIMIT $1`,
      [limit]
    );
    return rows;
  }
};

export const authCodes = {
  async create({ code, clientId, userId, redirectUri, scopes,
                 pkceChallenge, pkceMethod, state, nonce,
                 role, trustScore, verificationMethod,
                 ageGroup, ageVerified, ageVerificationMethod,
                 email, pseudonym, verifiedMethods, ttlSec = 60 }) {
    await q(
      `INSERT INTO authorization_codes
       (code, client_id, user_id, redirect_uri, scopes,
        pkce_challenge, pkce_method, state, nonce,
        role, trust_score, verification_method,
        age_group, age_verified, age_verification_method,
        email, pseudonym, verified_methods,
        expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
               $13, $14, $15,
               $16, $17, $18,
               NOW() + ($19 || ' seconds')::interval)`,
      [code, clientId, userId, redirectUri,
       JSON.stringify(scopes || []),
       pkceChallenge || null, pkceMethod || null,
       state || null, nonce || null,
       role, trustScore, verificationMethod || null,
       ageGroup || null, ageVerified ?? null, ageVerificationMethod || null,
       email || null, pseudonym || null,
       verifiedMethods == null ? null : JSON.stringify(verifiedMethods),
       ttlSec]
    );
  },

  /**
   * Atomic single-use claim in ONE statement (P-1). Returns the row (with
   * `scopes` and `verified_methods` parsed as arrays) only if the code was
   * unused and not expired, otherwise null. The e-mail copy on the code row is
   * wiped in the same UPDATE (transferred ⇒ deleted, AK-17); the value from
   * BEFORE the wipe is read via the `old` CTE (a plain SELECT — the row is
   * modified only once, so this is legal in PostgreSQL) and returned as
   * `email` to the caller.
   */
  async claim(code) {
    const { rows } = await q(
      `WITH old AS (SELECT email FROM authorization_codes WHERE code = $1)
       UPDATE authorization_codes a
       SET used = TRUE, used_at = NOW(), email = NULL
       WHERE a.code = $1 AND a.used = FALSE AND a.expires_at > NOW()
       RETURNING a.*, (SELECT email FROM old) AS email_before`,
      [code]
    );
    if (!rows[0]) return null;
    const r = rows[0];
    r.scopes = parseJsonArray(r.scopes);
    r.verified_methods = parseJsonArray(r.verified_methods);
    r.email = r.email_before ?? null;
    delete r.email_before;
    r.pseudonym = r.pseudonym ?? null;
    return r;
  },

  async cleanup() {
    // Periodic cleanup of expired/used codes
    await q(`DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'`);
  }
};

export const connectedPlatforms = {
  async record({ userId, clientId, pairwiseSubjectId, scopesGranted }) {
    await q(
      `INSERT INTO connected_platforms
       (user_id, client_id, pairwise_subject_id, scopes_granted)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, client_id) DO UPDATE
       SET last_login_at = NOW(),
           login_count = connected_platforms.login_count + 1,
           scopes_granted = EXCLUDED.scopes_granted,
           revoked_at = NULL`,
      [userId, clientId, pairwiseSubjectId, JSON.stringify(scopesGranted || [])]
    );
  },

  async listByUser(userId) {
    const { rows } = await q(
      `SELECT cp.*, oc.name AS client_name, oc.logo_url AS client_logo, oc.verified
       FROM connected_platforms cp
       JOIN oauth_clients oc ON oc.client_id = cp.client_id
       WHERE cp.user_id = $1 AND cp.revoked_at IS NULL
       ORDER BY cp.last_login_at DESC`,
      [userId]
    );
    return rows.map(r => {
      try { r.scopes_granted = JSON.parse(r.scopes_granted); } catch (e) { r.scopes_granted = []; }
      return r;
    });
  },

  async revoke(userId, clientId) {
    await q(
      `UPDATE connected_platforms SET revoked_at = NOW()
       WHERE user_id = $1 AND client_id = $2`,
      [userId, clientId]
    );
  },

  async getPairwiseId(userId, clientId) {
    const { rows } = await q(
      `SELECT pairwise_subject_id FROM connected_platforms
       WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
      [userId, clientId]
    );
    return rows[0]?.pairwise_subject_id || null;
  }
};

// ─── STATS ────────────────────────────────────────────────────────────────────

export const stats = {
  async increment(metric, by = 1) {
    await q(
      `INSERT INTO stats (metric, value) VALUES ($1, $2)
       ON CONFLICT (metric) DO UPDATE SET value = stats.value + $2, updated_at = NOW()`,
      [metric, by]
    );
  },

  async getAll() {
    const { rows } = await q(`SELECT metric, value FROM stats`);
    const out = {};
    for (const r of rows) out[r.metric] = Number(r.value);
    return out;
  }
};

// ─── CLEANUP ──────────────────────────────────────────────────────────────────

export async function cleanupExpired() {
  const { rows } = await q(`SELECT * FROM cleanup_expired()`);
  const out = rows[0] || {};
  // Phase 8: expired plaintext claims (D5) — not part of the SQL function so
  // the function body in schema.sql stays untouched.
  const { rowCount } = await q(`DELETE FROM identity_claims_cache WHERE expires_at < NOW()`);
  out.deleted_claims_cache = rowCount;
  return out;
}

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

export async function ping() {
  try {
    await q('SELECT 1');
    return true;
  } catch {
    return false;
  }
}

export async function close() {
  if (_pool) {
    await _pool.end();
    _pool = null;
  }
}
