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

import pg from 'pg';
const { Pool } = pg;

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
    await q(
      `INSERT INTO sessions (
        session_id, user_id, credential_id, device_type, backed_up,
        verified, trust_score, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + ($8 || ' milliseconds')::interval)`,
      [
        sessionId, data.userId, data.credentialId, data.deviceType, data.backedUp,
        data.verified !== false, data.trustScore || 60, ttlMs
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
      trustScore:      'trust_score'
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
  async create({ token, email, domain, level, trustBonus, category, sessionId, ttlMs = 900_000 }) {
    await q(
      `INSERT INTO email_verifications (token, email, domain, level, trust_bonus, category, session_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + ($8 || ' milliseconds')::interval)`,
      [token, email, domain, level, trustBonus, category, sessionId, ttlMs]
    );
  },

  async getAndConsume(token) {
    const { rows } = await q(
      `UPDATE email_verifications SET used = TRUE
       WHERE token = $1 AND used = FALSE AND expires_at > NOW()
       RETURNING *`,
      [token]
    );
    return rows[0] || null;
  }
};

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
  async create({ operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash, role, roleLabel, roleIcon }) {
    await q(
      `INSERT INTO machine_operators (operator_id, operator_name, operator_url, purpose, contact_email, api_key_hash, role, role_label, role_icon)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash, role || null, roleLabel || null, roleIcon || null]
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
       JSON.stringify(allowedScopes || ['openid', 'role']),
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
       JSON.stringify(['openid', 'role']),
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
                 role, trustScore, verificationMethod, ttlSec = 60 }) {
    await q(
      `INSERT INTO authorization_codes
       (code, client_id, user_id, redirect_uri, scopes,
        pkce_challenge, pkce_method, state, nonce,
        role, trust_score, verification_method,
        expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
               NOW() + ($13 || ' seconds')::interval)`,
      [code, clientId, userId, redirectUri,
       JSON.stringify(scopes || []),
       pkceChallenge || null, pkceMethod || null,
       state || null, nonce || null,
       role, trustScore, verificationMethod || null, ttlSec]
    );
  },

  async claim(code) {
    // Atomic claim: mark used AND return only if not yet used and not expired
    const { rows } = await q(
      `UPDATE authorization_codes
       SET used = TRUE, used_at = NOW()
       WHERE code = $1 AND used = FALSE AND expires_at > NOW()
       RETURNING *`,
      [code]
    );
    if (!rows[0]) return null;
    const r = rows[0];
    try { r.scopes = JSON.parse(r.scopes); } catch (e) { r.scopes = []; }
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
  return rows[0] || {};
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
