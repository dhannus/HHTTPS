// ════════════════════════════════════════════════════════════════════════════
//  workload-identity.js
//
//  Workload Identity Federation for HHTTPS. Exchanges a CI/CD provider's
//  short-lived OIDC token (GitHub Actions first) for an HHTTPS machine token,
//  with NO long-lived secret stored in the CI system.
//
//  Verification is done against the provider's public JWKS — no extra npm
//  dependency needed: Node's crypto.createPublicKey can build a verify key
//  from a JWK, and jsonwebtoken verifies the RS256 signature.
//
//  Design note on attribution vs pseudonymity: human GitHub verification is
//  pseudonymous (we store only a one-way hash). Workload identity is the
//  OPPOSITE — the resulting machine token deliberately carries the repository,
//  workflow, ref, actor, and run_id so a consuming platform can see exactly
//  which CI run produced the token. That attributability is the whole point.
// ════════════════════════════════════════════════════════════════════════════

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import * as db from './db.js';

// ─── Provider registry ──────────────────────────────────────────────────────
// Extensible: add GitLab CI, Buildkite, etc. by adding entries here.
const PROVIDERS = {
  'github-actions': {
    issuer:   'https://token.actions.githubusercontent.com',
    jwksUri:  'https://token.actions.githubusercontent.com/.well-known/jwks',
    // Map raw OIDC claims into the attributes we expose on the machine token
    extract(claims) {
      return {
        repository:        claims.repository,        // 'owner/repo'
        repository_owner:  claims.repository_owner,   // 'owner'
        ref:               claims.ref,                // 'refs/heads/main'
        sha:               claims.sha,
        workflow:          claims.workflow,
        actor:             claims.actor,
        run_id:            claims.run_id,
        event_name:        claims.event_name,
        environment:       claims.environment || null,
        sub:               claims.sub,
      };
    },
    // Which claim identifies the "repository" used for binding lookup
    repoOf(claims) { return claims.repository; },
  },

  // GitLab CI/CD ID tokens (gitlab.com). Self-hosted GitLab uses a different
  // issuer/JWKS (https://<instance>/oauth/discovery/keys) — would need a
  // per-binding override; not handled here.
  'gitlab-ci': {
    issuer:   'https://gitlab.com',
    jwksUri:  'https://gitlab.com/oauth/discovery/keys',
    extract(claims) {
      return {
        repository:        claims.project_path,      // 'group/project'
        repository_owner:  claims.namespace_path,     // 'group'
        ref:               claims.ref,                // 'main'
        ref_type:          claims.ref_type,           // 'branch' | 'tag'
        pipeline:          claims.pipeline_id,
        job_id:            claims.job_id,
        actor:             claims.user_login,
        environment:       claims.environment || null,
        sub:               claims.sub,
      };
    },
    repoOf(claims) { return claims.project_path; },
  },

  // Buildkite agent OIDC tokens. There is no "repository" per se; we use
  // organization_slug/pipeline_slug as the binding key.
  'buildkite': {
    issuer:   'https://agent.buildkite.com',
    jwksUri:  'https://agent.buildkite.com/.well-known/jwks',
    extract(claims) {
      return {
        repository:        (claims.organization_slug && claims.pipeline_slug)
                             ? `${claims.organization_slug}/${claims.pipeline_slug}` : null,
        repository_owner:  claims.organization_slug,
        ref:               claims.build_branch,
        sha:               claims.build_commit,
        pipeline:          claims.pipeline_slug,
        build_number:      claims.build_number,
        job_id:            claims.job_id,
        sub:               claims.sub,
      };
    },
    repoOf(claims) {
      return (claims.organization_slug && claims.pipeline_slug)
        ? `${claims.organization_slug}/${claims.pipeline_slug}` : null;
    },
  },
};

export function isProviderSupported(provider) {
  return !!PROVIDERS[provider];
}

/**
 * Decode an OIDC token WITHOUT verifying it — used only to read the
 * repository claim so we can look up the right binding (and its expected
 * audience) before doing full cryptographic verification. Never trust these
 * values for anything security-relevant; verifyOidcToken does the real check.
 */
export function decodeOidcUnverified(token) {
  const claims = jwt.decode(token);
  if (!claims || typeof claims !== 'object') {
    throw new Error('OIDC-Token konnte nicht dekodiert werden.');
  }
  return claims;
}

// ─── JWKS cache ───────────────────────────────────────────────────────────────
// Provider keys rotate rarely; cache for an hour, refetch on cache miss / kid miss.
const _jwksCache = new Map(); // provider -> { fetchedAt, keys: Map<kid, jwk> }
const JWKS_TTL_MS = 60 * 60 * 1000;

async function getProviderKeys(provider, { forceRefresh = false } = {}) {
  const cfg = PROVIDERS[provider];
  const cached = _jwksCache.get(provider);
  if (!forceRefresh && cached && (Date.now() - cached.fetchedAt) < JWKS_TTL_MS) {
    return cached.keys;
  }

  const res = await fetch(cfg.jwksUri, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`JWKS-Abruf fehlgeschlagen (${res.status}) für ${provider}.`);
  const jwks = await res.json();

  const keys = new Map();
  for (const k of (jwks.keys || [])) {
    if (k.kid) keys.set(k.kid, k);
  }
  _jwksCache.set(provider, { fetchedAt: Date.now(), keys });
  return keys;
}

/**
 * Verify a provider OIDC token. Returns the decoded claims if valid.
 * Throws with a descriptive message otherwise.
 *
 * @param {string} provider          e.g. 'github-actions'
 * @param {string} token             the raw OIDC JWT
 * @param {string} expectedAudience  required `aud` value (HHTTPS issuer URL)
 */
export async function verifyOidcToken(provider, token, expectedAudience) {
  const cfg = PROVIDERS[provider];
  if (!cfg) throw new Error(`Unbekannter Provider "${provider}".`);

  // Decode header to find the key id
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header) throw new Error('OIDC-Token konnte nicht dekodiert werden.');
  const kid = decoded.header.kid;
  if (!kid) throw new Error('OIDC-Token-Header enthält keine kid.');

  // Find the matching JWK; on miss, force a JWKS refresh once (key rotation)
  let keys = await getProviderKeys(provider);
  let jwk = keys.get(kid);
  if (!jwk) {
    keys = await getProviderKeys(provider, { forceRefresh: true });
    jwk = keys.get(kid);
  }
  if (!jwk) throw new Error(`Kein passender Signaturschlüssel (kid=${kid}) in der JWKS des Providers.`);

  // Build a verify key from the JWK (no extra dependency needed)
  const verifyKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });

  // Verify signature + standard claims
  let claims;
  try {
    claims = jwt.verify(token, verifyKey, {
      algorithms: ['RS256'],
      issuer:     cfg.issuer,
      audience:   expectedAudience,
    });
  } catch (e) {
    throw new Error(`OIDC-Token ungültig: ${e.message}`);
  }
  return claims;
}

// ─── Binding management ─────────────────────────────────────────────────────

/**
 * Create (or reactivate) a binding between a provider repository and an
 * HHTTPS machine operator. Caller must have already authenticated the
 * operator (operatorId + apiKey).
 */
export async function bindWorkload({ provider, repository, subjectPattern, expectedAudience, operatorId }) {
  await db.q(
    `INSERT INTO workload_identities
       (provider, repository, subject_pattern, expected_audience, operator_id, active)
     VALUES ($1, $2, $3, $4, $5, TRUE)
     ON CONFLICT (provider, repository, subject_pattern) DO UPDATE
       SET operator_id       = EXCLUDED.operator_id,
           expected_audience = EXCLUDED.expected_audience,
           active            = TRUE`,
    [provider, repository, subjectPattern || null, expectedAudience || null, operatorId]
  );
}

/**
 * Find an active binding for a (provider, repository). Returns the most
 * specific match: a binding with a subject_pattern that matches the token's
 * sub wins over a NULL-pattern (wildcard) binding.
 */
export async function findBinding({ provider, repository, sub }) {
  const { rows } = await db.q(
    `SELECT * FROM workload_identities
      WHERE provider = $1 AND repository = $2 AND active = TRUE`,
    [provider, repository]
  );
  if (!rows.length) return null;

  // Prefer a binding whose subject_pattern matches the token sub exactly,
  // then any wildcard (NULL) binding.
  const specific = rows.find(r => r.subject_pattern && r.subject_pattern === sub);
  if (specific) return specific;
  const wildcard = rows.find(r => !r.subject_pattern);
  return wildcard || null;
}

export async function recordExchange(bindingId) {
  await db.q(
    `UPDATE workload_identities
        SET exchanges = exchanges + 1, last_used_at = NOW()
      WHERE id = $1`,
    [bindingId]
  );
}

/**
 * Deactivate a binding. Scoped to the owning operator so one operator can't
 * unbind another's repositories. Returns true if a row was deactivated.
 */
export async function unbindWorkload({ bindingId, operatorId }) {
  const { rowCount } = await db.q(
    `UPDATE workload_identities
        SET active = FALSE
      WHERE id = $1 AND operator_id = $2 AND active = TRUE`,
    [bindingId, operatorId]
  );
  return rowCount > 0;
}

/**
 * List bindings owned by an operator (for the management endpoint).
 */
export async function listBindings(operatorId) {
  const { rows } = await db.q(
    `SELECT id, provider, repository, subject_pattern, expected_audience,
            created_at, last_used_at, exchanges, active
       FROM workload_identities
      WHERE operator_id = $1
      ORDER BY created_at DESC`,
    [operatorId]
  );
  return rows;
}

export { PROVIDERS };
