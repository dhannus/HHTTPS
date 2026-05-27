// ════════════════════════════════════════════════════════════════════════════
//  external-verify.js
//
//  External identity-provider verification for HHTTPS roles. Currently:
//  GitHub (for `developer`). Designed to extend to ORCID, LinkedIn, etc.
//
//  Pseudonymity contract — non-negotiable:
//    - The external username, ID, email, repo count, follower count etc. are
//      NEVER persisted to the database.
//    - Heuristics about the external profile (age, repos, followers) are
//      evaluated ONCE at verification time and collapsed into a single
//      trust score. The raw values evaporate the moment the OAuth callback
//      completes.
//    - What stays: sha256(provider:external_id:pepper) as anchor hash, and
//      the assigned trust score. Both are useless to anyone without GitHub's
//      cooperation.
//    - Resulting JWT contains `verification_method: 'github-verified'` and
//      the trust score. No username. No external IDs.
//
//  The pepper (HHTTPS_VERIFICATION_PEPPER env var) is critical — without it,
//  an attacker who steals the DB could brute-force GitHub IDs (they're
//  64-bit integers). Pepper makes that infeasible.
// ════════════════════════════════════════════════════════════════════════════

import crypto from 'crypto';
import * as db from './db.js';

const GITHUB_CLIENT_ID     = process.env.GITHUB_CLIENT_ID     || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const VERIFICATION_PEPPER  = process.env.HHTTPS_VERIFICATION_PEPPER || '';

const GITHUB_OAUTH_AUTHORIZE = 'https://github.com/login/oauth/authorize';
const GITHUB_OAUTH_TOKEN     = 'https://github.com/login/oauth/access_token';
const GITHUB_API_USER        = 'https://api.github.com/user';

export function isGithubConfigured() {
  return !!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && VERIFICATION_PEPPER);
}

/**
 * Compute the irreversible anchor hash for an external account.
 * sha256("github:" + githubUserId + ":" + pepper)
 *
 * Without the pepper, GitHub IDs (numeric, public) could be brute-forced
 * against a stolen anchor table. The pepper makes that infeasible.
 */
function anchorHash(provider, externalId) {
  if (!VERIFICATION_PEPPER) {
    throw new Error('HHTTPS_VERIFICATION_PEPPER is required and unset.');
  }
  return crypto
    .createHash('sha256')
    .update(`${provider}:${externalId}:${VERIFICATION_PEPPER}`)
    .digest('hex');
}

/**
 * Heuristic trust score for a GitHub profile.
 * Inputs (PROFILE) include: created_at, public_repos, followers.
 * Output: a single integer in {60, 70, 78, 85}. We never persist the inputs.
 *
 * Thresholds (per Daniel's spec):
 *   - <1 year, ≤0 repos              →  60  (verified but bare account)
 *   - 1–3 years, some repos          →  70  (standard active user)
 *   - 3+ years AND 10+ repos         →  78  (active developer)
 *   - >100 followers OR 50+ repos    →  85  (established public presence)
 */
function computeGithubTrust(profile) {
  const now = Date.now();
  const ageMs = now - new Date(profile.created_at).getTime();
  const ageYears = ageMs / (365.25 * 24 * 3600 * 1000);
  const repos = profile.public_repos | 0;
  const followers = profile.followers | 0;

  if (followers > 100 || repos >= 50) return 85;
  if (ageYears >= 3 && repos >= 10)   return 78;
  if (ageYears >= 1 && repos >= 1)    return 70;
  return 60;
}

// ─── DB helpers ─────────────────────────────────────────────────────────────

async function createPendingState({ sessionId }) {
  const state = crypto.randomBytes(24).toString('base64url');
  await db.q(
    `INSERT INTO github_oauth_pending (state, session_id) VALUES ($1, $2)`,
    [state, sessionId]
  );
  return state;
}

async function consumePendingState(state) {
  const { rows } = await db.q(
    `DELETE FROM github_oauth_pending
       WHERE state = $1 AND expires_at > NOW()
       RETURNING session_id`,
    [state]
  );
  return rows[0]?.session_id || null;
}

async function recordAnchor({ provider, externalId, userId, trustScore }) {
  const hash = anchorHash(provider, externalId);
  // ON CONFLICT path = same external account already verified;
  // update reverify timestamp + trust score (heuristic may have changed).
  await db.q(
    `INSERT INTO external_verification_anchors
       (provider, anchor_hash, user_id, trust_score_assigned)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (provider, anchor_hash) DO UPDATE
       SET user_id              = EXCLUDED.user_id,
           trust_score_assigned = EXCLUDED.trust_score_assigned,
           last_reverified_at   = NOW()`,
    [provider, hash, userId, trustScore]
  );
}

// ─── OAuth flow handlers ────────────────────────────────────────────────────

/**
 * Start the GitHub OAuth flow.
 * Generates a state, persists it linked to the session, returns the
 * authorize URL.
 */
export async function startGithubVerify({ sessionId, redirectBase }) {
  if (!isGithubConfigured()) {
    throw new Error('GitHub OAuth nicht konfiguriert (Server-Admin: setze GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, HHTTPS_VERIFICATION_PEPPER).');
  }

  const state = await createPendingState({ sessionId });
  const params = new URLSearchParams({
    client_id:    GITHUB_CLIENT_ID,
    redirect_uri: `${redirectBase}/hhttps/verify/github/callback`,
    state,
    scope:        'read:user',
    allow_signup: 'true',
  });

  return `${GITHUB_OAUTH_AUTHORIZE}?${params}`;
}

/**
 * Handle the GitHub OAuth callback.
 * 1. Consume + verify the state (binds back to a session).
 * 2. Exchange code → access_token.
 * 3. Fetch /user with the access token.
 * 4. Compute trust score from profile heuristics (which we then forget).
 * 5. Record only: anchor hash + user_id + trust_score.
 * 6. Mark the session as github-verified.
 *
 * Returns { sessionId, trustScore, alreadyOwnedBy } where alreadyOwnedBy is
 * non-null if this GitHub account was already linked to a different HHTTPS
 * user — caller decides how strict to be (we just warn).
 */
export async function handleGithubCallback({ code, state, redirectBase }) {
  if (!isGithubConfigured()) {
    throw new Error('GitHub OAuth nicht konfiguriert.');
  }

  const sessionId = await consumePendingState(state);
  if (!sessionId) {
    throw new Error('Invalid or expired state.');
  }

  const session = await db.sessions.get(sessionId);
  if (!session) throw new Error('Session no longer exists.');

  // 1. Exchange code for access token
  const tokenRes = await fetch(GITHUB_OAUTH_TOKEN, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id:     GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code,
      redirect_uri:  `${redirectBase}/hhttps/verify/github/callback`,
    }),
  });
  if (!tokenRes.ok) {
    throw new Error(`GitHub token exchange failed (${tokenRes.status}).`);
  }
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    throw new Error('GitHub did not return an access_token: ' + (tokenData.error_description || tokenData.error || 'unknown'));
  }

  // 2. Fetch user profile
  const userRes = await fetch(GITHUB_API_USER, {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept:        'application/vnd.github+json',
      'User-Agent':  'HHTTPS-Verifier',
    },
  });
  if (!userRes.ok) {
    throw new Error(`GitHub Profil-Abruf fehlgeschlagen (${userRes.status}).`);
  }
  const profile = await userRes.json();

  if (!profile.id) {
    throw new Error('GitHub-Profil enthielt keine ID — Verifikation abgebrochen.');
  }

  // 3. Compute trust score (heuristic values are then immediately discarded —
  //    only `trustScore` survives this scope)
  const trustScore = computeGithubTrust(profile);

  // 4. Check for prior anchor (same GitHub account previously verified by anyone)
  const hash = anchorHash('github', profile.id);
  const { rows: priorRows } = await db.q(
    `SELECT user_id FROM external_verification_anchors
      WHERE provider = 'github' AND anchor_hash = $1`,
    [hash]
  );
  const alreadyOwnedBy = priorRows[0]?.user_id || null;

  // 5. Record anchor (insert or update timestamp)
  await recordAnchor({
    provider:   'github',
    externalId: profile.id,
    userId:     session.userId,
    trustScore,
  });

  // 6. Mark session as github-verified
  await db.sessions.update(sessionId, {
    githubVerified:    true,
    githubTrustBonus:  trustScore,
  });

  // All profile data goes out of scope here. Only trustScore and the hash
  // (which is one-way) remain in the database.
  return {
    sessionId,
    trustScore,
    alreadyOwnedBy: (alreadyOwnedBy && alreadyOwnedBy !== session.userId) ? alreadyOwnedBy : null,
  };
}

/**
 * Check current github-verify status for a session. Used by the wallet UI
 * to display the verification badge.
 */
export async function getGithubStatus(sessionId) {
  const session = await db.sessions.get(sessionId);
  if (!session) return { verified: false };
  return {
    verified:   !!session.githubVerified,
    trustScore: session.githubTrustBonus || null,
  };
}

/**
 * Re-login persistence: if this user has previously verified a GitHub
 * account (anchor exists), return the stored trust score so a fresh
 * session can be marked github-verified automatically — no second OAuth
 * roundtrip needed on the same or a new device.
 *
 * Returns { verified: bool, trustScore: number|null }.
 */
export async function getUserGithubAnchor(userId) {
  if (!userId) return { verified: false, trustScore: null };
  const { rows } = await db.q(
    `SELECT trust_score_assigned
       FROM external_verification_anchors
      WHERE provider = 'github' AND user_id = $1
      ORDER BY last_reverified_at DESC
      LIMIT 1`,
    [userId]
  );
  if (!rows[0]) return { verified: false, trustScore: null };
  return { verified: true, trustScore: rows[0].trust_score_assigned };
}

// Best-effort hourly cleanup of expired pending OAuth states.
export function startGithubVerifyCleanup() {
  setInterval(async () => {
    try {
      await db.q(`DELETE FROM github_oauth_pending WHERE expires_at < NOW()`);
    } catch (e) {
      console.error('[github-verify] cleanup error:', e.message);
    }
  }, 60 * 60 * 1000).unref();
}
