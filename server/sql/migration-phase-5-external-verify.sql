-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS — Migration phase 5: External provider verification (GitHub first)
--
-- Pseudonymity-preserving verification against external identity providers.
-- We never store the external username, ID, or any other identifying field.
-- Instead we store only sha256(provider || ':' || external_id || ':' || pepper)
-- as an anchor hash, which lets us:
--   - detect re-verification of the same external account (Sybil resistance)
--   - re-verify a user across sessions/devices without re-running OAuth
--   - claim "X is github-verified" without ever revealing the GitHub identity
--
-- Heuristics about the external profile (account age, follower count, etc.)
-- are evaluated once at verification time and collapsed into a single trust
-- score. The raw heuristic values are NEVER persisted.
--
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

-- Anchor table: one row per (provider, external_account)
-- The user_id link lets us know which HHTTPS user owns this anchor, but the
-- external account is only knowable via the hash — irreversible.
CREATE TABLE IF NOT EXISTS external_verification_anchors (
  id                   SERIAL PRIMARY KEY,
  provider             TEXT NOT NULL,     -- 'github', later 'orcid', 'linkedin'
  anchor_hash          TEXT NOT NULL,     -- sha256(provider:external_id:pepper)
  user_id              TEXT NOT NULL,     -- HHTTPS user that owns this anchor
  trust_score_assigned INT  NOT NULL,     -- frozen at verification time
  verified_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_reverified_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, anchor_hash)
);

CREATE INDEX IF NOT EXISTS idx_eva_user
  ON external_verification_anchors(user_id);
CREATE INDEX IF NOT EXISTS idx_eva_provider_user
  ON external_verification_anchors(provider, user_id);

-- Session-side: track that this session has a github-verify boost so the
-- token-issue path can pick it up. Mirrors the email_verified columns.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name='sessions' AND column_name='github_verified') THEN
    ALTER TABLE sessions ADD COLUMN github_verified    BOOLEAN DEFAULT FALSE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name='sessions' AND column_name='github_trust_bonus') THEN
    ALTER TABLE sessions ADD COLUMN github_trust_bonus INT;
  END IF;
END$$;

-- Pending OAuth states (short-lived). Avoids stuffing OAuth flow state into
-- the session table where it doesn't belong.
CREATE TABLE IF NOT EXISTS github_oauth_pending (
  state        TEXT PRIMARY KEY,
  session_id   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 minutes')
);

CREATE INDEX IF NOT EXISTS idx_github_oauth_pending_session
  ON github_oauth_pending(session_id);
CREATE INDEX IF NOT EXISTS idx_github_oauth_pending_expires
  ON github_oauth_pending(expires_at);
