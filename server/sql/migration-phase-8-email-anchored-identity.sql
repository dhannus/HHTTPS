-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS — Migration phase 8: E-Mail-verankerte, stabile Identität
-- (feature `email-anchored-identity`, see docs/specs/email-anchored-identity)
--
-- Adds:
--   - identity_anchors:        HMAC(pepper, normalize(email)) → stable user_id
--                              + account pseudonym. The plaintext e-mail is
--                              NEVER stored here (hash only). (D1, D2, D3)
--   - identity_claims_cache:   plaintext e-mail, pseudonym and verified_methods
--                              per user_id, kept until transferred to the
--                              platform; rows expire (≤ 7 days). (D5, AK-16)
--   - sessions.pseudonym:      the session carries the account pseudonym.
--   - authorization_codes.{email, pseudonym, verified_methods}:
--                              claims copied onto the code at /oauth/approve;
--                              `email` is set to NULL when the code is claimed
--                              at /oauth/token (transferred ⇒ deleted, AK-17).
--                              verified_methods is a JSON array as TEXT, like
--                              `scopes`.
--   - oauth_clients.allowed_scopes += "email" for existing clients.
--
-- Idempotent: safe to run multiple times (IF NOT EXISTS / WHERE NOT ...).
-- The server also executes this file on boot (db.js: ensurePhase8Schema), so
-- a manual run is only needed for operators who want to migrate ahead of a
-- deploy or who run the app user without DDL rights.
--
-- IMPORTANT: run this migration AS THE APP USER, not postgres:
--   PGPASSWORD=$DB_PASSWORD psql -U hhttps -d hhttps -h localhost \
--     -f server/sql/migration-phase-8-email-anchored-identity.sql
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Identity anchors (email hash → stable user id) ────────────────────────
CREATE TABLE IF NOT EXISTS identity_anchors (
  email_hash    TEXT        PRIMARY KEY,           -- HMAC-SHA256(pepper, trim+lower(email)), hex
  user_id       TEXT        NOT NULL UNIQUE,       -- stable userId (pairwise sub derives from it)
  pseudonym     TEXT        NOT NULL,              -- account pseudonym, set once (AK-6/7/8)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Claims cache (plaintext until transferred to the platform) ────────────
CREATE TABLE IF NOT EXISTS identity_claims_cache (
  user_id          TEXT        PRIMARY KEY,
  email            TEXT        NOT NULL,           -- plaintext, as confirmed
  pseudonym        TEXT,
  verified_methods TEXT,                           -- JSON array, e.g. '["email","passkey"]'
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL            -- ≤ 7 days after last confirmation
);

CREATE INDEX IF NOT EXISTS idx_identity_claims_cache_expires ON identity_claims_cache(expires_at);

-- ─── Sessions carry the pseudonym ──────────────────────────────────────────
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS pseudonym TEXT;

-- ─── Authorization codes carry email / pseudonym / verified_methods ────────
ALTER TABLE authorization_codes
  ADD COLUMN IF NOT EXISTS email            TEXT,  -- only when scope `email`; NULLed on claim
  ADD COLUMN IF NOT EXISTS pseudonym        TEXT,
  ADD COLUMN IF NOT EXISTS verified_methods TEXT;  -- JSON array as text (like `scopes`)

-- ─── Scope `email` for existing clients ────────────────────────────────────
-- Deliberate assumption from requirements.md §6: already registered clients
-- get `email` appended to allowed_scopes so the transfer works immediately.
-- If that is not wanted for a deployment, remove this block before running.
UPDATE oauth_clients
   SET allowed_scopes = (allowed_scopes::jsonb || '["email"]'::jsonb)::text
 WHERE NOT (allowed_scopes::jsonb ? 'email');

-- ─── Grants for application user ───────────────────────────────────────────
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hhttps') THEN
    ALTER TABLE identity_anchors      OWNER TO hhttps;
    ALTER TABLE identity_claims_cache OWNER TO hhttps;
    GRANT SELECT, INSERT, UPDATE, DELETE ON
      identity_anchors, identity_claims_cache TO hhttps;
  END IF;
END$$;
