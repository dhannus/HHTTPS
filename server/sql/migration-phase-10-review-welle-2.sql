-- ─── HOW TO RUN (uniform for every file in sql/ — AP6-49, #200) ─────
--   cd /var/www/hhttps && node scripts/migrate.js
-- That runner is the ONE supported way (db.js: MIGRATIONS is the registry,
-- `schema_migrations` the ledger). It applies pending files in order AS THE
-- APP USER. Do NOT use `sudo -u postgres psql -f …`: postgres then owns the
-- objects and the app fails on the next ALTER with "must be owner of …".
-- sql/ownership-hhttps.sql repairs an installation where that happened.
-- Consequence of the convention: no file here carries OWNER/GRANT blocks.
-- Files with a "BOOT-DDL / OPERATOR" split: the runner applies BOTH sections;
-- the server applies only the BOOT-DDL part at boot.
-- ─────────────────────────────────────────────────────────────────────────

-- ============================================================================
-- HHTTPS — Migration Phase 10 (Projekt-Review 2026-09, Welle 2 / AP6)
-- ============================================================================
-- Two sections (same convention as phase 8 and 9):
--   1. BOOT-DDL  — idempotent DDL, applied by the server at boot when the
--                  applied-check (db.js: phase10SchemaApplied) fails.
--   2. OPERATOR  — the data part; the migration runner applies it too.
--
-- Findings:
--   AP6-06 (#73)  email_verifications.code was created only by a
--                 fire-and-forget ALTER on module import — it is now part of
--                 schema.sql and of the boot DDL.
--   AP6-03 (#58)  cleanup_expired() only removed rows with used = FALSE, so
--                 every sign-in left at least one row behind forever. The hot
--                 path filters on session_id (+ code), never on `email`.
--   AP6-15 (#107) oauth_clients.email_token now holds sha256(token); the
--                 outstanding plaintext tokens can never match again and are
--                 nulled in the OPERATOR section.
--   AP1 (Welle 2) cleanup_expired() also applies a retention to revoked_tokens
--                 and webhook_deliveries, which grew without bound.
--   AP5-29        … and removes platform drafts whose contact address was
--                 never confirmed.
--   AP5 (Welle 2) the workload-identity module was deleted in this wave; its
--                 table is dropped in the OPERATOR section.
--
-- ════════════════════════════ 1. BOOT-DDL ══════════════════════════════════

-- ─── AP6-06: the `code` column is part of the schema ────────────────────────
-- Holds the sha256 of the 6-digit code the user types into the original tab.
ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS code TEXT;

-- ─── AP6-03: index the hot path, drop the unused one ────────────────────────
-- getAndConsumeByCode / invalidateForSession filter on session_id; `email`
-- holds a sha256 and is never used as a lookup key.
CREATE INDEX IF NOT EXISTS email_verifications_session_id_idx ON email_verifications(session_id);
-- AP3-24: getAndConsumeByCode() filters on (code, session_id) together.
CREATE INDEX IF NOT EXISTS email_verifications_code_session_idx ON email_verifications(code, session_id);
DROP INDEX IF EXISTS email_verifications_email_idx;

-- ─── AP6-03 / AP1 / AP5-29: what cleanup_expired() removes ──────────────────
-- Identical body to the one in schema.sql — keep the two in sync.
-- The RETURNS TABLE signature gains columns, which CREATE OR REPLACE cannot
-- do — drop the old function first (nothing but db.js calls it).
DROP FUNCTION IF EXISTS cleanup_expired();
CREATE OR REPLACE FUNCTION cleanup_expired() RETURNS TABLE(
  deleted_tokens INT, deleted_refresh INT, deleted_sessions INT,
  deleted_challenges INT, deleted_emails INT,
  deleted_revoked INT, deleted_webhook_deliveries INT, deleted_stale_clients INT
) AS $$
DECLARE
  t INT; r INT; s INT; c INT; e INT; v INT; w INT; p INT;
BEGIN
  DELETE FROM tokens             WHERE expires_at < NOW();           GET DIAGNOSTICS t = ROW_COUNT;
  DELETE FROM refresh_tokens     WHERE expires_at < NOW();           GET DIAGNOSTICS r = ROW_COUNT;
  DELETE FROM sessions           WHERE expires_at < NOW();           GET DIAGNOSTICS s = ROW_COUNT;
  DELETE FROM challenges         WHERE expires_at < NOW();           GET DIAGNOSTICS c = ROW_COUNT;
  -- AP6-03: expired rows go regardless of `used` (both consume paths require
  -- expires_at > NOW(), so an expired row can never be redeemed); consumed
  -- rows are kept for 24 h so an operator can still inspect a fresh sign-in.
  DELETE FROM email_verifications
   WHERE expires_at < NOW()
      OR (used = TRUE AND created_at < NOW() - INTERVAL '24 hours');
  GET DIAGNOSTICS e = ROW_COUNT;
  -- AP1 (Welle 2): the revocation list was "permanent". A jti is only ever
  -- checked while the token could still be presented, so 90 days is far past
  -- the longest token lifetime.
  DELETE FROM revoked_tokens     WHERE revoked_at < NOW() - INTERVAL '90 days';
  GET DIAGNOSTICS v = ROW_COUNT;
  -- AP1 (Welle 2): the delivery log is an audit trail, not storage.
  DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - INTERVAL '30 days';
  GET DIAGNOSTICS w = ROW_COUNT;
  -- AP5-29: platform drafts whose contact address was never confirmed.
  DELETE FROM oauth_clients
   WHERE verification_status = 'email_pending'
     AND email_token_expires_at < NOW() - INTERVAL '7 days';
  GET DIAGNOSTICS p = ROW_COUNT;
  RETURN QUERY SELECT t, r, s, c, e, v, w, p;
END;
$$ LANGUAGE plpgsql;

-- >>> BOOT-DDL END
-- Everything below this marker is NEVER executed by the server: db.js reads
-- the file only up to this line (BOOT_DDL_FILES in db.js).
-- ════════════════════════════ 2. OPERATOR ══════════════════════════════════

-- ─── AP6-15: invalidate plaintext e-mail confirmation tokens ────────────────
-- db.js now stores sha256(token) (64 hex chars) and looks tokens up by hash.
-- A row that still holds a plaintext token (base64url, 32 chars) can never be
-- matched again: null it, so the dashboard offers "resend" instead of showing
-- a link that silently never confirms. Already-hashed rows are untouched.
UPDATE oauth_clients
   SET email_token = NULL,
       email_token_expires_at = NULL
 WHERE email_token IS NOT NULL
   AND email_token !~ '^[0-9a-f]{64}$';

-- ─── AP5 (Welle 2): drop the workload-identity table ────────────────────────
-- server/workload-identity.js was removed in this review wave, so nothing
-- reads or writes `workload_identities` any more. The table holds only
-- bindings (provider, repository, operator_id) — no user data that would have
-- to be preserved, and a binding is re-created by one API call.
--
-- migration-phase-6-workload-identity.sql deliberately STAYS in the chain:
-- the ledger (schema_migrations) must keep recording the history a database
-- actually went through, and a fresh install still replays phase 6 before
-- this file drops the table again. The drop lives here, in the OPERATOR
-- section, so the server never does it on its own at boot.
DROP TABLE IF EXISTS workload_identities;

-- ─── AP6-08: table ownership ────────────────────────────────────────────────
-- Not part of this file (it needs superuser rights): see
-- server/sql/ownership-hhttps.sql, which install-pg.sh and scripts/deploy-all.sh
-- run as postgres before the migration chain.
