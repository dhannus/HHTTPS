-- ============================================================================
-- HHTTPS — Migration Phase 10 (Projekt-Review 2026-09, Welle 2)
-- ============================================================================
-- Two sections (same convention as phase 8 / 9):
--   1. BOOT-DDL  — idempotent DDL, applied by the server at boot when the
--                  applied-check fails (cleanup_expired() has fewer than 7
--                  output columns). Wiring: db.js BOOT_DDL_FILES + scripts/migrate.js.
--   2. OPERATOR  — run manually:  psql -U hhttps -d hhttps -f <this file>
--                  (psql runs BOTH sections; everything here is idempotent).
--
-- Findings:
--   AP1-34 (#132) revoked_tokens was read on every check but never cleaned —
--                 a jti older than REFRESH_TTL (7 d) can no longer belong to
--                 a verifiable token.
--   AP1-35 (#139) webhook_deliveries grew by one row per delivery attempt
--                 with no retention.
--   AP3-24 (#128) consumed email_verifications rows were never deleted
--                 (cleanup ran with `used = FALSE`) and the hot lookups had
--                 no index.
--   AP5-29 (#179) unauthenticated plugin registrations left `email_pending`
--                 oauth_clients drafts behind that are never confirmed.
-- All of it goes into cleanup_expired() (called every 5 minutes by server.js).
-- The RETURNS TABLE signature gains columns, so the function is dropped and
-- re-created (CREATE OR REPLACE cannot change a return type).
-- ════════════════════════════ 1. BOOT-DDL ══════════════════════════════════

-- AP3-24: the two lookups on this table filter by session_id resp.
-- (code, session_id) — getAndConsumeByCode() and invalidateForSession() used
-- to run a seq scan over every verification row ever written.
CREATE INDEX IF NOT EXISTS email_verifications_session_idx
  ON email_verifications(session_id);
CREATE INDEX IF NOT EXISTS email_verifications_code_session_idx
  ON email_verifications(code, session_id);

DROP FUNCTION IF EXISTS cleanup_expired();
CREATE FUNCTION cleanup_expired() RETURNS TABLE(
  deleted_tokens INT, deleted_refresh INT, deleted_sessions INT,
  deleted_challenges INT, deleted_emails INT,
  deleted_revoked INT, deleted_webhook_deliveries INT, deleted_client_drafts INT
) AS $$
DECLARE
  t INT; r INT; s INT; c INT; e INT; v INT; w INT; d INT;
BEGIN
  DELETE FROM tokens             WHERE expires_at < NOW();           GET DIAGNOSTICS t = ROW_COUNT;
  DELETE FROM refresh_tokens     WHERE expires_at < NOW();           GET DIAGNOSTICS r = ROW_COUNT;
  DELETE FROM sessions           WHERE expires_at < NOW();           GET DIAGNOSTICS s = ROW_COUNT;
  DELETE FROM challenges         WHERE expires_at < NOW();           GET DIAGNOSTICS c = ROW_COUNT;
  -- AP3-24: an expired row is worthless whether it was used or not.
  DELETE FROM email_verifications WHERE expires_at < NOW();          GET DIAGNOSTICS e = ROW_COUNT;
  DELETE FROM revoked_tokens     WHERE revoked_at < NOW() - INTERVAL '8 days';     GET DIAGNOSTICS v = ROW_COUNT;
  DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - INTERVAL '30 days';  GET DIAGNOSTICS w = ROW_COUNT;
  -- AP5-29: plugin drafts nobody ever confirmed (the token is long expired).
  DELETE FROM oauth_clients      WHERE verification_status = 'email_pending'
                                   AND email_verified_at IS NULL
                                   AND email_token_expires_at < NOW() - INTERVAL '7 days';
  GET DIAGNOSTICS d = ROW_COUNT;
  RETURN QUERY SELECT t, r, s, c, e, v, w, d;
END;
$$ LANGUAGE plpgsql;

-- >>> BOOT-DDL END
-- ════════════════════════════ 2. OPERATOR ══════════════════════════════════

-- One-off backfill so the first periodic run does not delete a huge batch in
-- one transaction on a long-running installation (all idempotent).
DELETE FROM email_verifications WHERE expires_at   < NOW();
DELETE FROM revoked_tokens      WHERE revoked_at   < NOW() - INTERVAL '8 days';
DELETE FROM webhook_deliveries  WHERE delivered_at < NOW() - INTERVAL '30 days';
DELETE FROM oauth_clients       WHERE verification_status = 'email_pending'
                                  AND email_verified_at IS NULL
                                  AND email_token_expires_at < NOW() - INTERVAL '7 days';
