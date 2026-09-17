-- ============================================================================
-- HHTTPS — Migration Phase 10 (Projekt-Review 2026-09, Welle 2)
-- ============================================================================
-- Two sections (same convention as phase 8 / phase 9):
--   1. BOOT-DDL  — idempotent DDL, applied by the server at boot when the
--                  applied-check fails.
--   2. OPERATOR  — run manually:  psql -U hhttps -d hhttps -f <this file>
--                  (psql runs BOTH sections; the DDL is idempotent).
--
-- Findings: AP3-24 (#128) — consumed `email_verifications` rows were never
--           deleted and the hot lookups had no index.
-- ════════════════════════════ 1. BOOT-DDL ══════════════════════════════════

-- AP3-24: the two lookups on this table filter by session_id resp.
-- (code, session_id) — getAndConsumeByCode() and invalidateForSession() used
-- to run a seq scan over every verification row ever written.
CREATE INDEX IF NOT EXISTS email_verifications_session_idx
  ON email_verifications(session_id);
CREATE INDEX IF NOT EXISTS email_verifications_code_session_idx
  ON email_verifications(code, session_id);

-- AP3-24: every consume path sets used = TRUE, and cleanup_expired() deleted
-- expired rows only while used = FALSE — so the consumed rows stayed forever.
-- An expired row is worthless whether it was used or not.
CREATE OR REPLACE FUNCTION cleanup_expired() RETURNS TABLE(
  deleted_tokens INT, deleted_refresh INT, deleted_sessions INT,
  deleted_challenges INT, deleted_emails INT
) AS $$
DECLARE
  t INT; r INT; s INT; c INT; e INT;
BEGIN
  DELETE FROM tokens             WHERE expires_at < NOW();           GET DIAGNOSTICS t = ROW_COUNT;
  DELETE FROM refresh_tokens     WHERE expires_at < NOW();           GET DIAGNOSTICS r = ROW_COUNT;
  DELETE FROM sessions           WHERE expires_at < NOW();           GET DIAGNOSTICS s = ROW_COUNT;
  DELETE FROM challenges         WHERE expires_at < NOW();           GET DIAGNOSTICS c = ROW_COUNT;
  DELETE FROM email_verifications WHERE expires_at < NOW();          GET DIAGNOSTICS e = ROW_COUNT;
  RETURN QUERY SELECT t, r, s, c, e;
END;
$$ LANGUAGE plpgsql;

-- >>> BOOT-DDL END
-- ════════════════════════════ 2. OPERATOR ══════════════════════════════════

-- One-off: remove the consumed rows that accumulated before this migration.
-- They are expired AND used — nothing reads them any more.
DELETE FROM email_verifications WHERE expires_at < NOW();
