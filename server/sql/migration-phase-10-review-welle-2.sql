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
-- Findings: AP1-34 (revoked_tokens was read on every check but never
--                   cleaned — a jti older than REFRESH_TTL (7 d) can no longer
--                   belong to a verifiable token),
--           AP1-35 (webhook_deliveries grew by one row per delivery attempt
--                   with no retention).
-- Both go into cleanup_expired() (called every 5 minutes by server.js). The
-- RETURNS TABLE signature gains two columns, so the function is dropped and
-- re-created (CREATE OR REPLACE cannot change a return type).
-- ════════════════════════════ 1. BOOT-DDL ══════════════════════════════════

DROP FUNCTION IF EXISTS cleanup_expired();
CREATE FUNCTION cleanup_expired() RETURNS TABLE(
  deleted_tokens INT, deleted_refresh INT, deleted_sessions INT,
  deleted_challenges INT, deleted_emails INT,
  deleted_revoked INT, deleted_webhook_deliveries INT
) AS $$
DECLARE
  t INT; r INT; s INT; c INT; e INT; v INT; w INT;
BEGIN
  DELETE FROM tokens             WHERE expires_at < NOW();           GET DIAGNOSTICS t = ROW_COUNT;
  DELETE FROM refresh_tokens     WHERE expires_at < NOW();           GET DIAGNOSTICS r = ROW_COUNT;
  DELETE FROM sessions           WHERE expires_at < NOW();           GET DIAGNOSTICS s = ROW_COUNT;
  DELETE FROM challenges         WHERE expires_at < NOW();           GET DIAGNOSTICS c = ROW_COUNT;
  DELETE FROM email_verifications WHERE expires_at < NOW() AND used = FALSE;  GET DIAGNOSTICS e = ROW_COUNT;
  DELETE FROM revoked_tokens     WHERE revoked_at < NOW() - INTERVAL '8 days';     GET DIAGNOSTICS v = ROW_COUNT;
  DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - INTERVAL '30 days';  GET DIAGNOSTICS w = ROW_COUNT;
  RETURN QUERY SELECT t, r, s, c, e, v, w;
END;
$$ LANGUAGE plpgsql;

-- >>> BOOT-DDL END
-- ════════════════════════════ 2. OPERATOR ══════════════════════════════════

-- One-off backfill so the first periodic run does not delete a huge batch in
-- one transaction on a long-running installation (idempotent).
DELETE FROM revoked_tokens     WHERE revoked_at   < NOW() - INTERVAL '8 days';
DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - INTERVAL '30 days';
