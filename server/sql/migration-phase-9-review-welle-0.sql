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
-- HHTTPS — Migration Phase 9 (Projekt-Review 2026-09, Welle 0)
-- ============================================================================
-- Two sections (same convention as phase 8):
--   1. BOOT-DDL  — idempotent DDL, applied by the server at boot when the
--                  applied-check (webhooks.owner_user_id) fails.
--   2. OPERATOR  — the data part; the migration runner applies it too.
--
-- Findings: AP5-16 / AP1-22 (webhooks bound to an owner, secrets never listed),
--           AP2-01 / AP4-03 (refresh tokens bound to a platform),
--           AP7 (Privacy-Pass module removed → its tables are dropped).
-- ════════════════════════════ 1. BOOT-DDL ══════════════════════════════════

-- AP5-16: a webhook belongs to the HHTTPS user who registered it. Rows created
-- before this migration have no owner and are therefore invisible to
-- GET/DELETE /hhttps/webhooks (they keep firing until an operator removes them,
-- see the OPERATOR section).
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS owner_user_id TEXT;
CREATE INDEX IF NOT EXISTS webhooks_owner_idx ON webhooks(owner_user_id);

-- AP2-01 / AP4-03: OAuth refresh tokens are bound to their platform so a
-- "disconnect" can end exactly that chain; HHTTPS refresh tokens keep NULL.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS client_id TEXT;
CREATE INDEX IF NOT EXISTS refresh_tokens_user_client_idx ON refresh_tokens(user_id, client_id);

-- >>> BOOT-DDL END
-- ════════════════════════════ 2. OPERATOR ══════════════════════════════════

-- Ownerless legacy webhooks: nobody can list or delete them through the API
-- any more. Review them and deactivate (or assign an owner) explicitly:
--   SELECT webhook_id, url, events, created_at FROM webhooks WHERE owner_user_id IS NULL;
UPDATE webhooks SET active = FALSE WHERE owner_user_id IS NULL;

-- AP7: the Privacy-Pass module (server/privacy-pass/) was removed in Welle 0.
-- Its tables hold only wallet state (issuance log, pending e-mail links,
-- recovery codes, redeemed tokens, attribute verifications) — drop them.
DROP TABLE IF EXISTS pp_redeemed;
DROP TABLE IF EXISTS pp_recovery_codes;
DROP TABLE IF EXISTS pp_email_pending;
DROP TABLE IF EXISTS pp_attribute_verifications;
DROP TABLE IF EXISTS pp_issuance_log;
