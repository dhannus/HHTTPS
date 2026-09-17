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

-- ═══════════════════════════════════════════════════════════════════════════
-- HHTTPS Phase 3b.1 — Domain/Email match tracking
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Adds: `domain_email_match` boolean on oauth_clients.
-- TRUE iff contact_email's domain matches the apex of homepage_url's domain.
-- Required for `verified` status (along with DNS verification + admin review).
--
-- Computed by server code on email change. Idempotent migration.
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

ALTER TABLE oauth_clients
  ADD COLUMN IF NOT EXISTS domain_email_match BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.domain_email_match IS
  'TRUE iff contact_email apex-domain matches homepage_url apex-domain. Required for verified status.';

-- For existing verified clients, set to TRUE (they were manually approved,
-- domain match is implied by admin review).
UPDATE oauth_clients
   SET domain_email_match = TRUE
 WHERE verification_status = 'verified'
   AND contact_email IS NOT NULL;

COMMIT;
