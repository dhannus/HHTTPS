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

-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS — Migration Phase 11 (Projekt-Review 2026-09, Welle 3 / AP6)
-- ════════════════════════════════════════════════════════════════════════════
--
-- Finding:
--   AP6-11 (#213) `stats` is a row-based (metric, value) table. Phase 2.5 and
--                 phase 3a nonetheless added six counter COLUMNS to it that no
--                 code ever read or wrote — db.stats.increment() has always
--                 used rows. The columns are dropped and the six metrics are
--                 seeded as rows, the way schema.sql seeds the others.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE stats
  DROP COLUMN IF EXISTS signatures_created,
  DROP COLUMN IF EXISTS signatures_verified,
  DROP COLUMN IF EXISTS signatures_revoked,
  DROP COLUMN IF EXISTS oauth_authorizations,
  DROP COLUMN IF EXISTS oauth_tokens_issued,
  DROP COLUMN IF EXISTS oauth_logins;

INSERT INTO stats (metric, value) VALUES
  ('signatures_created',   0),
  ('signatures_verified',  0),
  ('signatures_revoked',   0),
  ('oauth_authorizations', 0),
  ('oauth_tokens_issued',  0),
  ('oauth_logins',         0)
ON CONFLICT (metric) DO NOTHING;
