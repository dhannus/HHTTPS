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
-- HHTTPS — Migration phase 4b: machine operators may bind a public key (jkt)
--
-- Adds `key_jkt` to machine_operators: the RFC 7638 JWK thumbprint of the
-- optional `publicKeyJwk` a bot submits at /hhttps/machine/register. When set,
-- issued machine tokens carry `cnf: { jkt }` so origins can demand
-- proof-of-possession. db.js (machineOperators.create) has written this column
-- since phase 6 (workload identity), but no migration ever created it — on a
-- database without it every /machine/register failed with 42703 and, because
-- the route had no error handling, the unhandled rejection terminated the
-- server process (GitHub issue #7).
--
-- BOOT-DDL: the server applies this file itself at boot (db.js: BOOT_DDL_FILES)
-- when `machine_operators.key_jkt` is missing. Nothing else to do.
--
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE machine_operators
  ADD COLUMN IF NOT EXISTS key_jkt TEXT;
