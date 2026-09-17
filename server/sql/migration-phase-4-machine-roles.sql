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
-- HHTTPS — Migration: machine operators can self-declare a role
--
-- Adds an optional `role` column to machine_operators. Bots can declare which
-- role they identify as when calling /hhttps/machine/register. The role is
-- self-declared in pilot mode (no verification beyond what we'd require for
-- humans does not exist for bots yet — no standard).
--
-- The role becomes part of the issued machine token's claims, so origins
-- (like ask.iamhmn.org) can apply role-based logic to bot interactions just
-- as they do for humans.
--
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE machine_operators
  ADD COLUMN IF NOT EXISTS role TEXT,
  ADD COLUMN IF NOT EXISTS role_label TEXT,
  ADD COLUMN IF NOT EXISTS role_icon  TEXT;

CREATE INDEX IF NOT EXISTS idx_machine_operators_role
  ON machine_operators(role) WHERE role IS NOT NULL;

-- For existing bots without a role: leave NULL — token won't carry a role claim.
