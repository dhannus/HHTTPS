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
-- HHTTPS — Migration phase 6: Workload Identity Federation
--
-- Lets CI/CD workloads (GitHub Actions first) exchange their short-lived OIDC
-- token for an HHTTPS machine token — WITHOUT any long-lived secret stored in
-- the CI system. The flow:
--
--   1. (once)  A machine operator binds a GitHub repository to their operator
--              identity via POST /hhttps/machine/workload/bind (uses apiKey once).
--   2. (in CI) The workflow presents its GitHub Actions OIDC token to
--              POST /hhttps/machine/exchange. HHTTPS verifies the token against
--              GitHub's JWKS, matches the repository to a binding, and issues an
--              HHTTPS machine token carrying the workflow claims as attributes.
--
-- Unlike human GitHub verification (which is pseudonymous), workload identity is
-- intentionally ATTRIBUTABLE: the whole point is that a platform can see exactly
-- which repo/workflow/run minted the token. That transparency is the feature.
--
--
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS workload_identities (
  id                 SERIAL PRIMARY KEY,
  provider           TEXT NOT NULL,            -- 'github-actions'
  repository         TEXT NOT NULL,            -- e.g. 'dhannus/HHTTPS'
  subject_pattern    TEXT,                     -- optional sub constraint, e.g.
                                               --   'repo:dhannus/HHTTPS:ref:refs/heads/main'
                                               -- NULL = accept any sub for this repo
  expected_audience  TEXT,                     -- optional; NULL = use server BASE_URL
  operator_id        TEXT NOT NULL REFERENCES machine_operators(operator_id) ON DELETE CASCADE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at       TIMESTAMPTZ,
  exchanges          INT DEFAULT 0,
  active             BOOLEAN DEFAULT TRUE,
  UNIQUE (provider, repository, subject_pattern)
);

CREATE INDEX IF NOT EXISTS idx_workload_repo
  ON workload_identities(provider, repository) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_workload_operator
  ON workload_identities(operator_id);
