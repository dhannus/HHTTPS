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
-- IMPORTANT: run this migration AS THE APP USER, not postgres:
--   PGPASSWORD=$DB_PASSWORD psql -U hhttps -d hhttps -h localhost \
--     < server/sql/migration-phase-6-workload-identity.sql
-- Running it via `sudo -u postgres` makes postgres the table owner and the app
-- gets "permission denied" / "must be owner" errors.
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
