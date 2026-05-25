-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS — Migration phase 7: Age group (orthogonal, EUDI-aligned)
--
-- Adds an OPTIONAL, orthogonal age_group claim to the OAuth authorization code,
-- so it can be carried into the OIDC id_token / userinfo when a client requests
-- the new `age_group` scope. age_group is INDEPENDENT of role (a person can be
-- both medical_professional AND adult_18_plus).
--
-- Phase 1 (this migration): age_group is self-declared only —
--   age_verified = FALSE, age_verification_method = 'self-declared', low trust.
-- Phase 3 (later): an EUDI Wallet PID presentation (age_over_NN, selective
--   disclosure) will set age_verified = TRUE, method = 'eudi-wallet'. No schema
--   change needed then — only the values change.
--
-- Groups (German legal thresholds):
--   minor_under_14 · minor_14_to_15 · minor_16_to_17 · adult_18_plus
--
-- Idempotent: safe to run multiple times (ADD COLUMN IF NOT EXISTS).
--
-- IMPORTANT: run this migration AS THE APP USER, not postgres:
--   PGPASSWORD=$DB_PASSWORD psql -U hhttps -d hhttps -h localhost \
--     -f server/sql/migration-phase-7-age-group.sql
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE authorization_codes
  ADD COLUMN IF NOT EXISTS age_group               TEXT,
  ADD COLUMN IF NOT EXISTS age_verified            BOOLEAN,
  ADD COLUMN IF NOT EXISTS age_verification_method TEXT;

-- The access/refresh token tables do not need new columns: age_group travels
-- inside the signed JWT payload (issueAccessToken spreads it via ...payload),
-- and the token store only tracks jti/role/trust for revocation. No change there.
