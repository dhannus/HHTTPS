-- ═══════════════════════════════════════════════════════════════════════════
-- HHTTPS Phase 3b — Developer Self-Service Registration
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Prerequisites: schema.sql, migration-phase-2.5.sql, migration-phase-3a.sql
-- Idempotent. Safe to run multiple times.
--
-- Architectural notes:
--   • HHTTPS has no `users` table. Identity = `user_id` (TEXT) referenced
--     across credentials, sessions, tokens, etc. This migration follows that
--     pattern.
--   • Admin is determined by membership in `admins` table (KISS — single
--     boolean per-user equivalent, but as a separate join table to avoid
--     adding new column to a non-existent users table).
--   • Phase 3a already created some columns on oauth_clients
--     (description, homepage_url, logo_url, contact_email, verified_at,
--     verified_by, is_active). This migration only adds what's missing.
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

-- ─── 1. Admins ─────────────────────────────────────────────────────────────
-- Membership-style: a user_id is admin iff it appears here.
-- To grant admin:   INSERT INTO admins (user_id, note) VALUES ('<id>', 'reason');
-- To revoke admin:  DELETE FROM admins WHERE user_id = '<id>';

CREATE TABLE IF NOT EXISTS admins (
  user_id      TEXT        PRIMARY KEY,
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  granted_by   TEXT,
  note         TEXT
);

COMMENT ON TABLE admins IS
  'Membership table for admin privileges. Presence of user_id = admin.';


-- ─── 2. Extend oauth_clients with verification workflow ────────────────────
-- Phase 3a created the base table. We add only the new workflow fields.

ALTER TABLE oauth_clients
  ADD COLUMN IF NOT EXISTS impressum_url     VARCHAR(500),

  -- Verification workflow state
  -- 'draft'             — created via API, awaiting email confirmation
  -- 'email_pending'     — email sent, awaiting user's confirmation click
  -- 'unverified'        — email confirmed, can be used (amber warning shown)
  -- 'pending_review'    — owner submitted for manual admin verification
  -- 'verified'          — admin-approved, gets green badge on consent page
  -- 'rejected'          — admin rejected with reason
  -- 'suspended'         — admin disabled the platform (abuse, complaint, etc.)
  ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'draft',

  -- Email verification (always required, double-opt-in)
  ADD COLUMN IF NOT EXISTS email_token       TEXT,
  ADD COLUMN IF NOT EXISTS email_token_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ,

  -- DNS verification (optional, gives "DNS-verified" badge)
  ADD COLUMN IF NOT EXISTS dns_token         TEXT,
  ADD COLUMN IF NOT EXISTS dns_verified_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS dns_last_checked_at TIMESTAMPTZ,

  -- Admin review
  ADD COLUMN IF NOT EXISTS submitted_for_review_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS reviewed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rejection_reason  TEXT,

  -- Cached role snapshot at submission (for admin queue sorting)
  ADD COLUMN IF NOT EXISTS owner_role_at_submit  TEXT,
  ADD COLUMN IF NOT EXISTS owner_trust_at_submit INT;

-- Constraint on verification_status values
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oauth_clients_verification_status_check'
  ) THEN
    ALTER TABLE oauth_clients
      ADD CONSTRAINT oauth_clients_verification_status_check
      CHECK (verification_status IN (
        'draft', 'email_pending', 'unverified',
        'pending_review', 'verified', 'rejected', 'suspended'
      ));
  END IF;
END$$;

-- Migrate existing Phase 3a data:
--   verified=TRUE  → verification_status='verified'
--   verified=FALSE → verification_status='unverified' (was already in use)
UPDATE oauth_clients
   SET verification_status = 'verified',
       email_verified_at = COALESCE(email_verified_at, created_at)
 WHERE verified = TRUE
   AND verification_status = 'draft';

UPDATE oauth_clients
   SET verification_status = 'unverified',
       email_verified_at = COALESCE(email_verified_at, created_at)
 WHERE verified = FALSE
   AND verification_status = 'draft';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_oauth_clients_status
  ON oauth_clients(verification_status);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_pending_review
  ON oauth_clients(verification_status, submitted_for_review_at DESC NULLS LAST)
  WHERE verification_status = 'pending_review';

CREATE INDEX IF NOT EXISTS idx_oauth_clients_owner_recent
  ON oauth_clients(owner_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_email_token
  ON oauth_clients(email_token)
  WHERE email_token IS NOT NULL;


-- ─── 3. Privacy-preserving daily stats ─────────────────────────────────────
-- Aggregated per-day, per-client. NO user IDs, NO timestamps. Just counts.

CREATE TABLE IF NOT EXISTS client_stats_daily (
  client_id        VARCHAR(64) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  day              DATE        NOT NULL,
  role_bucket      TEXT        NOT NULL,
  trust_bucket     TEXT        NOT NULL,        -- 'low' | 'medium' | 'high'
  login_count      INT         NOT NULL DEFAULT 0,
  PRIMARY KEY (client_id, day, role_bucket, trust_bucket)
);

CREATE INDEX IF NOT EXISTS idx_client_stats_client_day
  ON client_stats_daily(client_id, day DESC);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'client_stats_trust_bucket_check'
  ) THEN
    ALTER TABLE client_stats_daily
      ADD CONSTRAINT client_stats_trust_bucket_check
      CHECK (trust_bucket IN ('low', 'medium', 'high'));
  END IF;
END$$;

COMMENT ON TABLE client_stats_daily IS
  'Per-day per-client login counts. No user IDs. Privacy-by-design.';


-- ─── 4. Audit log for admin actions ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin_actions (
  id            BIGSERIAL PRIMARY KEY,
  action_type   TEXT        NOT NULL,    -- 'verify_client' | 'reject_client' | 'suspend_client' | 'grant_admin' | 'revoke_admin'
  target_type   TEXT        NOT NULL,    -- 'oauth_client' | 'user' | 'admin'
  target_id     TEXT        NOT NULL,
  admin_user_id TEXT        NOT NULL,
  details       JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_actions_target
  ON admin_actions(target_type, target_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_actions_admin
  ON admin_actions(admin_user_id, created_at DESC);

COMMENT ON TABLE admin_actions IS
  'Append-only audit log of admin actions. For transparency and dispute resolution.';


-- ─── 5. Ownership grants ───────────────────────────────────────────────────
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hhttps') THEN
    EXECUTE 'ALTER TABLE admins             OWNER TO hhttps';
    EXECUTE 'ALTER TABLE client_stats_daily OWNER TO hhttps';
    EXECUTE 'ALTER TABLE admin_actions      OWNER TO hhttps';
    EXECUTE 'ALTER SEQUENCE admin_actions_id_seq OWNER TO hhttps';

    GRANT ALL ON admins             TO hhttps;
    GRANT ALL ON client_stats_daily TO hhttps;
    GRANT ALL ON admin_actions      TO hhttps;
    GRANT ALL ON SEQUENCE admin_actions_id_seq TO hhttps;
  END IF;
END$$;

COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════
-- POST-MIGRATION: Bootstrap yourself as admin
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Find your user_id (run in DevTools on https://hhttps.org):
--   JSON.parse(localStorage.hhttps_identity).uid
--
-- Then in psql:
--   INSERT INTO admins (user_id, note)
--   VALUES ('<your-user-id>', 'Project operator — bootstrap');
--
-- Verify:
--   SELECT * FROM admins;
-- ═══════════════════════════════════════════════════════════════════════════
