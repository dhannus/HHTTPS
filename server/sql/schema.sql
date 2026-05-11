-- HHTTPS v4.1 — PostgreSQL Schema
-- HumanProof Initiative · daniel.hannuschka@tweakz.de
--
-- All persistent state lives here. Any restart of Node.js leaves data intact.
-- Designed for ACID guarantees, indexes for hot paths, and TTL via cleanup jobs.

-- ─── Extensions ─────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS pgcrypto;        -- gen_random_uuid()

-- ─── Credentials (WebAuthn passkeys) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS credentials (
  credential_id      TEXT PRIMARY KEY,            -- base64url-encoded
  user_id            TEXT NOT NULL,
  public_key         BYTEA NOT NULL,
  counter            BIGINT NOT NULL DEFAULT 0,
  transports         TEXT[] DEFAULT '{}',
  device_type        TEXT,
  backed_up          BOOLEAN DEFAULT FALSE,
  registered_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS credentials_user_id_idx  ON credentials(user_id);
CREATE INDEX IF NOT EXISTS credentials_registered_at_idx ON credentials(registered_at);

-- ─── Sessions (verified, awaiting role declaration) ─────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  session_id         TEXT PRIMARY KEY,
  user_id            TEXT NOT NULL,
  credential_id      TEXT REFERENCES credentials(credential_id) ON DELETE SET NULL,
  device_type        TEXT,
  backed_up          BOOLEAN DEFAULT FALSE,
  verified           BOOLEAN DEFAULT TRUE,
  email_verified     BOOLEAN DEFAULT FALSE,
  email_level        TEXT,
  email_domain       TEXT,
  email_trust_bonus  INT,
  email_category     TEXT,
  emails_sent        INT DEFAULT 0,
  role               TEXT,
  role_level         TEXT,
  trust_score        INT DEFAULT 60,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx    ON sessions(user_id);

-- ─── WebAuthn challenges (short-lived) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS challenges (
  challenge_id       TEXT PRIMARY KEY,            -- userId or sessionId
  challenge          TEXT NOT NULL,
  user_id            TEXT,
  context            TEXT NOT NULL,               -- 'registration' | 'authentication'
  expires_at         TIMESTAMPTZ NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS challenges_expires_at_idx ON challenges(expires_at);

-- ─── Active access tokens ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tokens (
  jti                TEXT PRIMARY KEY,
  type               TEXT NOT NULL,               -- 'access' | 'machine'
  user_id            TEXT,
  role               TEXT,
  role_level         TEXT,
  trust_score        INT,
  method             TEXT,
  device_type        TEXT,
  operator_id        TEXT,                        -- for machine tokens
  issued_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS tokens_expires_at_idx ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS tokens_user_id_idx    ON tokens(user_id);

-- ─── Refresh tokens (long-lived, 7 days) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  jti                TEXT PRIMARY KEY,
  user_id            TEXT NOT NULL,
  credential_id      TEXT REFERENCES credentials(credential_id) ON DELETE CASCADE,
  role               TEXT,
  issued_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL,
  last_used_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at_idx ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx    ON refresh_tokens(user_id);

-- ─── Revoked tokens (permanent ban list, persists past expiry) ──────────────
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti                TEXT PRIMARY KEY,
  role               TEXT,
  revoked_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reason             TEXT
);

CREATE INDEX IF NOT EXISTS revoked_tokens_revoked_at_idx ON revoked_tokens(revoked_at);

-- ─── Email verifications (15-min TTL) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_verifications (
  token              TEXT PRIMARY KEY,
  email              TEXT NOT NULL,
  domain             TEXT NOT NULL,
  level              TEXT,
  trust_bonus        INT,
  category           TEXT,
  session_id         TEXT,
  used               BOOLEAN DEFAULT FALSE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS email_verifications_expires_at_idx ON email_verifications(expires_at);
CREATE INDEX IF NOT EXISTS email_verifications_email_idx      ON email_verifications(email);

-- ─── Role declarations (persistent user → role mapping) ─────────────────────
CREATE TABLE IF NOT EXISTS roles_declared (
  user_id            TEXT PRIMARY KEY,
  role               TEXT NOT NULL,
  role_level         TEXT NOT NULL,
  trust_score        INT NOT NULL,
  declared_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Machine operators (third-party bots) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS machine_operators (
  operator_id        TEXT PRIMARY KEY,
  operator_name      TEXT NOT NULL,
  operator_url       TEXT,
  purpose            TEXT NOT NULL,
  contact_email      TEXT,
  api_key_hash       TEXT NOT NULL,               -- sha256
  registered_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tokens_issued      INT DEFAULT 0,
  last_used_at       TIMESTAMPTZ,
  active             BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS machine_operators_active_idx ON machine_operators(active);

-- ─── Webhooks (third-party event subscriptions) ─────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
  webhook_id         TEXT PRIMARY KEY,
  url                TEXT NOT NULL,
  events             TEXT[] NOT NULL,
  secret             TEXT NOT NULL,
  active             BOOLEAN DEFAULT TRUE,
  failures           INT DEFAULT 0,
  deliveries         INT DEFAULT 0,
  last_delivery_at   TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS webhooks_active_idx ON webhooks(active);

-- ─── Webhook deliveries (audit log) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id         TEXT REFERENCES webhooks(webhook_id) ON DELETE CASCADE,
  event              TEXT NOT NULL,
  status             TEXT NOT NULL,               -- 'success' | 'failed' | 'pending'
  status_code        INT,
  attempt            INT DEFAULT 1,
  delivered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_webhook_idx ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS webhook_deliveries_delivered_at_idx ON webhook_deliveries(delivered_at);

-- ─── Stats counter (for /hhttps/stats) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS stats (
  metric             TEXT PRIMARY KEY,
  value              BIGINT NOT NULL DEFAULT 0,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO stats (metric, value) VALUES
  ('verifications', 0),
  ('tokens_issued', 0),
  ('tokens_revoked', 0),
  ('check_calls', 0),
  ('machine_checks', 0)
ON CONFLICT (metric) DO NOTHING;

-- ─── Cleanup function (called every 5 minutes by application) ───────────────
CREATE OR REPLACE FUNCTION cleanup_expired() RETURNS TABLE(
  deleted_tokens INT, deleted_refresh INT, deleted_sessions INT,
  deleted_challenges INT, deleted_emails INT
) AS $$
DECLARE
  t INT; r INT; s INT; c INT; e INT;
BEGIN
  DELETE FROM tokens             WHERE expires_at < NOW();           GET DIAGNOSTICS t = ROW_COUNT;
  DELETE FROM refresh_tokens     WHERE expires_at < NOW();           GET DIAGNOSTICS r = ROW_COUNT;
  DELETE FROM sessions           WHERE expires_at < NOW();           GET DIAGNOSTICS s = ROW_COUNT;
  DELETE FROM challenges         WHERE expires_at < NOW();           GET DIAGNOSTICS c = ROW_COUNT;
  DELETE FROM email_verifications WHERE expires_at < NOW() AND used = FALSE;  GET DIAGNOSTICS e = ROW_COUNT;
  RETURN QUERY SELECT t, r, s, c, e;
END;
$$ LANGUAGE plpgsql;

-- ─── Grant access to application role (set in install-pg.sh) ────────────────
-- This is a placeholder; real grants happen in install-pg.sh after role creation.
