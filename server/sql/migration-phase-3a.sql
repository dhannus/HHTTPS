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
-- HHTTPS Phase 3a — OAuth 2.0 / OpenID Connect Provider
--
-- Adds tables for:
--   - oauth_clients:        Registered third-party platforms (verified or not)
--   - authorization_codes:  Short-lived (60s) codes for OAuth code exchange
--   - connected_platforms:  User ↔ Platform connections (for "my logins" UI
--                           and one-click revocation)
--
-- Design constraints:
--   - Pairwise Subject IDs by default: each platform sees a different
--     pseudonymous user ID, preventing cross-platform tracking
--   - Public Pseudonym Mode opt-in for platforms that need a stable shared ID
--   - PKCE enforced for public clients (no client_secret)
-- ════════════════════════════════════════════════════════════════════════════

-- ─── OAuth Clients (third-party platforms) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id          VARCHAR(64)  PRIMARY KEY,
  client_secret_hash VARCHAR(128),                -- bcrypt or sha256, NULL = public client (PKCE required)
  name               VARCHAR(120) NOT NULL,
  description        TEXT,
  homepage_url       VARCHAR(500),
  redirect_uris      TEXT NOT NULL,               -- JSON array, exact-match
  allowed_scopes     TEXT NOT NULL DEFAULT '["openid","role"]',  -- JSON array
  subject_type       VARCHAR(20) NOT NULL DEFAULT 'pairwise',     -- 'pairwise' | 'public'
  logo_url           VARCHAR(500),
  contact_email      VARCHAR(120),

  -- Verification status (see Phase 3b for full workflow)
  verified           BOOLEAN NOT NULL DEFAULT FALSE,
  verified_at        TIMESTAMPTZ,
  verified_by        VARCHAR(64),                 -- admin user_id who approved

  owner_user_id      VARCHAR(64),                 -- HHTTPS user_id of owner

  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at       TIMESTAMPTZ,
  is_active          BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_owner    ON oauth_clients(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_verified ON oauth_clients(verified)
  WHERE verified = TRUE;

-- ─── Authorization Codes (60-sec single-use) ───────────────────────────────
CREATE TABLE IF NOT EXISTS authorization_codes (
  code                 VARCHAR(48)  PRIMARY KEY,  -- random base64url string
  client_id            VARCHAR(64)  NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id              VARCHAR(64)  NOT NULL,
  redirect_uri         VARCHAR(500) NOT NULL,     -- bound to issuance request
  scopes               TEXT NOT NULL,             -- JSON array of granted scopes
  pkce_challenge       VARCHAR(128),              -- code_challenge from auth request
  pkce_method          VARCHAR(10),               -- 'S256' or 'plain'
  state                VARCHAR(128),              -- echoed back to client
  nonce                VARCHAR(128),              -- for OIDC id_token
  role                 VARCHAR(40)  NOT NULL,     -- frozen role at issue time
  trust_score          INTEGER      NOT NULL,
  verification_method  VARCHAR(40),
  created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  expires_at           TIMESTAMPTZ  NOT NULL,     -- created_at + 60 sec
  used                 BOOLEAN      NOT NULL DEFAULT FALSE,
  used_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_authcodes_expires ON authorization_codes(expires_at);

-- ─── Connected Platforms (user-visible "where am I logged in") ─────────────
CREATE TABLE IF NOT EXISTS connected_platforms (
  id                  SERIAL PRIMARY KEY,
  user_id             VARCHAR(64)  NOT NULL,
  client_id           VARCHAR(64)  NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  pairwise_subject_id VARCHAR(64)  NOT NULL,      -- the ID this platform sees
  scopes_granted      TEXT NOT NULL,              -- JSON array
  first_login_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  last_login_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  login_count         INTEGER      NOT NULL DEFAULT 1,
  revoked_at          TIMESTAMPTZ,
  UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_connections_user   ON connected_platforms(user_id);
CREATE INDEX IF NOT EXISTS idx_connections_client ON connected_platforms(client_id);

-- ─── Ownership / grants ────────────────────────────────────────────────────
-- None (AP6-49, #200). The convention is: every migration runs AS THE APP
-- USER via `node scripts/migrate.js`, so the app user owns what it creates.
-- sql/ownership-hhttps.sql repairs installations where a historical
-- `sudo -u postgres psql -f …` made postgres the owner.
