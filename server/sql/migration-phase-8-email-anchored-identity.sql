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
-- HHTTPS — Migration phase 8: E-Mail-verankerte, stabile Identität
-- (feature `email-anchored-identity`, see docs/specs/email-anchored-identity)
--
-- Adds:
--   - identity_anchors:        HMAC(pepper, normalize(email)) → stable user_id
--                              + account pseudonym. The plaintext e-mail is
--                              NEVER stored here (hash only). (D1, D2, D3)
--   - identity_claims_cache:   plaintext e-mail, pseudonym and verified_methods
--                              per user_id, kept until transferred to the
--                              platform; rows expire (≤ 7 days). (D5, AK-16)
--   - sessions.pseudonym:      the session carries the account pseudonym.
--   - authorization_codes.{email, pseudonym, verified_methods}:
--                              claims copied onto the code at /oauth/approve;
--                              `email` is set to NULL when the code is claimed
--                              at /oauth/token (transferred ⇒ deleted, AK-17).
--                              verified_methods is a JSON array as TEXT, like
--                              `scopes`.
--   - oauth_clients.allowed_scopes += "email" for existing clients.
--
-- Idempotent: safe to run multiple times (IF NOT EXISTS / WHERE NOT ...).
--
-- The file has TWO sections (F-7 / K-6, P-2):
--   1. BOOT-DDL  — tables / columns / indexes only. The server runs this
--                  section on boot (db.js: ensurePhase8Schema) when an
--                  applied-check shows the schema is missing, and awaits it
--                  before listening. Nothing below the marker is ever run
--                  automatically.
--   2. OPERATOR  — the data update (allowed_scopes += "email") and the
--                  grants. Run this section deliberately, once, as part of
--                  the deploy (or remove the UPDATE if you do not want every
--                  existing client to get scope `email`).
--
-- ════════════════════════════════════════════════════════════════════════════

-- ════════════════════════════ 1. BOOT-DDL ══════════════════════════════════
-- (executed by db.js on boot when not yet applied — DDL only, idempotent)

-- ─── Identity anchors (email hash → stable user id) ────────────────────────
CREATE TABLE IF NOT EXISTS identity_anchors (
  email_hash    TEXT        PRIMARY KEY,           -- HMAC-SHA256(pepper, trim+lower(email)), hex
  user_id       TEXT        NOT NULL UNIQUE,       -- stable userId (pairwise sub derives from it)
  pseudonym     TEXT        NOT NULL,              -- account pseudonym, set once (AK-6/7/8)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Claims cache (plaintext until transferred to the platform) ────────────
CREATE TABLE IF NOT EXISTS identity_claims_cache (
  user_id          TEXT        PRIMARY KEY,
  email            TEXT        NOT NULL,           -- plaintext, as confirmed
  pseudonym        TEXT,
  verified_methods TEXT,                           -- JSON array, e.g. '["email","passkey"]'
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL            -- ≤ 7 days after last confirmation
);

CREATE INDEX IF NOT EXISTS idx_identity_claims_cache_expires ON identity_claims_cache(expires_at);

-- ─── Sessions carry the pseudonym ──────────────────────────────────────────
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS pseudonym TEXT;

-- ─── Authorization codes carry email / pseudonym / verified_methods ────────
ALTER TABLE authorization_codes
  ADD COLUMN IF NOT EXISTS email            TEXT,  -- only when scope `email`; NULLed on claim
  ADD COLUMN IF NOT EXISTS pseudonym        TEXT,
  ADD COLUMN IF NOT EXISTS verified_methods TEXT;  -- JSON array as text (like `scopes`)

-- >>> BOOT-DDL END
-- Everything below this marker is NEVER executed by the server. db.js reads
-- the file only up to the marker (see phase8BootDdl in db.js).

-- ════════════════════════════ 2. OPERATOR ══════════════════════════════════
-- (run once, explicitly, by the operator — data update + grants)

-- ─── Scope `email` for existing clients ────────────────────────────────────
-- Deliberate assumption from requirements.md §6: already registered clients
-- get `email` appended to allowed_scopes so the transfer works immediately.
-- If that is not wanted for a deployment, remove this block before running.
UPDATE oauth_clients
   SET allowed_scopes = (allowed_scopes::jsonb || '["email"]'::jsonb)::text
 WHERE NOT (allowed_scopes::jsonb ? 'email');

-- ─── Ownership / grants ────────────────────────────────────────────────────
-- None (AP6-49, #200). The convention is: every migration runs AS THE APP
-- USER via `node scripts/migrate.js`, so the app user owns what it creates.
-- sql/ownership-hhttps.sql repairs installations where a historical
-- `sudo -u postgres psql -f …` made postgres the owner.
