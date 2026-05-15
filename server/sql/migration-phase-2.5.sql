-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS Phase 2.5 — Signatures with Domain Binding
--
-- Adds the signatures table. Each row is a single, immutable proof that a
-- specific signer (identified by their pseudonymous credentials.user_id at
-- sign time) approved a specific text on a specific website/context.
--
-- Design constraints:
--   - Slugs are short (12 char base32-ish) — usable inside character-limited
--     posts (Twitter etc.) and unambiguous to read aloud
--   - Slugs persist forever once issued; revocation flips a flag, never deletes
--   - Domain binding prevents cross-site reuse by bots/scrapers
--   - Two text hashes (strict + loose) catch text-tampering with different
--     tolerance for whitespace and case
--   - Role/trust frozen at sign time so a later trust-score change doesn't
--     retroactively alter old signatures
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS signatures (
  -- Public identifier (slug): the only thing that goes into a marker
  id              VARCHAR(20) PRIMARY KEY,

  -- Signer (pseudonymous — no PII)
  signer_id       VARCHAR(64) NOT NULL,        -- credentials.user_id at sign time

  -- Role snapshot (frozen at sign time)
  role            VARCHAR(40) NOT NULL,
  role_label      VARCHAR(80),
  role_icon       VARCHAR(20),
  trust_score     INTEGER NOT NULL,
  level           VARCHAR(40),
  level_label     VARCHAR(80),

  -- Binding (Anti-Theft)
  -- binding_type:
  --   'web'      → bound_domain set, signature only valid on that domain
  --   'email'    → no domain check (newsletters, mailing lists)
  --   'document' → strictest mode, single-context use
  binding_type    VARCHAR(20) NOT NULL DEFAULT 'web',
  bound_domain    VARCHAR(120),                -- apex domain, e.g. "reddit.com"

  -- Text fingerprint
  -- strict: sha256(text)                            — byte-exact
  -- loose:  sha256(text.trim().replace(/\s+/g,' ').toLowerCase()) — tolerant
  text_hash_strict CHAR(64) NOT NULL,
  text_hash_loose  CHAR(64) NOT NULL,
  text_length      INTEGER NOT NULL,
  text_preview     VARCHAR(120),               -- first 120 chars for "what was signed?"

  -- First-seen lock (privacy-preserving: just domain + ts, no full URL)
  first_seen_domain VARCHAR(120),
  first_seen_at     TIMESTAMPTZ,

  -- Verification stats
  verify_count    INTEGER NOT NULL DEFAULT 0,
  last_verified_at TIMESTAMPTZ,

  -- Lifecycle
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at      TIMESTAMPTZ,
  revoke_reason   VARCHAR(120),

  issuer          VARCHAR(80) NOT NULL DEFAULT 'hhttps://hhttps.org'
);

CREATE INDEX IF NOT EXISTS idx_signatures_signer    ON signatures(signer_id);
CREATE INDEX IF NOT EXISTS idx_signatures_created   ON signatures(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_signatures_domain    ON signatures(bound_domain);
CREATE INDEX IF NOT EXISTS idx_signatures_revoked   ON signatures(revoked_at)
  WHERE revoked_at IS NOT NULL;

-- Reserved slugs: we don't want to issue slugs that look like URLs or have
-- obvious meanings. These are blocklist-checked at sign time.
CREATE TABLE IF NOT EXISTS reserved_slugs (
  slug VARCHAR(20) PRIMARY KEY
);

INSERT INTO reserved_slugs (slug) VALUES
  ('hhttps'), ('admin'), ('root'), ('null'), ('undefined'),
  ('login'), ('logout'), ('signup'), ('test'), ('demo'),
  ('api'), ('www'), ('mail'), ('email')
ON CONFLICT (slug) DO NOTHING;

-- Stats counter
ALTER TABLE stats ADD COLUMN IF NOT EXISTS signatures_created INTEGER DEFAULT 0;
ALTER TABLE stats ADD COLUMN IF NOT EXISTS signatures_verified INTEGER DEFAULT 0;
ALTER TABLE stats ADD COLUMN IF NOT EXISTS signatures_revoked  INTEGER DEFAULT 0;

-- ════════════════════════════════════════════════════════════════════════════
-- Grant ownership to the application user.
--
-- When this script is executed via `sudo -u postgres psql -f ...`, the new
-- tables are created with the postgres superuser as owner. Without this
-- block, the application user `hhttps` would get "permission denied" on
-- INSERT/UPDATE. We grant explicit ownership so future ALTER statements
-- also work without manual intervention.
--
-- Skips silently if the role doesn't exist (e.g. when running on a dev box
-- with a different user). Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hhttps') THEN
    ALTER TABLE signatures      OWNER TO hhttps;
    ALTER TABLE reserved_slugs  OWNER TO hhttps;
    GRANT SELECT, INSERT, UPDATE, DELETE ON signatures      TO hhttps;
    GRANT SELECT, INSERT, UPDATE, DELETE ON reserved_slugs  TO hhttps;
  END IF;
END$$;
