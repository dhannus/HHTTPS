-- ═════════════════════════════════════════════════════════════════════════════
-- Privacy Pass Issuance Log
--
-- Tracks how many tokens each WebAuthn credential has been issued, sliding
-- window. Used for Sybil-resistance rate limiting (default: 10 tokens / 24h).
-- ═════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pp_issuance_log (
  id              BIGSERIAL PRIMARY KEY,
  credential_id   TEXT NOT NULL,
  role            TEXT NOT NULL,
  token_count     INT NOT NULL CHECK (token_count > 0),
  issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot path: lookups by credential within a rolling window
CREATE INDEX IF NOT EXISTS pp_issuance_log_credential_at_idx
  ON pp_issuance_log (credential_id, issued_at DESC);

-- For analytics / dashboards
CREATE INDEX IF NOT EXISTS pp_issuance_log_role_at_idx
  ON pp_issuance_log (role, issued_at DESC);

-- TTL hint: rows older than 30 days can be cleaned up by the existing
-- cleanup job. They serve no operational purpose past the rate-limit window.
-- See server.js: setInterval(() => db.cleanupExpired(), ...);
