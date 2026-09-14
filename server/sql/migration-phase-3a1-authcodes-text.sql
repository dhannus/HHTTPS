-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS — Migration phase 3a.1: authorization_codes.state/nonce/pkce_challenge → TEXT
--
-- Phase 3a created these three columns as VARCHAR(128). Real-world OAuth
-- clients send longer `state` (encrypted/signed state blobs) and `nonce`
-- values; the insert in /hhttps/oauth/approve then failed with
-- `[DB] Query failed: value too long for type character varying(128)` and
-- the login broke with 401/500 (GitHub issue #31). The columns become TEXT;
-- the server validates the input up front (oauth-params.js: state/nonce
-- ≤ 2048 chars, code_challenge 43–128 chars per RFC 7636 §4.2).
--
-- BOOT-DDL: the server applies this file itself at boot (db.js: BOOT_DDL_FILES)
-- when information_schema reports authorization_codes.state as anything but
-- `text`. Nothing else to do.
--
-- Safe to re-run (ALTER COLUMN … TYPE TEXT on a TEXT column is a no-op).
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE authorization_codes
  ALTER COLUMN state          TYPE TEXT,
  ALTER COLUMN nonce          TYPE TEXT,
  ALTER COLUMN pkce_challenge TYPE TEXT;
