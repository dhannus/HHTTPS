-- ===========================================================================
-- HHTTPS — register the Developer Portal as an OAuth client
--
-- The portal now goes through the same consent flow as every other client
-- (ask.iamhmn.org, the WordPress plugin): the "Anmelden" button leads to
-- /hhttps/oauth/authorize, which renders the universal consent page, sends the
-- user to the sign-in when there is no identity yet, and redirects back to the
-- portal on "Erlauben".
--
-- Public client (client_secret_hash NULL) → PKCE is mandatory, which is
-- correct for a browser-only surface: there is nowhere to keep a secret.
--
-- verification_status/verified are set to the verified state on purpose. This
-- is the issuer's own first-party surface; showing an "unverified platform"
-- warning on it would be false, and would teach users to click past the very
-- warning that protects them elsewhere.
--
-- Idempotent. Safe to run repeatedly.
-- ===========================================================================

BEGIN;

INSERT INTO oauth_clients (
  client_id,
  client_secret_hash,
  name,
  description,
  homepage_url,
  redirect_uris,
  allowed_scopes,
  subject_type,
  contact_email,
  verified,
  verified_at,
  verified_by,
  is_active
) VALUES (
  'hhttps-developer-portal',
  NULL,                                   -- public client → PKCE required
  'HHTTPS Developer Portal',
  'Erstverwaltung von Plattformen, DNS-Verifikation und Review-Anträgen auf hhttps.org.',
  'https://hhttps.org/developers/',
  '["https://hhttps.org/developers/dashboard.html"]',
  '["openid"]',                           -- identity only; no role, no age
  'public',
  'daniel.hannuschka@tweakz.de',
  TRUE,
  NOW(),
  'system:first-party',
  TRUE
)
ON CONFLICT (client_id) DO UPDATE SET
  name           = EXCLUDED.name,
  description    = EXCLUDED.description,
  homepage_url   = EXCLUDED.homepage_url,
  redirect_uris  = EXCLUDED.redirect_uris,
  allowed_scopes = EXCLUDED.allowed_scopes,
  subject_type   = EXCLUDED.subject_type,
  verified       = TRUE,
  is_active      = TRUE;

-- Phase 3b added the verification workflow columns. Set the portal to the
-- terminal state so it never shows up in the admin review queue.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'oauth_clients' AND column_name = 'verification_status'
  ) THEN
    UPDATE oauth_clients
       SET verification_status = 'verified'
     WHERE client_id = 'hhttps-developer-portal';
  END IF;
END $$;

COMMIT;

-- Verify:
--   SELECT client_id, name, verified, subject_type, redirect_uris
--     FROM oauth_clients WHERE client_id = 'hhttps-developer-portal';
