-- ═══════════════════════════════════════════════════════════════════════════
-- HHTTPS Phase 3b.1 — Domain/Email match tracking
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Adds: `domain_email_match` boolean on oauth_clients.
-- TRUE iff contact_email's domain matches the apex of homepage_url's domain.
-- Required for `verified` status (along with DNS verification + admin review).
--
-- Computed by server code on email change. Idempotent migration.
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

ALTER TABLE oauth_clients
  ADD COLUMN IF NOT EXISTS domain_email_match BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.domain_email_match IS
  'TRUE iff contact_email apex-domain matches homepage_url apex-domain. Required for verified status.';

-- For existing verified clients, set to TRUE (they were manually approved,
-- domain match is implied by admin review).
UPDATE oauth_clients
   SET domain_email_match = TRUE
 WHERE verification_status = 'verified'
   AND contact_email IS NOT NULL;

COMMIT;
