-- ════════════════════════════════════════════════════════════════════════════
-- HHTTPS — Migration: machine operators can self-declare a role
--
-- Adds an optional `role` column to machine_operators. Bots can declare which
-- role they identify as when calling /hhttps/machine/register. The role is
-- self-declared in pilot mode (no verification beyond what we'd require for
-- humans does not exist for bots yet — no standard).
--
-- The role becomes part of the issued machine token's claims, so origins
-- (like ask.iamhmn.org) can apply role-based logic to bot interactions just
-- as they do for humans.
--
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE machine_operators
  ADD COLUMN IF NOT EXISTS role TEXT,
  ADD COLUMN IF NOT EXISTS role_label TEXT,
  ADD COLUMN IF NOT EXISTS role_icon  TEXT;

CREATE INDEX IF NOT EXISTS idx_machine_operators_role
  ON machine_operators(role) WHERE role IS NOT NULL;

-- For existing bots without a role: leave NULL — token won't carry a role claim.
