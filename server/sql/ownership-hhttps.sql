-- ============================================================================
-- HHTTPS — Ownership repair: every object in schema public belongs to the app role
-- ============================================================================
-- AP6-08 (#85): older installs applied the schema through a silent
-- `sudo -u postgres psql` fallback, which made postgres the owner of the
-- tables. The app user then fails on every boot-DDL ALTER ("must be owner of
-- table …") and on writes to tables it never got a GRANT for — while the
-- install script still reported success.
--
-- Run AS POSTGRES (superuser). Idempotent, a no-op on a clean install:
--   sudo -u postgres psql -d hhttps -v ON_ERROR_STOP=1 \
--     -v owner_role=hhttps -f server/sql/ownership-hhttps.sql
--
-- install-pg.sh and scripts/deploy-all.sh run this before the migration chain,
-- so the migrations can always be applied as the app user.
-- ============================================================================

-- Default role name when the caller passes no -v owner_role=…
\if :{?owner_role}
\else
\set owner_role hhttps
\endif

SELECT set_config('hhttps.owner_role', :'owner_role', false);

DO $$
DECLARE
  target TEXT := current_setting('hhttps.owner_role');
  r RECORD;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target) THEN
    RAISE NOTICE 'role % does not exist — nothing to do', target;
    RETURN;
  END IF;

  FOR r IN SELECT tablename AS name FROM pg_tables
            WHERE schemaname = 'public' AND tableowner <> target LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO %I', r.name, target);
  END LOOP;

  FOR r IN SELECT sequencename AS name FROM pg_sequences
            WHERE schemaname = 'public' AND sequenceowner <> target LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO %I', r.name, target);
  END LOOP;

  FOR r IN SELECT viewname AS name FROM pg_views
            WHERE schemaname = 'public' AND viewowner <> target LOOP
    EXECUTE format('ALTER VIEW public.%I OWNER TO %I', r.name, target);
  END LOOP;

  FOR r IN SELECT p.oid::regprocedure::text AS name
             FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
             JOIN pg_roles o     ON o.oid = p.proowner
            WHERE n.nspname = 'public' AND o.rolname <> target LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', r.name, target);
  END LOOP;

  EXECUTE format('GRANT ALL ON SCHEMA public TO %I', target);
END
$$;

-- Objects a superuser creates later (an operator running a migration as
-- postgres) should still be usable by the app role.
DO $$
DECLARE
  target TEXT := current_setting('hhttps.owner_role');
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target)
     AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public '
                || 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', target);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public '
                || 'GRANT USAGE, SELECT ON SEQUENCES TO %I', target);
  END IF;
END
$$;
