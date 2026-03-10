-- Supabase Database Initialization Script
-- Idempotent - safe to run multiple times

-- Create schemas
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS storage;
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE SCHEMA IF NOT EXISTS realtime;
CREATE SCHEMA IF NOT EXISTS _realtime;

-- ============================================================================
-- AUTH HELPER FUNCTIONS (required for RLS policies)
-- ============================================================================
-- These functions extract user information from JWT claims set by PostgREST
-- PostgREST sets request.jwt.claims from the Authorization Bearer token

-- auth.uid() - Get the user ID from the JWT 'sub' claim
CREATE OR REPLACE FUNCTION auth.uid()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb->>'sub',
    (NULLIF(current_setting('request.jwt.claims', true), '')::jsonb->>'user_id')
  )::uuid
$$;

-- auth.jwt() - Get all JWT claims
CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  )
$$;

-- auth.role() - Get the role from the JWT
CREATE OR REPLACE FUNCTION auth.role()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb->>'role',
    current_setting('role', true)
  )
$$;

-- auth.email() - Get the email from the JWT
CREATE OR REPLACE FUNCTION auth.email()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb->>'email'
$$;

-- Grant execute permissions to API roles
GRANT EXECUTE ON FUNCTION auth.uid() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.jwt() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.role() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.email() TO anon, authenticated, service_role;

-- Install required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pgjwt WITH SCHEMA extensions;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgjwt extension not available — skipping (not required for Realtime)';
END $$;

-- Install optional extensions
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- Create Supabase API roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN NOINHERIT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN NOINHERIT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
    END IF;

END $$;

-- Create service-specific users with LOGIN capability
-- These users are used by individual Supabase services for least-privilege access
-- All users share the same password as doadmin for simplicity in managed environments

DO $$
BEGIN
    -- Create supabase_auth_admin
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supabase_auth_admin') THEN
        CREATE USER supabase_auth_admin NOINHERIT CREATEROLE LOGIN;
    END IF;

    -- Create supabase_storage_admin
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supabase_storage_admin') THEN
        CREATE USER supabase_storage_admin NOINHERIT CREATEROLE LOGIN;
    END IF;

    -- Create authenticator
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticator') THEN
        CREATE USER authenticator NOINHERIT;
    END IF;

    -- Create supabase_admin
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supabase_admin') THEN
        CREATE USER supabase_admin CREATEROLE CREATEDB BYPASSRLS;
    END IF;
END $$;

-- Grant API roles to authenticator (allows PostgREST to switch roles based on JWT)
GRANT anon TO authenticator;
GRANT authenticated TO authenticator;
GRANT service_role TO authenticator;

-- Grant service_role to storage admin (allows Storage API to impersonate service_role)
GRANT service_role TO supabase_storage_admin;

-- Grant service_role to auth admin (allows Auth service to impersonate service_role)
GRANT service_role TO supabase_auth_admin;

-- Set passwords using psql variable (passed from run-db-init.sh)
-- All users use the same password as doadmin for simplicity
-- ALTER USER is idempotent - setting password multiple times is safe
\gset
ALTER USER supabase_auth_admin WITH PASSWORD :'admin_password';
ALTER USER supabase_storage_admin WITH PASSWORD :'admin_password';
ALTER USER authenticator WITH PASSWORD :'admin_password';
ALTER USER supabase_admin WITH PASSWORD :'admin_password';

-- Grant database privileges to supabase_admin
GRANT ALL PRIVILEGES ON DATABASE defaultdb TO supabase_admin;

-- Grant CREATE on database to supabase_storage_admin (for migrations)
GRANT CREATE ON DATABASE defaultdb TO supabase_storage_admin;

-- Grant supabase_admin to authenticator (allows Studio to manage database)
GRANT supabase_admin TO authenticator;

-- Set statement timeouts for API roles (prevent long-running queries)
ALTER ROLE anon SET statement_timeout = '3s';
ALTER ROLE authenticated SET statement_timeout = '8s';

-- Grant schema permissions to supabase_admin
GRANT ALL ON SCHEMA public TO supabase_admin;
GRANT ALL ON SCHEMA auth TO supabase_admin;
GRANT ALL ON SCHEMA storage TO supabase_admin;
GRANT USAGE ON SCHEMA extensions TO supabase_admin;
GRANT ALL ON SCHEMA realtime TO supabase_admin;
GRANT ALL ON SCHEMA _realtime TO supabase_admin;

-- Transfer schema ownership to service-specific users
-- Each service owns its own schema for migrations
ALTER SCHEMA auth OWNER TO supabase_auth_admin;
ALTER SCHEMA storage OWNER TO supabase_storage_admin;
ALTER SCHEMA realtime OWNER TO supabase_admin;
ALTER SCHEMA _realtime OWNER TO supabase_admin;

-- Keep doadmin grants as fallback for complex migrations that might need elevated privileges
GRANT ALL ON SCHEMA auth TO doadmin;
GRANT ALL ON SCHEMA storage TO doadmin;
GRANT ALL ON SCHEMA realtime TO doadmin;
GRANT ALL ON SCHEMA _realtime TO doadmin;

-- Grant doadmin table-level access to storage schema
GRANT ALL ON ALL TABLES IN SCHEMA storage TO doadmin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA storage TO doadmin;

-- Grant permissions to API roles (anon, authenticated, service_role) on public schema
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL ROUTINES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- Grant permissions on realtime schema (for Realtime migrations and subscriptions)
GRANT USAGE ON SCHEMA realtime TO anon, authenticated, service_role;

-- Grant permissions on auth schema to supabase_auth_admin
GRANT ALL ON SCHEMA auth TO supabase_auth_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA auth GRANT ALL ON TABLES TO supabase_auth_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA auth GRANT ALL ON SEQUENCES TO supabase_auth_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA auth GRANT ALL ON ROUTINES TO supabase_auth_admin;

-- Grant permissions on auth tables to supabase_admin (for Studio/Meta access)
-- This allows Studio to view users, audit logs, etc.
GRANT USAGE ON SCHEMA auth TO supabase_admin;
GRANT ALL ON ALL TABLES IN SCHEMA auth TO supabase_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA auth TO supabase_admin;
GRANT ALL ON ALL ROUTINES IN SCHEMA auth TO supabase_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA auth GRANT ALL ON TABLES TO supabase_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA auth GRANT ALL ON SEQUENCES TO supabase_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA auth GRANT ALL ON ROUTINES TO supabase_admin;

-- Grant permissions on storage schema to supabase_storage_admin
GRANT USAGE ON SCHEMA storage TO supabase_storage_admin;
GRANT ALL ON ALL TABLES IN SCHEMA storage TO supabase_storage_admin;
GRANT ALL ON ALL ROUTINES IN SCHEMA storage TO supabase_storage_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA storage TO supabase_storage_admin;

-- Set default privileges for future objects in storage schema
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON TABLES TO supabase_storage_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON SEQUENCES TO supabase_storage_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON ROUTINES TO supabase_storage_admin;

-- Grant storage permissions to supabase_admin (for Studio/Meta access to buckets)
GRANT USAGE ON SCHEMA storage TO supabase_admin;
GRANT ALL ON ALL TABLES IN SCHEMA storage TO supabase_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA storage TO supabase_admin;
GRANT ALL ON ALL ROUTINES IN SCHEMA storage TO supabase_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON TABLES TO supabase_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON SEQUENCES TO supabase_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON ROUTINES TO supabase_admin;

-- Grant storage permissions to service_role
GRANT USAGE ON SCHEMA storage TO service_role;
GRANT ALL ON ALL TABLES IN SCHEMA storage TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA storage TO service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE doadmin IN SCHEMA storage GRANT ALL ON SEQUENCES TO service_role;

-- Grant storage schema access to frontend roles
GRANT USAGE ON SCHEMA storage TO anon, authenticated;

-- Grant permissions on extensions schema
GRANT USAGE ON SCHEMA extensions TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA extensions TO anon, authenticated, service_role;

-- Set default privileges for future objects in public schema
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON ROUTINES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;

-- Set default privileges for objects created by supabase_admin
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON TABLES TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON ROUTINES TO postgres, anon, authenticated, service_role;

-- ============================================================================
-- AUTH SCHEMA SETUP
-- ============================================================================
-- NOTE: Auth tables are created by GoTrue migrations, not here
-- We only set permissions and search paths for the auth schema

-- Grant permissions for future auth tables (created by GoTrue migrations)
GRANT ALL ON ALL TABLES IN SCHEMA auth TO supabase_auth_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA auth TO supabase_auth_admin;
GRANT ALL ON ALL ROUTINES IN SCHEMA auth TO supabase_auth_admin;

-- Grant permissions to supabase_admin for Studio access
GRANT ALL ON ALL TABLES IN SCHEMA auth TO supabase_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA auth TO supabase_admin;
GRANT ALL ON ALL ROUTINES IN SCHEMA auth TO supabase_admin;

-- ============================================================================
-- CREATE STORAGE SCHEMA TABLES
-- ============================================================================
-- Storage API expects these tables to exist
-- NOTE: Foreign keys to auth.users are omitted because auth tables are created
-- by GoTrue migrations after this script runs. Storage API handles auth checks
-- via RLS policies and application logic instead.

-- Buckets table
CREATE TABLE IF NOT EXISTS storage.buckets (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    owner UUID,  -- References auth.users(id) but FK added later by Storage migrations
    public BOOLEAN DEFAULT false,
    avif_autodetection BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    file_size_limit BIGINT,
    allowed_mime_types TEXT[]
);

-- Objects table
CREATE TABLE IF NOT EXISTS storage.objects (
    id UUID PRIMARY KEY DEFAULT extensions.uuid_generate_v4(),
    bucket_id TEXT REFERENCES storage.buckets(id),
    name TEXT NOT NULL,
    owner UUID,  -- References auth.users(id) but FK added later by Storage migrations
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB,
    path_tokens TEXT[] GENERATED ALWAYS AS (string_to_array(name, '/')) STORED,
    version TEXT,
    UNIQUE(bucket_id, name)
);

-- S3 Multipart uploads table
CREATE TABLE IF NOT EXISTS storage.s3_multipart_uploads (
    id TEXT PRIMARY KEY,
    in_progress_size BIGINT DEFAULT 0,
    upload_signature TEXT NOT NULL,
    bucket_id TEXT NOT NULL REFERENCES storage.buckets(id),
    key TEXT NOT NULL,
    version TEXT NOT NULL,
    owner_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(bucket_id, key)
);

-- S3 Multipart uploads parts table
CREATE TABLE IF NOT EXISTS storage.s3_multipart_uploads_parts (
    id UUID PRIMARY KEY DEFAULT extensions.uuid_generate_v4(),
    upload_id TEXT NOT NULL REFERENCES storage.s3_multipart_uploads(id) ON DELETE CASCADE,
    size BIGINT DEFAULT 0,
    part_number INT NOT NULL,
    bucket_id TEXT NOT NULL REFERENCES storage.buckets(id),
    key TEXT NOT NULL,
    etag TEXT NOT NULL,
    owner_id TEXT,
    version TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for storage tables
CREATE INDEX IF NOT EXISTS objects_bucket_id_idx ON storage.objects(bucket_id);
CREATE INDEX IF NOT EXISTS objects_name_idx ON storage.objects(name);
CREATE INDEX IF NOT EXISTS objects_bucket_id_name_idx ON storage.objects(bucket_id, name);

-- Transfer ownership of storage tables to supabase_storage_admin
ALTER TABLE IF EXISTS storage.buckets OWNER TO supabase_storage_admin;
ALTER TABLE IF EXISTS storage.objects OWNER TO supabase_storage_admin;
ALTER TABLE IF EXISTS storage.s3_multipart_uploads OWNER TO supabase_storage_admin;
ALTER TABLE IF EXISTS storage.s3_multipart_uploads_parts OWNER TO supabase_storage_admin;

-- ============================================================================
-- CONFIGURE SEARCH PATH (Supabase best practice)
-- ============================================================================
-- Use ALTER ROLE ... IN DATABASE for highest precedence
-- This ensures search_path is set for each role specifically in this database

-- Set search_path for service_role (Storage API uses this role!)
-- CRITICAL: Must include storage schema FIRST for Storage API to find buckets table
ALTER ROLE service_role IN DATABASE defaultdb SET search_path = storage, public, auth, extensions;

-- Set search_path for doadmin
ALTER ROLE doadmin IN DATABASE defaultdb SET search_path = storage, public, auth, extensions;

-- Set search_path for authenticator (used by PostgREST)
ALTER ROLE authenticator IN DATABASE defaultdb SET search_path = public, extensions;

-- Set search_path for frontend roles
ALTER ROLE anon IN DATABASE defaultdb SET search_path = storage, public, auth, extensions;
ALTER ROLE authenticated IN DATABASE defaultdb SET search_path = storage, public, auth, extensions;

-- Set search_path for storage admin
ALTER ROLE supabase_storage_admin IN DATABASE defaultdb SET search_path = storage, public, extensions;

-- Set search_path for auth admin
ALTER ROLE supabase_auth_admin IN DATABASE defaultdb SET search_path = auth, public, extensions;

-- Set search_path for supabase_admin (don't include auth schema per official setup)
ALTER ROLE supabase_admin IN DATABASE defaultdb SET search_path = public, extensions;

-- ============================================================================
-- REALTIME: ensure db_pool and ssl_enforced are always set on tenant extensions
-- ============================================================================
-- The Realtime seed (SEED_SELF_HOST=true) recreates the tenant on every restart
-- without db_pool (defaults to 1) or ssl_enforced (defaults to false).
-- db_pool=1 causes DatabaseConnectionRateLimitReached with multiple subscriptions.
-- ssl_enforced=false causes Postgrex to connect without SSL, which DO managed
-- Postgres rejects (pg_hba.conf only allows hostssl connections).
-- db_pool=5 is conservative for managed Postgres with max_connections=50 (Supabase Cloud
-- defaults to 1; 5 gives headroom for CDC multiplexing without exhausting the pool).
-- This trigger intercepts INSERTs AND UPDATEs so that re-seeding via UPSERT
-- (which the pipeline does on every deploy) can never override these values.
-- On first deploy the _realtime.extensions table doesn't exist yet (created by
-- Realtime migrations), so we guard with an IF EXISTS check.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = '_realtime' AND table_name = 'extensions'
  ) THEN
    -- Patch any existing extensions missing db_pool or ssl_enforced
    UPDATE _realtime.extensions
    SET settings = COALESCE(settings, '{}'::jsonb)
                  || jsonb_build_object('db_pool', 5, 'ssl_enforced', true),
        updated_at = NOW()
    WHERE type = 'postgres_cdc_rls'
      AND (
        settings->>'db_pool' IS NULL OR (settings->'db_pool')::int IS DISTINCT FROM 5
        OR (settings->>'ssl_enforced')::boolean IS NOT TRUE
      );

    -- Create trigger for future INSERTs and UPDATEs (handles re-seeding via UPSERT)
    CREATE OR REPLACE FUNCTION _realtime.ensure_tenant_settings()
    RETURNS TRIGGER AS $fn$
    BEGIN
      IF NEW.type = 'postgres_cdc_rls' THEN
        NEW.settings = COALESCE(NEW.settings, '{}'::jsonb)
                      || jsonb_build_object('db_pool', 5, 'ssl_enforced', true);
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS ensure_db_pool ON _realtime.extensions;
    DROP TRIGGER IF EXISTS ensure_tenant_settings ON _realtime.extensions;
    CREATE TRIGGER ensure_tenant_settings
      BEFORE INSERT OR UPDATE ON _realtime.extensions
      FOR EACH ROW EXECUTE FUNCTION _realtime.ensure_tenant_settings();
  END IF;
END $$;

-- ============================================================================
-- FIX: MigrationsFailedToRun — realtime.list_changes()
-- ============================================================================
-- Realtime migration 20230328144023 creates list_changes() with
--   SET log_min_messages TO 'fatal'
-- — a superuser-only GUC. On DO managed Postgres (non-superuser) it fails with:
--   MigrationsFailedToRun: permission denied to set parameter "log_min_messages"
-- (upstream issues: supabase/realtime#614, supabase/realtime#1326)
--
-- Fix: pre-create the function WITHOUT the SET attribute, then mark the
-- migration as applied so Realtime skips it on subsequent boots.
--
-- Guards: this block only runs when Realtime has already booted at least once
-- (creating realtime.schema_migrations + prerequisite types). On a completely
-- fresh deploy the block is a no-op; re-deploying after the first failed boot
-- will apply the fix.
DO $$
BEGIN
  -- Guard 1: schema_migrations must exist (created by Realtime tenant migrations)
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'realtime' AND table_name = 'schema_migrations'
  ) THEN
    RAISE NOTICE 'init-db: realtime.schema_migrations not found — skipping list_changes fix (first deploy)';
    RETURN;
  END IF;

  -- Guard 2: skip if migration already applied
  IF EXISTS (
    SELECT 1 FROM realtime.schema_migrations WHERE version = 20230328144023
  ) THEN
    RAISE NOTICE 'init-db: migration 20230328144023 already applied — skipping';
    RETURN;
  END IF;

  -- Guard 3: prerequisite type must exist (created by earlier migrations)
  IF NOT EXISTS (
    SELECT 1 FROM pg_type t
    JOIN pg_namespace n ON t.typnamespace = n.oid
    WHERE n.nspname = 'realtime' AND t.typname = 'wal_rls'
  ) THEN
    RAISE NOTICE 'init-db: realtime.wal_rls type not found — skipping list_changes fix';
    RETURN;
  END IF;

  -- Create list_changes WITHOUT the problematic SET log_min_messages attribute.
  -- Function body is identical to upstream Supabase Realtime migration 20230328144023.
  EXECUTE $fn$
    CREATE OR REPLACE FUNCTION realtime.list_changes(
        publication name,
        slot_name name,
        max_changes int,
        max_record_bytes int
    )
    RETURNS SETOF realtime.wal_rls
    LANGUAGE sql
    AS $body$
      with pub as (
        select
          concat_ws(
            ',',
            case when bool_or(pubinsert) then 'insert' else null end,
            case when bool_or(pubupdate) then 'update' else null end,
            case when bool_or(pubdelete) then 'delete' else null end
          ) as w2j_actions,
          coalesce(
            string_agg(
              realtime.quote_wal2json(format('%I.%I', schemaname, tablename)::regclass),
              ','
            ) filter (where ppt.tablename is not null and ppt.tablename not like '% %'),
            ''
          ) w2j_add_tables
        from
          pg_publication pp
          left join pg_publication_tables ppt
            on pp.pubname = ppt.pubname
        where
          pp.pubname = publication
        group by
          pp.pubname
        limit 1
      ),
      w2j as (
        select
          x.*, pub.w2j_add_tables
        from
          pub,
          pg_logical_slot_get_changes(
            slot_name, null, max_changes,
            'include-pk', 'true',
            'include-transaction', 'false',
            'include-timestamp', 'true',
            'include-type-oids', 'true',
            'format-version', '2',
            'actions', pub.w2j_actions,
            'add-tables', pub.w2j_add_tables
          ) x
      )
      select
        xyz.wal,
        xyz.is_rls_enabled,
        xyz.subscription_ids,
        xyz.errors
      from
        w2j,
        realtime.apply_rls(
          wal := w2j.data::jsonb,
          max_record_bytes := max_record_bytes
        ) xyz(wal, is_rls_enabled, subscription_ids, errors)
      where
        w2j.w2j_add_tables <> ''
        and xyz.subscription_ids[1] is not null
    $body$;
  $fn$;

  -- Mark migration as applied so Realtime skips it
  INSERT INTO realtime.schema_migrations (version, inserted_at)
  VALUES (20230328144023, NOW()::timestamp(0))
  ON CONFLICT DO NOTHING;

  RAISE NOTICE 'init-db: created realtime.list_changes() (no SET log_min_messages) and marked migration 20230328144023';
END $$;

-- ============================================================
-- Rename seeded tenant if SELF_HOST_TENANT_NAME differs from 'realtime-dev'.
-- The psql variable :tenant_name is passed by run-db-init.sh.
-- On first deploy the tenant table may not exist yet — the DO block guards this.
-- ============================================================
SELECT set_config('app.tenant_name', :'tenant_name', false);

DO $$
DECLARE
  target TEXT := current_setting('app.tenant_name', true);
  fk_name TEXT;
BEGIN
  -- Skip if no target, target is default seed name, or tables don't exist yet
  IF target IS NULL OR target = '' OR target = 'realtime-dev' THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = '_realtime' AND table_name = 'tenants'
  ) THEN
    RAISE NOTICE 'init-db: _realtime.tenants not found yet, skipping tenant rename';
    RETURN;
  END IF;

  -- Skip if target tenant already exists (idempotent)
  IF EXISTS (SELECT 1 FROM _realtime.tenants WHERE external_id = target) THEN
    RAISE NOTICE 'init-db: tenant "%" already exists, skipping rename', target;
    RETURN;
  END IF;

  -- Skip if source tenant doesn't exist (nothing to rename)
  IF NOT EXISTS (SELECT 1 FROM _realtime.tenants WHERE external_id = 'realtime-dev') THEN
    RAISE NOTICE 'init-db: tenant "realtime-dev" not found, skipping rename';
    RETURN;
  END IF;

  -- Make FK constraint deferrable so we can update both tables atomically
  SELECT conname INTO fk_name
  FROM pg_constraint
  WHERE conrelid = '_realtime.extensions'::regclass
    AND confrelid = '_realtime.tenants'::regclass
    AND contype = 'f'
    AND NOT condeferrable
  LIMIT 1;

  IF fk_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE _realtime.extensions DROP CONSTRAINT %I', fk_name);
    EXECUTE format(
      'ALTER TABLE _realtime.extensions ADD CONSTRAINT %I '
      'FOREIGN KEY (tenant_external_id) REFERENCES _realtime.tenants(external_id) '
      'DEFERRABLE INITIALLY DEFERRED',
      fk_name
    );
    RAISE NOTICE 'init-db: made FK constraint % deferrable', fk_name;
  END IF;

  -- Rename in deferred mode
  SET CONSTRAINTS ALL DEFERRED;

  UPDATE _realtime.tenants
  SET external_id = target
  WHERE external_id = 'realtime-dev';

  UPDATE _realtime.extensions
  SET tenant_external_id = target,
      updated_at = NOW()
  WHERE tenant_external_id = 'realtime-dev';

  SET CONSTRAINTS ALL IMMEDIATE;

  RAISE NOTICE 'init-db: renamed tenant "realtime-dev" → "%"', target;
END $$;
