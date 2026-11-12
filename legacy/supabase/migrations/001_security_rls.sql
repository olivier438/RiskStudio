-- =============================================================================
-- Risk Studio — Supabase Security Migration 001
-- Security by Design: RLS, CHECK constraints, input limits
-- Run in Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. DROP ANY PERMISSIVE "public" POLICIES (run first to start clean)
-- -----------------------------------------------------------------------------
-- Adjust table names if they differ in your project.

DO $$ DECLARE
  pol record;
BEGIN
  FOR pol IN
    SELECT policyname, tablename
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('risks', 'proposals', 'data_leaks', 'categories')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', pol.policyname, pol.tablename);
  END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- 1. ENABLE ROW LEVEL SECURITY
-- -----------------------------------------------------------------------------
ALTER TABLE risks        ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals    ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_leaks   ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories   ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owners
ALTER TABLE risks        FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals    FORCE ROW LEVEL SECURITY;
ALTER TABLE data_leaks   FORCE ROW LEVEL SECURITY;
ALTER TABLE categories   FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- 2. RLS POLICIES — risks
-- -----------------------------------------------------------------------------

-- Anon: read published rows only, no writes
CREATE POLICY "risks_anon_select_published" ON risks
  FOR SELECT
  TO anon
  USING (status = 'published');

-- Authenticated admin: full access
CREATE POLICY "risks_admin_all" ON risks
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- Service role (Cloudflare Worker): bypass via SUPABASE_SERVICE_KEY (RLS bypassed by design)

-- -----------------------------------------------------------------------------
-- 3. RLS POLICIES — proposals
-- -----------------------------------------------------------------------------

-- Anon: INSERT only, and ONLY with status='pending'
-- This prevents a malicious actor from directly publishing via the form
CREATE POLICY "proposals_anon_insert_pending_only" ON proposals
  FOR INSERT
  TO anon
  WITH CHECK (status = 'pending');

-- Anon: NO SELECT, UPDATE, or DELETE
-- (no SELECT policy for anon = no rows returned)

-- Authenticated admin: full access
CREATE POLICY "proposals_admin_all" ON proposals
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 4. RLS POLICIES — data_leaks
-- -----------------------------------------------------------------------------

-- Anon: read published only
CREATE POLICY "leaks_anon_select_published" ON data_leaks
  FOR SELECT
  TO anon
  USING (status = 'published');

-- Authenticated admin: full access
CREATE POLICY "leaks_admin_all" ON data_leaks
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 5. RLS POLICIES — categories (public lookup table)
-- -----------------------------------------------------------------------------

-- Anon: read-only (all rows)
CREATE POLICY "categories_anon_select" ON categories
  FOR SELECT
  TO anon
  USING (true);

-- Authenticated admin: full access
CREATE POLICY "categories_admin_all" ON categories
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 6. CHECK CONSTRAINTS — enum values and input lengths
-- -----------------------------------------------------------------------------

-- risks.status
ALTER TABLE risks DROP CONSTRAINT IF EXISTS risks_status_check;
ALTER TABLE risks ADD CONSTRAINT risks_status_check
  CHECK (status IN ('published', 'pending', 'rejected', 'archived'));

-- risks.triage
ALTER TABLE risks DROP CONSTRAINT IF EXISTS risks_triage_check;
ALTER TABLE risks ADD CONSTRAINT risks_triage_check
  CHECK (triage IN ('critical', 'significant', 'moderate', 'low'));

-- risks.type
ALTER TABLE risks DROP CONSTRAINT IF EXISTS risks_type_check;
ALTER TABLE risks ADD CONSTRAINT risks_type_check
  CHECK (type IN ('cyber', 'grc', 'risk', 'leak') OR type IS NULL);

-- risks text field lengths
ALTER TABLE risks DROP CONSTRAINT IF EXISTS risks_titre_length;
ALTER TABLE risks ADD CONSTRAINT risks_titre_length
  CHECK (char_length(titre) BETWEEN 1 AND 300);

ALTER TABLE risks DROP CONSTRAINT IF EXISTS risks_source_url_length;
ALTER TABLE risks ADD CONSTRAINT risks_source_url_length
  CHECK (source_url IS NULL OR char_length(source_url) <= 2048);

-- proposals.status
ALTER TABLE proposals DROP CONSTRAINT IF EXISTS proposals_status_check;
ALTER TABLE proposals ADD CONSTRAINT proposals_status_check
  CHECK (status IN ('pending', 'approved', 'rejected'));

-- proposals text field lengths (prevent oversized form submissions)
ALTER TABLE proposals DROP CONSTRAINT IF EXISTS proposals_titre_length;
ALTER TABLE proposals ADD CONSTRAINT proposals_titre_length
  CHECK (titre IS NULL OR char_length(titre) <= 300);

ALTER TABLE proposals DROP CONSTRAINT IF EXISTS proposals_menace_length;
ALTER TABLE proposals ADD CONSTRAINT proposals_menace_length
  CHECK (menace IS NULL OR char_length(menace) <= 500);

ALTER TABLE proposals DROP CONSTRAINT IF EXISTS proposals_commentaire_length;
ALTER TABLE proposals ADD CONSTRAINT proposals_commentaire_length
  CHECK (commentaire IS NULL OR char_length(commentaire) <= 2000);

ALTER TABLE proposals DROP CONSTRAINT IF EXISTS proposals_email_length;
ALTER TABLE proposals ADD CONSTRAINT proposals_email_length
  CHECK (email IS NULL OR char_length(email) <= 254);

-- data_leaks.status
ALTER TABLE data_leaks DROP CONSTRAINT IF EXISTS leaks_status_check;
ALTER TABLE data_leaks ADD CONSTRAINT leaks_status_check
  CHECK (status IN ('published', 'pending', 'archived'));

-- -----------------------------------------------------------------------------
-- 7. RATE LIMITING — proposals (DB-level, 10 inserts per hour per session)
-- Note: for production, pair with Cloudflare WAF rate limiting on the
-- Supabase REST endpoint /rest/v1/proposals (POST) for IP-based throttling.
-- This function provides a last-resort DB-level guard.
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION check_proposals_rate_limit()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  recent_count INTEGER;
  window_start TIMESTAMPTZ := NOW() - INTERVAL '1 hour';
BEGIN
  -- Count recent proposals from the same email (if provided)
  IF NEW.email IS NOT NULL THEN
    SELECT COUNT(*) INTO recent_count
    FROM proposals
    WHERE email = NEW.email
      AND created_at >= window_start;

    IF recent_count >= 10 THEN
      RAISE EXCEPTION 'rate_limit_exceeded'
        USING HINT = 'Maximum 10 proposals per hour per email address';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS proposals_rate_limit_trigger ON proposals;
CREATE TRIGGER proposals_rate_limit_trigger
  BEFORE INSERT ON proposals
  FOR EACH ROW
  EXECUTE FUNCTION check_proposals_rate_limit();

-- -----------------------------------------------------------------------------
-- 8. ENSURE created_at HAS A DEFAULT (prevent missing timestamps)
-- -----------------------------------------------------------------------------
ALTER TABLE proposals  ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE risks      ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE data_leaks ALTER COLUMN created_at SET DEFAULT NOW();

-- -----------------------------------------------------------------------------
-- 9. REVOKE direct table grants from anon (PostgREST uses RLS, not grants)
--    These are belt-and-suspenders: RLS is the primary control.
-- -----------------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON risks      FROM anon;
REVOKE UPDATE, DELETE         ON proposals  FROM anon;
REVOKE INSERT, UPDATE, DELETE ON data_leaks FROM anon;
REVOKE INSERT, UPDATE, DELETE ON categories FROM anon;

-- Re-grant only what anon legitimately needs
GRANT SELECT ON risks        TO anon;
GRANT SELECT ON data_leaks   TO anon;
GRANT SELECT ON categories   TO anon;
GRANT INSERT ON proposals    TO anon;  -- form submissions only

-- Sequence grants for INSERT
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO anon;

-- -----------------------------------------------------------------------------
-- DONE
-- Verify with:
--   SELECT tablename, policyname, cmd, roles, qual
--   FROM pg_policies WHERE schemaname = 'public';
-- -----------------------------------------------------------------------------
