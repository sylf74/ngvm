-- SPDX-License-Identifier: LicenseRef-ngvm-proprietary
-- Repair of the tenant isolation of an NGVM database (v0.27.3, docs/kubernetes.md §5.1).
--
-- Every table of the NGVM schemas that has a `tenant` column must have row-level security enabled
-- and forced, and only policies that test the setting `ngvm.tenant`. A database restored from a
-- dump made before v0.25.0 keeps policies testing another setting: the services then see no row. The services refuse
-- to start on such a database; this script is the explicit repair, run once by the operator:
--   - with the services' role: `ngvm db repair` (it runs this file);
--   - or as the database's superuser, in the CloudNativePG pod while the services refuse to start:
--     kubectl -n <ns> exec -i <db>-1 -c postgres -- psql -d app -v ON_ERROR_STOP=1 < this file
-- It drops every policy that tests another setting (or none), enables and forces row-level
-- security, and creates the policy `<table>_tenant` where a table has none left. Each change is
-- reported as a NOTICE; run twice, the second run changes nothing.

DO $$
DECLARE
  t record;
  p record;
  good constant text := 'current_setting\(''ngvm\.tenant''';
  other constant text := 'current_setting\(''(?!ngvm\.tenant'')';
BEGIN
  FOR t IN
    SELECT n.nspname AS s, c.relname AS r, c.oid AS id, c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant' AND NOT a.attisdropped
    WHERE n.nspname = ANY (ARRAY['via', 'detect', 'verdict', 'dispatch', 'actions', 'audit'])
      AND c.relkind IN ('r', 'p')
    ORDER BY 1, 2
  LOOP
    FOR p IN
      SELECT polname,
             coalesce(pg_get_expr(polqual, polrelid), '') AS q,
             coalesce(pg_get_expr(polwithcheck, polrelid), '') AS w
      FROM pg_policy WHERE polrelid = t.id
    LOOP
      IF p.q !~ good OR (p.w <> '' AND p.w !~ good) OR (p.q || ' ' || p.w) ~ other THEN
        EXECUTE format('DROP POLICY %I ON %I.%I', p.polname, t.s, t.r);
        RAISE NOTICE 'dropped policy % on %.%', p.polname, t.s, t.r;
      END IF;
    END LOOP;
    IF NOT t.enabled THEN
      EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', t.s, t.r);
      RAISE NOTICE 'enabled row-level security on %.%', t.s, t.r;
    END IF;
    IF NOT t.forced THEN
      EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', t.s, t.r);
      RAISE NOTICE 'forced row-level security on %.%', t.s, t.r;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = t.id) THEN
      EXECUTE format(
        'CREATE POLICY %I ON %I.%I USING (tenant = current_setting(''ngvm.tenant'', true)) '
        'WITH CHECK (tenant = current_setting(''ngvm.tenant'', true))',
        t.r || '_tenant', t.s, t.r);
      RAISE NOTICE 'created policy %_tenant on %.%', t.r, t.s, t.r;
    END IF;
  END LOOP;
END $$;
