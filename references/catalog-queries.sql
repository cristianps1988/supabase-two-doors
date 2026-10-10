-- =============================================================================
-- supabase-two-doors — read-only catalog inventory
--
-- Every statement here is a SELECT against the system catalog. Nothing writes.
-- Run as the project owner (postgres) locally, or over the user's own read-only
-- connection on staging/prod. Replace the schema list in each query if the
-- project exposes more than `public` through PostgREST (config.toml [api] schemas).
--
-- Each query says what a hit means. Save the output, redacting nothing but
-- secrets (there should be none in catalog output — function bodies are the one
-- place a hard-coded key can hide; check Q3 output before saving it).
-- =============================================================================


-- Q1. Functions in exposed schemas that anon / authenticated / PUBLIC can EXECUTE.
-- A row is an RPC endpoint: POST /rest/v1/rpc/<name>. SECURITY DEFINER rows run
-- with the OWNER's privileges (usually postgres → bypasses RLS) — read every one.
-- Trigger functions and internal helpers that show up here are reachable too.
SELECT
  n.nspname                                        AS schema,
  p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS signature,
  p.prosecdef                                      AS security_definer,
  pg_get_userbyid(p.proowner)                      AS owner,
  has_function_privilege('anon',          p.oid, 'EXECUTE') AS anon,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated,
  EXISTS (
    SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
    WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'
  )                                                AS public_grant,
  p.prorettype = 'trigger'::regtype                AS is_trigger
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('public')
  AND p.prokind IN ('f', 'p')
  AND (has_function_privilege('anon', p.oid, 'EXECUTE')
       OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
ORDER BY p.prosecdef DESC, anon DESC, 2;


-- Q2. Default privileges. THIS is why `REVOKE ... FROM PUBLIC` doesn't help:
-- Supabase's bootstrap grants future functions/tables/sequences to anon and
-- authenticated BY NAME. Any row whose acl mentions anon= or authenticated=
-- means every object created later in that schema inherits the grant.
-- objtype: r = tables, S = sequences, f = functions, T = types, n = schemas.
SELECT
  pg_get_userbyid(d.defaclrole)        AS creator_role,
  coalesce(n.nspname, '<all schemas>') AS schema,
  d.defaclobjtype                      AS objtype,
  d.defaclacl::text                    AS acl
FROM pg_default_acl d
LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
ORDER BY 1, 2, 3;


-- Q3. Bodies of every SECURITY DEFINER function reachable by anon/authenticated.
-- For each one, answer: what can the caller make it do, and what in the body
-- stops a caller who is not who the function assumes? Red flags:
--   * identity taken from a parameter (p_user_id, p_org_id, p_role) and trusted
--   * no check of auth.uid() / jwt claims against table state
--   * dynamic SQL (EXECUTE format(...)) built from parameters
--   * proconfig without search_path (search_path hijack)
SELECT
  p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS signature,
  coalesce(array_to_string(p.proconfig, ', '), '<none>') AS settings,
  p.prosrc AS body
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('public')
  AND p.prosecdef
  AND (has_function_privilege('anon', p.oid, 'EXECUTE')
       OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
ORDER BY 1;


-- Q4. Tables, views and sequences in exposed schemas with privileges for anon /
-- authenticated, plus RLS state. A table with grants and rls_enabled = false is
-- fully readable/writable through PostgREST. rls_forced = false matters only for
-- the table owner (and roles that bypass RLS).
SELECT
  n.nspname AS schema,
  c.relname AS name,
  CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned'
                 WHEN 'v' THEN 'view' WHEN 'm' THEN 'matview'
                 WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'foreign' END AS kind,
  c.relrowsecurity   AS rls_enabled,
  c.relforcerowsecurity AS rls_forced,
  (SELECT string_agg(DISTINCT a.privilege_type, ',' ORDER BY a.privilege_type)
     FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    WHERE a.grantee = 'anon'::regrole)          AS anon_privs,
  (SELECT string_agg(DISTINCT a.privilege_type, ',' ORDER BY a.privilege_type)
     FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
    WHERE a.grantee = 'authenticated'::regrole) AS authenticated_privs,
  (SELECT count(*) FROM pg_policy pol WHERE pol.polrelid = c.oid) AS policies
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public')
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
  AND (has_table_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE,DELETE')
       OR has_table_privilege('authenticated', c.oid, 'SELECT,INSERT,UPDATE,DELETE'))
ORDER BY rls_enabled, 1, 2;


-- Q5. Tables where a role holds TABLE-level UPDATE — i.e. every column. Any row
-- RLS lets that user update can be changed in EVERY column (role, is_admin,
-- plan, status, organization_id…). For each hit, ask whether every column is
-- really editable by every user the UPDATE policy admits. Explicit column-level
-- grants (attacl) are listed separately; they're the narrowed, intended shape.
-- (information_schema.column_privileges is not used: it expands table-level
-- grants into every column and buries the signal.)
SELECT n.nspname AS schema, c.relname AS table, r.rolname AS grantee,
       'UPDATE (all columns, table-level)' AS grant_kind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN (VALUES ('anon'), ('authenticated')) AS r(rolname)
WHERE n.nspname IN ('public') AND c.relkind IN ('r', 'p')
  AND EXISTS (SELECT 1 FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
              WHERE a.grantee = r.rolname::regrole AND a.privilege_type = 'UPDATE')
UNION ALL
SELECT n.nspname, c.relname, pg_get_userbyid(a.grantee),
       'UPDATE (' || string_agg(att.attname, ', ' ORDER BY att.attname) || ')'
FROM pg_attribute att
JOIN pg_class c ON c.oid = att.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(att.attacl) a
WHERE n.nspname IN ('public') AND att.attacl IS NOT NULL AND a.privilege_type = 'UPDATE'
  AND a.grantee IN ('anon'::regrole, 'authenticated'::regrole)
GROUP BY 1, 2, 3
ORDER BY 1, 2, 3;


-- Q6. Policies, with the roles they apply to and their expressions. Look for:
--   * roles = {public} (applies to anon too, unless the expression excludes it)
--   * USING (true) / WITH CHECK (true)
--   * UPDATE policies with USING but no WITH CHECK (row can be moved to another
--     tenant by changing organization_id)
--   * conditions on user_metadata / raw_user_meta_data — user-editable via
--     supabase.auth.updateUser(), never an authorization source
--   * tenant read from a claim nobody sets server-side
SELECT
  schemaname, tablename, policyname, cmd, permissive,
  roles::text AS roles,
  qual        AS using_expr,
  with_check  AS check_expr
FROM pg_policies
WHERE schemaname IN ('public', 'storage')
ORDER BY schemaname, tablename, cmd, policyname;


-- Q7. Views that do not run with the caller's privileges. A view owned by
-- postgres without security_invoker evaluates its base tables as postgres,
-- so RLS on those tables does not apply to whoever queries the view.
SELECT n.nspname AS schema, c.relname AS view, pg_get_userbyid(c.relowner) AS owner,
       coalesce(c.reloptions::text, '<none>') AS options
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public')
  AND c.relkind IN ('v', 'm')
  AND NOT coalesce('security_invoker=true' = ANY (c.reloptions)
                   OR 'security_invoker=on' = ANY (c.reloptions), false)
  AND (has_table_privilege('anon', c.oid, 'SELECT')
       OR has_table_privilege('authenticated', c.oid, 'SELECT'));


-- Q8. Roles that matter for the backend door: who can log in, who bypasses RLS,
-- and who is a member of whom. If the backend's role is a member of
-- authenticated (or switches into it), every grant it needs is a browser grant.
SELECT r.rolname, r.rolcanlogin, r.rolbypassrls, r.rolsuper, r.rolinherit,
       coalesce((SELECT string_agg(g.rolname, ', ')
                   FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                  WHERE m.member = r.oid), '') AS member_of
FROM pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%'
ORDER BY r.rolbypassrls DESC, r.rolcanlogin DESC, r.rolname;


-- Q9. Storage buckets. public = true means objects are readable by URL with no
-- policy check at all. Then read the storage.objects rows from Q6.
SELECT id, name, public, file_size_limit, allowed_mime_types
FROM storage.buckets
ORDER BY public DESC, id;


-- Q10. Tables in ANY schema (not only the exposed ones) that PUBLIC, anon or
-- authenticated can write. A non-exposed schema isn't reachable through
-- PostgREST, but every database role — your backend, a read-only reporting
-- role, a SQL injection — inherits PUBLIC grants. Known example: pg_net's
-- net.http_request_queue ships with ALL to PUBLIC, which lets any role make the
-- database send HTTP requests. Report these under the backend door.
SELECT n.nspname AS schema, c.relname AS name,
       (SELECT string_agg(DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                                        ELSE pg_get_userbyid(a.grantee) END
                          || ':' || a.privilege_type, ', ')
          FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
         WHERE (a.grantee = 0 OR a.grantee IN ('anon'::regrole, 'authenticated'::regrole))
           AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')) AS write_grants
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_%'
  AND EXISTS (SELECT 1 FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
              WHERE (a.grantee = 0 OR a.grantee IN ('anon'::regrole, 'authenticated'::regrole))
                AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'))
ORDER BY (n.nspname IN ('public')) DESC, 1, 2;


-- Q11. Other schemas reachable at all (USAGE) by anon/authenticated. Not every
-- one of these is exposed through PostgREST, but functions inside them can be
-- called from an exposed function or a view.
SELECT n.nspname AS schema,
       has_schema_privilege('anon', n.oid, 'USAGE')          AS anon_usage,
       has_schema_privilege('authenticated', n.oid, 'USAGE') AS authenticated_usage
FROM pg_namespace n
WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  AND (has_schema_privilege('anon', n.oid, 'USAGE')
       OR has_schema_privilege('authenticated', n.oid, 'USAGE'))
ORDER BY 1;
