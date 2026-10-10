# Fix templates

Adapt names and schemas. Every template is a migration: run it locally, re-run
the confirmation tests, and let the user deploy it through their pipeline.
Include a rollback note in each migration header.

## 1. Default-deny the function and table surface

The trap: `REVOKE ALL ON FUNCTION f FROM PUBLIC` leaves the grants Supabase made
to `anon` and `authenticated` **by name**. You have to name them, and you have to
change the default privileges or the next migration reopens it.

```sql
BEGIN;

-- Future objects: stop inheriting grants.
-- (a) The built-in PUBLIC EXECUTE default can only be removed globally.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- (b) Supabase's named-role defaults, per exposed schema.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM anon, authenticated;

-- Existing functions: revoke all, grant back an explicit allowlist.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;

-- ALLOWLIST — every line needs a reason. This list is what the CI test pins.
GRANT EXECUTE ON FUNCTION public.current_tenant_id() TO authenticated; -- used by RLS policies
-- GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) TO supabase_auth_admin;

COMMIT;
```

Repeat the `FOR ROLE` lines for every role that creates objects (check catalog
Q2: `creator_role`). `supabase_admin` usually has its own defaults in `public`
granting everything to `anon`/`authenticated`; your migrations may not be
allowed to change another role's defaults on the hosted platform. If you can't
remove them, make sure nothing of yours is created as that role, and let the CI
allowlist test (which checks the objects, not the defaults) catch it if it ever
happens.

Extension objects outside exposed schemas (catalog Q10) are often granted by
`supabase_admin`, and a `REVOKE` run as `postgres` silently does nothing ("no
privileges could be revoked") because only the grantor can take back its
grant. Try it inside a transaction and read the warning before writing it into
a migration. If it can't be revoked: say so in the report, pin the current state
in the CI test so a change is noticed, and decide with the user whether to
accept it, ask Supabase support, or stop using the extension. (Known case:
pg_net's `net.http_request_queue` is writable by `PUBLIC`.)

**Before running it:** list every function the frontend (supabase-js `.rpc()`),
RLS policies, triggers and the backend call. Policies call functions as the
querying role, so a helper used inside a policy must stay granted to the roles
the policy applies to. Run the whole test suite locally after.

**Tables.** If the browser uses supabase-js for data, `authenticated` legitimately
needs table grants — keep them, and make sure RLS and column grants (§4) are
right. If the browser only talks to your backend, revoke table grants from
`anon` and `authenticated` too (after §2, if the backend switches into
`authenticated`).

Supabase has announced a change to the grants new tables receive by default.
Check the current docs before relying on it, and note: a default change affects
objects created **after** it — existing tables and functions keep their grants,
so this migration is still needed for them.

## 2. A dedicated backend role

When the backend switches into `authenticated` per request, it shares that role
with every browser. Give it its own:

```sql
-- 2a: additive, safe while the backend still uses authenticated.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOLOGIN NOINHERIT;
  END IF;
END $$;
GRANT app_user TO api_runtime;               -- the backend's LOGIN role
GRANT USAGE ON SCHEMA public TO app_user;
-- Mirror exactly what the backend needs (generate from the current grants of
-- authenticated, then trim):
-- GRANT SELECT, INSERT, UPDATE, DELETE ON public.<table> TO app_user;
-- Add app_user to every policy the backend relies on:
-- ALTER POLICY <name> ON public.<table> TO authenticated, app_user;
COMMIT;
```

Deploy in three steps, each its own release, so nothing breaks in between:

1. **2a** — create `app_user`, mirror grants, retarget policies to both roles.
2. **Switch the backend** to `SET LOCAL ROLE app_user`. If it read `auth.uid()`,
   either grant `USAGE ON SCHEMA auth` + `EXECUTE ON auth.uid()` to `app_user`,
   or read `current_setting('request.jwt.claims', true)::jsonb ->> 'sub'`.
3. **Strip `authenticated`** of what only the backend needed (table grants,
   function grants, policies), keeping only what the browser itself uses.

## 3. Fence SECURITY DEFINER functions the backend calls

PostgREST and GraphQL always connect as `authenticator` and switch role from
there; `session_user` stays `authenticator` and the caller cannot change it. The
backend connects as its own LOGIN role. So `session_user` tells the doors apart:

```sql
CREATE OR REPLACE FUNCTION public.assert_backend_session() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = '' AS $$
BEGIN
  IF session_user NOT IN ('api_runtime', 'postgres', 'supabase_admin') THEN
    RAISE EXCEPTION 'not callable from this connection' USING ERRCODE = '42501';
  END IF;
END $$;
REVOKE ALL ON FUNCTION public.assert_backend_session() FROM PUBLIC, anon, authenticated;
```

Then, at the top of each function the backend must call:

```sql
CREATE OR REPLACE FUNCTION public.add_member(p_org uuid, p_user uuid, p_role text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM public.assert_backend_session();                    -- fence: which door
  IF NOT EXISTS (                                             -- guard: who, from state
    SELECT 1 FROM public.invitations i
     WHERE i.organization_id = p_org
       AND i.email = (SELECT lower(email) FROM auth.users WHERE id = auth.uid())
       AND i.role = p_role AND i.accepted_at IS NULL AND i.expires_at > now()
  ) THEN
    RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';    -- don't echo values
  END IF;
  -- ...
END $$;
```

The fence alone is not enough — a bug in the backend can still call it with the
wrong ids. The guard checks the **verified caller** (`auth.uid()`, JWT claims)
against table state, never a parameter that names the caller. Always
`SET search_path = ''` and schema-qualify everything.

`CREATE OR REPLACE` with the same signature keeps the function's ACL — so this
can ship separately from §1 and be reverted alone.

## 4. Column guards

RLS chooses rows, not columns. A member allowed to update "their own" row can
otherwise change `role`, `is_active`, `plan`, `organization_id`.

**If the role is dedicated (only your backend uses it)** — column grants:

```sql
REVOKE UPDATE ON public.profiles FROM app_user;
GRANT UPDATE (display_name, avatar_url, preferred_locale) ON public.profiles TO app_user;
```

**If the role is shared, or only some users are restricted** — a trigger with an
allow-list (an allow-list fails closed when someone adds a column; a deny-list
fails open):

```sql
CREATE OR REPLACE FUNCTION public.guard_worker_columns() RETURNS trigger
LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  IF <caller is the restricted kind of user> THEN
    IF (to_jsonb(NEW) - ARRAY['status','notes','updated_at'])
       IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status','notes','updated_at']) THEN
      RAISE EXCEPTION 'column not editable by this role' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER guard_worker_columns BEFORE UPDATE ON public.work_orders
  FOR EACH ROW EXECUTE FUNCTION public.guard_worker_columns();
```

Watch for: timestamp columns your ORM round-trips with less precision than
Postgres stores (compare `date_trunc('milliseconds', …)` or exclude them), and
nullable columns the restricted user's normal flow leaves NULL.

Also add `WITH CHECK` to every `UPDATE` policy that has a `USING`, so a row can't
be moved into another tenant by changing its `organization_id`.

## 5. Views

```sql
ALTER VIEW public.some_view SET (security_invoker = true);  -- Postgres 15+
```

Or revoke the view from `anon`/`authenticated` if only the backend reads it.

## 6. Storage

Public buckets skip policies entirely: make them private unless every object is
meant to be world-readable, and serve signed URLs. In `storage.objects`
policies, scope by bucket **and** by a tenant path segment, for `INSERT`,
`UPDATE` (rename/move) and `DELETE` — not only `SELECT`.
