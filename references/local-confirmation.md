# Confirming findings on the local stack

Every "X can do Y" claim gets proven here before it goes in the report — and
only here. The local stack is a copy built from the project's own migrations on
the user's machine. Nothing in this file is ever pointed at a hosted project.

## 1. Start the local stack

```bash
supabase start          # builds the DB from supabase/migrations
supabase status         # ports and local connection strings
```

If the project already runs a local stack you'd collide with (ports in use),
ask the user before stopping it — they may have work in it.

## 2. Primary method: replay the Supabase door inside the database

PostgREST does three things per request: it connects as `authenticator`, runs
`SET LOCAL ROLE anon|authenticated`, and writes the JWT claims into
`request.jwt.claims`. You can do exactly the same in `psql`, inside a
transaction you always roll back:

```sql
-- connect as authenticator, NOT postgres (see "why" below)
-- psql "postgresql://authenticator:postgres@127.0.0.1:<db-port>/postgres"
BEGIN;
SET LOCAL ROLE anon;                                  -- or authenticated
SELECT set_config('request.jwt.claims',
  json_build_object('sub', '<throwaway-user-uuid>', 'role', 'authenticated')::text, true);

SELECT public.platform_grant_admin('<throwaway-user-uuid>', 'super', NULL, NULL);
SELECT level, is_active FROM public.platform_admins WHERE user_id = '<throwaway-user-uuid>';
ROLLBACK;                                             -- always
```

Why this is the default:

- **Same checks as the real door.** Privileges, RLS, `auth.uid()` (it reads
  `request.jwt.claims`) and `session_user` fences all behave as they would
  behind PostgREST.
- **No keys.** No anon key, no JWT minting, no service-role key — nothing
  secret-shaped to read, print or leave in a file.
- **Nothing to clean up.** The `ROLLBACK` undoes every write, even if a step
  fails halfway.

**Why `authenticator` and not `postgres`:** a `session_user` fence
(`IF session_user NOT IN ('api_runtime', 'postgres', …)`) lets a superuser
session through. Simulating as `postgres` + `SET ROLE anon` reports a fenced
function as open — a false positive. `authenticator` is what PostgREST really
uses. On the local stack its password is the development default `postgres`;
if that doesn't work, read the local connection details from `supabase status`
or the project's config rather than guessing, and stop if they aren't local.

For the backend's own role (`app_user` or similar), `authenticator` can't switch
into it — that's the point. Connect as the backend's LOGIN role if you have its
local password, otherwise as `postgres` + `SET LOCAL ROLE app_user`; the latter
is fine for privileges, RLS and column checks, but not for anything a
`session_user` fence decides (postgres passes every fence).

Throwaway rows the test needs (a user in `auth.users`, two organizations, a
membership) can be seeded in the **same transaction** before `SET LOCAL ROLE`
only if the connecting role can write them — usually it can't. In that case
seed them with a separate superuser connection, prefix every name/email with an
audit marker (e.g. `audit-`), and delete them in a cleanup step that runs even
when the test fails (a shell `trap`, a test `afterAll`, a `finally`).

## 3. Secondary method: real HTTP to localhost

Use it when the finding is about HTTP-level behaviour (Storage listing, headers,
the backend's own routes, GraphQL), or to double-check one critical finding
end-to-end. Every script or test starts with a guard that refuses anything but
the local stack:

```ts
const target = new URL(process.env.SUPABASE_URL ?? "http://127.0.0.1:54321");
if (!["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)) {
  throw new Error(`Refusing to run: ${target.hostname} is not the local stack`);
}
```

```bash
case "$SUPABASE_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "Refusing to run: $SUPABASE_URL is not the local stack" >&2; exit 1 ;;
esac
```

The local anon key comes from `supabase status`. Read it at runtime; never write
it to a file in the audit outputs. Create users through local sign-up, prefixed
with the audit marker, and remove them (and any Storage objects) in a cleanup
step that runs on failure too.

## 4. One test per finding

Where the project has a test suite that talks to the local database, write each
confirmation as a test there, so it becomes the regression test in phase 5.

Two rules keep these honest:

- **Assert the state, not only the error.** Re-read the row the call would have
  changed (inside the same transaction, before `ROLLBACK`). A call that errors
  *after* writing is still a finding.
- **Assert which refusal.** `42501` covers both "permission denied for
  function" and a guard's own `RAISE ... ERRCODE '42501'`; check the message. A
  test that passes because of an unrelated error (a CHECK constraint, wrong
  argument names, a MIME-type rejection in Storage) proves nothing. Run every
  confirmation once and read *why* it was refused before calling a door closed.

Codes through PostgREST: `42501` privilege or guard refusal (tell them apart by
message), `PGRST202` no function with that name and those argument names
(usually a broken test, not a closed door), `PGRST301` invalid JWT. Codes shift
between versions: confirm each by running the test.

## 5. Things not to confirm actively

Race conditions, rate-limit bypasses and anything that needs volume: describe
them from the code and mark them "unconfirmed — needs load, not run". The rail
against load applies locally too; it keeps the habit honest.

## 6. Log

Append each confirmation to `security-audit/LOG.md`: finding id, method
(in-DB / HTTP), what was run, result, and that cleanup left 0 rows.
