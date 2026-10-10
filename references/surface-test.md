# Freezing the surface in CI

Fixes rot. The next migration adds a function, the default privileges or a
hurried `GRANT` reopen the door, and nobody notices because every existing test
connects as the backend. This test reads the catalog and fails on any change to
what `anon`, `authenticated` and the backend role can reach.

It needs a real database in CI: `supabase start` in the job (or a Postgres
service with the migrations applied), and a superuser connection to read the
catalog.

## Allowlist file

Commit it next to the test. Every entry is a decision someone made on purpose.

```json
{
  "_comment": "What each role may EXECUTE in public. Adding a line requires a fence + guard (see SECURITY.md).",
  "functions": {
    "anon": [],
    "authenticated": ["current_tenant_id()"],
    "app_user": ["current_tenant_id()", "add_member(p_org uuid, p_user uuid, p_role text)"]
  },
  "tables": {
    "anon": [],
    "authenticated": []
  }
}
```

## Test (Vitest + postgres.js — adapt to the project's stack)

```ts
import { readFileSync } from "node:fs";
import postgres from "postgres";
import { afterAll, describe, expect, it } from "vitest";

const allow = JSON.parse(readFileSync(new URL("./db-surface.allowlist.json", import.meta.url), "utf8"));
const sql = postgres(process.env.SUPERUSER_DATABASE_URL ?? "postgres://postgres:postgres@127.0.0.1:54322/postgres");
afterAll(() => sql.end());

const executable = (role: string) => sql<{ sig: string }[]>`
  SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS sig
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'public' AND has_function_privilege(${role}, p.oid, 'EXECUTE')
  ORDER BY 1`;

describe("db surface", () => {
  for (const role of Object.keys(allow.functions)) {
    it(`${role} can execute EXACTLY the allowlisted functions`, async () => {
      const actual = (await executable(role)).map((r) => r.sig).sort();
      expect(actual).toEqual([...allow.functions[role]].sort());
    });
  }

  for (const role of Object.keys(allow.tables)) {
    it(`${role} has table privileges on EXACTLY the allowlisted relations`, async () => {
      const rows = await sql<{ rel: string }[]>`
        SELECT c.relname AS rel FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m')
          AND has_table_privilege(${role}, c.oid, 'SELECT,INSERT,UPDATE,DELETE')
        ORDER BY 1`;
      expect(rows.map((r) => r.rel).sort()).toEqual([...allow.tables[role]].sort());
    });
  }

  it("no public function carries a PUBLIC execute grant", async () => {
    const rows = await sql`
      SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND EXISTS (
        SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')`;
    expect(rows.map((r) => r.proname)).toEqual([]);
  });

  it("every SECURITY DEFINER function the backend can call is fenced", async () => {
    const rows = await sql`
      SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.prosecdef
        AND has_function_privilege('app_user', p.oid, 'EXECUTE')
        AND p.prosrc NOT ILIKE '%assert_backend_session%'
        AND p.proname <> 'current_tenant_id'`;   // read-only helpers used by policies
    expect(rows.map((r) => r.proname)).toEqual([]);
  });

  it("a new function inherits nothing (canary)", async () => {
    await sql`CREATE FUNCTION public.__surface_canary() RETURNS int LANGUAGE sql AS 'SELECT 1'`;
    try {
      for (const role of ["anon", "authenticated"]) {
        const [r] = await sql`SELECT has_function_privilege(${role}, 'public.__surface_canary()', 'EXECUTE') AS ok`;
        expect(r.ok).toBe(false);
      }
    } finally {
      await sql`DROP FUNCTION IF EXISTS public.__surface_canary()`;
    }
  });

  it("a new table inherits nothing (canary)", async () => {
    await sql`CREATE TABLE public.__surface_canary_t (id int)`;
    try {
      for (const role of ["anon", "authenticated"]) {
        const [r] = await sql`SELECT has_table_privilege(${role}, 'public.__surface_canary_t', 'SELECT,INSERT,UPDATE,DELETE') AS ok`;
        expect(r.ok).toBe(false);
      }
    } finally {
      await sql`DROP TABLE IF EXISTS public.__surface_canary_t`;
    }
  });
});
```

Notes:

- The canaries are created by the role the test connects as. Make that the same
  role your migrations run as (usually `postgres`), or the canary tests a
  different set of default privileges than the ones that matter.
- If the browser legitimately uses supabase-js for data, `tables.authenticated`
  won't be empty — list exactly what it needs.
- The test compares in **both** directions: a removed grant fails too, so the
  allowlist never drifts into fiction.

## Mutation check

For each security test (this file and the phase 3 confirmations): revert its
fix locally (e.g. re-`GRANT` the function to `authenticated`, drop the fence
line, drop the trigger), run the test, confirm it fails with the message you
expect, restore. Record "mutation-checked: yes" in the report only for tests you
actually saw fail.
