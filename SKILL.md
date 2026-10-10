---
name: supabase-two-doors
description: Security audit and hardening workflow for apps that run their OWN backend (Node, Hono, Express, Nest, Django, Go, Rails…) against a Supabase Postgres database, where the browser may never call Supabase directly but PostgREST/GraphQL/Storage are still exposed with the public anon key. Finds what anon and authenticated can actually reach (including Supabase's default grants that survive REVOKE FROM PUBLIC), reviews how the backend connects and sets tenant context, writes the fixes as migrations, confirms each finding with tests against the LOCAL stack only, and freezes the exposed surface with a CI test. Use this whenever the user asks to audit, review, pentest, or harden a Supabase project, mentions RLS, SECURITY DEFINER, anon key exposure, PostgREST/RPC exposure, "is my Supabase secure", multi-tenant data isolation on Supabase, the Supabase security advisor/linter, or the change to Supabase's default table grants — even if they only mention one of the two sides.
---

# Supabase: two doors

An app with its own backend on top of Supabase has **two doors into the same database**:

1. **The backend door** — your API connects with a database role and runs the queries your code decides.
2. **The Supabase door** — PostgREST (`/rest/v1`, including `/rest/v1/rpc/*`), GraphQL (`/graphql/v1`), Storage and Realtime. Anyone holding the **anon key** can knock on it, and the anon key is public by design: it ships inside every frontend that uses Supabase, and it is usually still there even if your frontend only talks to your backend.

Teams harden the backend door (auth middleware, role checks, tenant filters) and assume the Supabase door is closed because "the frontend doesn't use supabase-js for data". It usually isn't closed. Supabase grants `anon` and `authenticated` access to objects in exposed schemas through **default privileges granted to those roles by name**, so `REVOKE ... FROM PUBLIC` — the reflex most Postgres people have — leaves them in place. A single `SECURITY DEFINER` function written for the backend becomes an RPC endpoint any browser can call.

This skill audits both doors, fixes root causes, and makes the result stay fixed.

## Safety rails — read before doing anything

These exist because an audit is something the user runs on their own system, and the most dangerous moment is when it touches something real. They are not optional, and explaining them to the user is part of the job.

- **Own project only.** Before starting, confirm with the user that the project is theirs (or that they are authorized to audit it) and write that down in the log. Everything this skill does to a hosted project needs the database connection string — which only the owner has. Do not proceed from just a URL and an anon key: those are public, so they prove nothing about ownership.
- **Hosted environments are read-only.** Against staging or production you only read: the Supabase Security Advisor and catalog queries (`references/catalog-queries.sql`) over the user's own connection. No HTTP requests to their REST/RPC/GraphQL endpoints, no writes, no "quick test" with a real account. A hosted project may hold real customers' data even when the user thinks it doesn't.
- **Active confirmation happens only on the local stack.** Every finding is proven against `supabase start`, built from the project's own migrations. The default method replays what PostgREST does — connect as `authenticator`, `SET LOCAL ROLE anon|authenticated`, set the JWT claims — inside a transaction that is always rolled back, so no keys are needed and nothing is left behind. HTTP requests, when needed, go only to `localhost` behind a guard that refuses any other host (see `references/local-confirmation.md`). This is what makes confirmation safe to run at all: it can only ever touch a copy on the user's machine.
- **No secrets in requests or in the report.** Never ask for, print, or use a hosted `service_role` key, JWT secret, or database password in requests. Connection strings are read from the user's environment, never echoed. Redact anything secret-looking from query output before writing it to the report.
- **No load.** No fuzzing, brute force, flooding, or scanners pointed at anything. A handful of targeted requests per finding, locally.
- **Log everything.** Append every query run and every local request sent to `security-audit/LOG.md` (timestamp, environment, what, why). The user should be able to replay or audit the audit.
- **Fixes go through migrations and the user's review.** Never apply DDL to a hosted database directly. Write migrations, run them locally, and let the user deploy them through their normal pipeline.

If the user asks you to cross one of these (e.g. "just try it against prod"), explain which rail it hits and why, and offer the local equivalent.

## Workflow

Create `security-audit/` in the repo for the log, the raw query results and the report. Work through the phases in order — each one feeds the next — and tell the user briefly what you found at the end of each phase before moving on.

### Phase 0 — Scope

Establish and write down in `security-audit/LOG.md`:

- Who owns the project, which environments exist (local / staging / prod), and which ones hold real users' data.
- Which schemas PostgREST exposes (`supabase/config.toml` → `[api] schemas`, or Dashboard → API settings; default is `public` and `graphql_public`). Everything in an exposed schema is reachable through the Supabase door unless privileges say otherwise.
- How the frontend talks to data: only via the backend, via supabase-js, or both. Either way the Supabase door exists — this only changes which grants are *intended*.
- Whether the local stack runs (`supabase start`). If it doesn't, phases 3 and 5 can't confirm anything; say so rather than guessing.

### Phase 1 — Map the Supabase door (read-only)

Goal: an exact list of what `anon`, `authenticated` and `PUBLIC` can reach, from the catalog, not from reading migrations. Migrations tell you what someone intended; the catalog tells you what is true, including grants nobody wrote.

1. If the Supabase MCP or CLI is available, run the Security Advisor (`get_advisors` type `security`, or Dashboard → Advisors). Record what it reports. It catches RLS-disabled tables, mutable `search_path`, exposed `auth.users` and more — but it does **not** tell you which `SECURITY DEFINER` functions are callable by whom and what they let the caller do. That is the gap this phase fills.
2. Run the queries in `references/catalog-queries.sql` — locally first, then on staging/prod over the user's read-only connection if they want the hosted picture. Each query is commented with what a hit means. Save raw output to `security-audit/catalog-<env>.md`.
3. For every function reachable by `anon` or `authenticated`, read its body and answer: what does it let the caller do, and what in the body stops a caller who isn't who the function assumes? Functions that take an identity as a parameter (`p_user_id`, `p_organization_id`, `p_role`) and trust it are the classic critical finding — anyone can pass someone else's id.
4. For every table/view reachable by `authenticated` — and by the backend's own role, if it has one — check RLS is on and look at what the policies allow *per role inside a tenant*, not just across tenants. A member who can `UPDATE` their own row can usually update *every column* of it (role, flags, plan, status) — RLS selects rows, never columns.
5. Don't stop at exposed schemas. Q10 lists tables in **any** schema that `PUBLIC`, `anon` or `authenticated` can write. Those aren't reachable through PostgREST, but every database role inherits `PUBLIC` — including a read-only reporting role or whatever an injection runs as. Extensions are the usual source (pg_net's request queue ships writable by `PUBLIC`).

Classify each item: intended (and guarded), intended but unguarded, or not intended at all.

### Phase 2 — Understand the backend door (read-only)

Read the backend's database setup and request pipeline. `references/backend-door.md` has the checklist; the questions that matter most:

- **What role does the backend connect as?** `postgres`, `service_role` or anything with `BYPASSRLS` means RLS is decoration for that door, and every tenant check lives in application code alone.
- **If it switches role per request** (`SET LOCAL ROLE authenticated` + `request.jwt.claims`), it shares a role with the Supabase door. Then every grant the backend needs is also a grant every browser has. This is the structural cause behind most findings in phase 1; the fix is a dedicated backend role (phase 4).
- **Where does tenant context come from?** It must come from a verified token or a server-side lookup — never a header, query param or body field the client controls. JWT signature, `aud` and expiry must be verified, not just decoded. Claims from `user_metadata` are user-editable and must never drive authorization.
- **Client IP and rate limits.** If rate limits or audit logs key on `X-Forwarded-For`, which hop is trusted? The left-most entry is client-controlled.

### Phase 3 — Confirm on the local stack

Every finding from phases 1–2 that claims "X can do Y" gets proven locally before it goes in the report. Follow `references/local-confirmation.md`: replay the call inside a rolled-back transaction connected as `authenticator` (connecting as `postgres` lets `session_user` fences through and invents findings), fall back to HTTP against `localhost` only for HTTP-level behaviour, one test per finding, written into the project's own test suite where possible so the confirmation becomes the regression test in phase 5. Anything that only shows up under concurrency or volume is reported as unconfirmed, not load-tested.

A finding you could not reproduce is reported as "unconfirmed" with the reason, never upgraded to confirmed. A test that passes for the wrong reason (e.g. expecting `42501` and getting a different `permission denied` with the same code) is worse than no test — assert on what was refused and why.

### Phase 4 — Fix root causes

Fix the cause, not the instance. If one function was exposed because of default privileges, all of them were, and new ones will be. `references/fixes.md` has migration templates for each:

1. **Default-deny the surface.** Remove the named-role default privileges for future objects, revoke existing grants from `PUBLIC, anon, authenticated`, then grant back an explicit allowlist. Revoking from `PUBLIC` alone does not work — that's the whole trap.
2. **A dedicated backend role** (e.g. `app_user`) that the backend switches into, with its own grants and policies, so the backend's needs stop being the browser's privileges. Then strip `authenticated` down to what the browser genuinely needs.
3. **Fence `SECURITY DEFINER` functions the backend must call** with a `session_user` check (PostgREST always connects as `authenticator` and cannot change `session_user`), plus a guard keyed on the verified caller (`auth.uid()` / JWT claims) and table state — never on a caller-supplied identity parameter.
4. **Column guards** where a role may update a row but only some of its columns: column-level `GRANT UPDATE (col, …)` when the role is dedicated, or a `BEFORE UPDATE` trigger with an allow-list when it isn't.
5. Backend-door fixes from phase 2 (tenant from verified claims, trusted proxy hops, bounded rate-limit maps).

Order matters when a fix changes what the running backend depends on: create the new role and grants first, switch the backend, then strip the old grants — each as its own deploy, so nothing breaks mid-way. Write migrations, run them locally, re-run phase 3's tests: they must now pass.

### Phase 5 — Freeze the surface

Fixes rot: the next migration adds a function and the default privileges (or a hurried `GRANT`) reopen the door. Add the CI test from `references/surface-test.md`:

- reads the catalog and compares what `anon` / `authenticated` / the backend role can execute and access against a **committed allowlist**, failing on any difference in either direction;
- creates a canary function and table and asserts they inherit nothing for `anon`/`authenticated`/`PUBLIC`;
- asserts every reachable `SECURITY DEFINER` function contains the fence.

Then **mutation-check every security test**: revert its fix locally, run the test, watch it fail, restore. A security test you have never seen fail has not been shown to test anything.

### Phase 6 — Verify and report

After the user deploys the migrations to staging, re-run the catalog queries there (read-only) and diff against the allowlist. Write `security-audit/REPORT.md` with this structure:

```markdown
# Supabase security audit — <project> — <date>

## Summary
<two or three sentences: what was exposed, through which door, what is fixed>

## Scope and rails
<environments touched and how (read-only / local only), who confirmed ownership>

## Findings
### <ID> — <severity> — <one-line title>
- Door: Supabase (anon | authenticated) / backend
- What a caller could do: <concrete, one sentence>
- Evidence: <catalog row or local test name — no secrets>
- Root cause: <e.g. default privilege to `authenticated` on public functions>
- Fix: <migration file> — Test: <test file> (mutation-checked: yes/no)
- Status: fixed | fix written, not deployed | unconfirmed (<why>)

## What keeps it fixed
<CI surface test, allowlist location, how to add a function correctly>

## Not covered
<what this audit did not look at>
```

Severity: **critical** — anon (no account) can read or write other people's data or escalate; **high** — any signed-in user can cross tenants or escalate roles; **medium** — escalation inside a tenant, or a defense layer missing while another still holds; **low** — hygiene that would matter once something else fails.

Be explicit in "Not covered" — Realtime authorization, Edge Functions, Storage policies beyond the bucket list, application logic bugs. An audit that silently implies full coverage is how the next incident happens.
