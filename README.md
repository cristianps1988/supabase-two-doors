# supabase-two-doors

A Claude skill that audits and hardens a Supabase project that has **its own backend** in front of the same database.

## The problem

If your API talks to Supabase Postgres and your frontend never calls Supabase for data, it's easy to believe the database is only reachable through your API. It isn't. PostgREST (`/rest/v1`, including every function at `/rest/v1/rpc/<name>`), GraphQL and Storage are still there, and the key to knock on them, the anon key, is public by design.

What gets reached through that door is decided by Postgres privileges. Supabase grants `anon` and `authenticated` access to new objects in `public` **through default privileges granted to those roles by name**. So the usual Postgres reflex, `REVOKE ALL ... FROM PUBLIC`, leaves those grants in place. One `SECURITY DEFINER` function written for your backend then becomes an endpoint any browser can call.

That is how a real multi-tenant SaaS ended up with platform-admin functions callable by anyone with the anon key. This skill is the process that found and fixed that, written down so it can be repeated.

## What it does

| Phase | What happens | Touches |
|---|---|---|
| 0. Scope | Ownership, environments, exposed schemas, how the frontend reaches data | nothing |
| 1. Map the Supabase door | Security Advisor + 11 catalog queries: what `anon`/`authenticated`/`PUBLIC` can execute and access, default privileges, policies, views, buckets | read-only |
| 2. Map the backend door | Connection role, tenant context, JWT verification, role checks, client IP, webhooks | reads code |
| 3. Confirm | Each finding proven by a test against **the local stack only** | `localhost` |
| 4. Fix | Migration templates: default-deny + allowlist, dedicated backend role, `session_user` fence, column guards | local migrations |
| 5. Freeze | CI test that pins the exposed surface to a committed allowlist, plus canaries; every security test mutation-checked | CI |
| 6. Report | Findings with door, evidence, root cause, fix, test | — |

## Safe by default

- **Own project only.** Hosted work requires the database connection string, which only the owner has. A URL and an anon key prove nothing, because both are public.
- **Hosted environments are read-only**: the Advisor and catalog `SELECT`s over your connection. The skill sends no requests to your hosted REST/RPC/GraphQL endpoints.
- **Active testing runs only on `supabase start`.** By default the skill replays what PostgREST does: it connects as `authenticator`, switches role and sets the JWT claims, all inside a transaction that is always rolled back. That needs no keys and leaves nothing behind. HTTP checks go only to `localhost`, behind a guard that refuses any other host.
- **No secrets** in requests or the report, **no load** (no fuzzing, no scanners), and **every query and request is logged** to `security-audit/LOG.md`.
- **Fixes are migrations you review and deploy.** The skill never applies DDL to a hosted database.

## What it is not

- A replacement for the [Supabase Security Advisor](https://supabase.com/docs/guides/database/database-advisors). Phase 1 runs it first and covers what it doesn't: who can call which `SECURITY DEFINER` function, and what that function lets them do.
- A general Supabase best-practices guide. For that, see [supabase/agent-skills](https://github.com/supabase/agent-skills).
- A penetration-testing tool. It doesn't probe anything you don't run locally.
- Full coverage. Realtime authorization, Edge Functions and your application logic are out of scope, and the report says so.

## Install

Claude Code:

```bash
git clone https://github.com/cristianps1988/supabase-two-doors ~/.claude/skills/supabase-two-doors
```

Then, in your project: *"audit the Supabase security of this project"*.

Requirements: the Supabase CLI, Docker (for `supabase start`), and `psql` or a Postgres client in your test suite.

## Layout

```
SKILL.md                         workflow and safety rails
references/catalog-queries.sql   read-only inventory (Q1–Q11)
references/backend-door.md       backend review checklist
references/local-confirmation.md localhost-only confirmation tests
references/fixes.md              migration templates
references/surface-test.md       CI allowlist test + mutation check
```

## License

MIT
