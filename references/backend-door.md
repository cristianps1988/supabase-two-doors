# The backend door — review checklist

Read-only. You are reading the backend's code and configuration, not calling it.
Record each answer, with file:line, in `security-audit/LOG.md`.

## 1. Connection role

Find where the backend builds its database connection (`DATABASE_URL`, pool setup, Drizzle/Prisma/Knex/SQLAlchemy config).

| Connects as | What it means |
|---|---|
| `postgres` / superuser | RLS never applies to this door. Every tenant boundary is application code. One missed `WHERE organization_id = …` is a cross-tenant leak. |
| `service_role` key via supabase-js | Same: `service_role` has `BYPASSRLS`. Also check the key never reaches a client bundle (grep the frontend build output). |
| A custom LOGIN role with `BYPASSRLS` | Same as above, with a better name. |
| A custom LOGIN role without `BYPASSRLS` that **switches** into `authenticated` per request | RLS applies, but the backend and the browser now share one role. Every grant the backend needs is a grant the browser has through PostgREST. Most "authenticated can call X" findings trace back here. |
| A custom role that switches into a **dedicated** role (e.g. `app_user`) | The good shape. Check the dedicated role is `NOLOGIN` and nothing grants it to `authenticator`. |

Cross-check with catalog Q8: `rolbypassrls`, memberships.

## 2. Tenant context

How does the database learn who the caller is and which tenant they act for?

- Look for `set_config('request.jwt.claims', …)`, `SET LOCAL ROLE`, `SET LOCAL app.tenant_id`, or a per-request transaction wrapper.
- Are those settings **transaction-local** (`SET LOCAL`, `set_config(..., true)`) inside a transaction? Session-level settings on a pooled connection leak into the next request that reuses it.
- Where does the tenant value come from? It must be a verified token claim or a server-side lookup (e.g. membership table). A header (`X-Org-Id`), query param or body field the client sends is a cross-tenant bug unless the server re-checks membership.
- Is the claim set only after the user's membership in that tenant has been confirmed, and is membership re-checked per request (or is a deactivated member's token good until it expires)?

## 3. Token verification

- Is the JWT's signature verified (JWKS or the project secret), or only decoded? `jwt.decode` without verification is a full bypass.
- Are `exp`, `aud` (`authenticated`) and `iss` checked?
- Does authorization read `user_metadata`? It is user-editable via `supabase.auth.updateUser()`. Roles must come from `app_metadata`, a custom access-token hook, or the database.
- If there's a custom access-token hook: what does it return for a user with no tenant? A hook returning SQL `NULL` (e.g. `jsonb_set` with a NULL value — `jsonb_set` is STRICT) breaks login for those users rather than failing safe.

## 4. Role checks on mutations

For each mutating route: is there a role/permission check beyond "belongs to the tenant"? Tenant match alone lets a read-only member write. List routes that have none.

## 5. Client IP, rate limits, abuse signals

- Which header does the app read for the client IP? `X-Forwarded-For` left-most entry is client-controlled. The trustworthy value is the one appended by the proxy you control (right-most, or the hop count you configure), or a provider header like `CF-Connecting-IP` **only when the request came from that provider's IP ranges**.
- Are rate-limit stores bounded (expiry / sweep)? An in-memory `Map` keyed by IP that is never pruned is a memory leak an attacker can drive.
- IPv6: one subscriber usually owns a whole /64. Keying limits on the full address gives them 2^64 fresh identities.

## 6. Webhooks and internal endpoints

- Signature verified over the raw body, with a constant-time compare, and a timestamp tolerance?
- Idempotency: is an event marked processed **after** it was applied, in the same transaction — or claimed first and lost if the process crashes in between?
- Internal endpoints (cron, jobs): protected by a secret that is not a published default? Does the app refuse to boot in production with the default?
- Do this for **every** secret with a fallback in code or `.env.example` (JWT signing secrets for your own tokens, impersonation, OAuth state, webhook, internal API). A check that the variable *exists* doesn't help when it's set to the value everyone can read in the repository; refuse the published default by value. For tokens your backend mints itself (impersonation, magic links), check that verification also re-checks who issued them (still an active admin?) and not only the signature.

## 7. Search inputs

User text interpolated into `LIKE`/`ILIKE` patterns without escaping `%`, `_` and `\` turns a search box into a "match everything" query. Not an injection, but it bypasses intended filters and can be expensive.
