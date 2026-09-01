# Task: Integration tests for redirect-driven Browser Flows

**Status: implemented** — `internal/server/integration_harness_test.go` and
`internal/server/integration_test.go`, `make test-integration`, CI Postgres
service. One deviation from the plan, found while running it: a fresh
database broke the pre-existing `janitor`/`ratelimit` suites, which assumed
an already-migrated database. Both now migrate in their own `TestMain`, and
`storage.Migrate` takes an advisory lock so concurrent suites (and
production replicas) serialize instead of racing.

Codify the manual verification matrix of [ADR 0006](../adr/0006-content-negotiated-browser-flows.md)
(implemented in [browser-flow-redirects.md](browser-flow-redirects.md)) as
automated integration tests against a real Postgres. Read
[CONTEXT.md](../../CONTEXT.md) first and use its vocabulary verbatim
(Tenant, Identity, Self-Service Flow, Browser Flow, One-Time Code, Courier, …).

## Problem

The Browser Flow redirect contract was verified by hand with curl against a
live server. Nothing guards it now: the unit tests in
`internal/server/browserflow_test.go` cover negotiation, `return_to`
validation, and form decoding in isolation, but no test drives a flow end to
end through real handlers, real CSRF cookies, real RLS, and a real flow row.

## Settled design (do not relitigate)

1. **Scope**: HTTP-level integration tests of the public (and admin) API.
   No browser/JS e2e — the reference UI stays untested example code.
2. **Postgres via the existing convention**: `PRATU_TEST_DATABASE_URL` env
   var; `t.Skip` when unset (same as `internal/storage/janitor_test.go`,
   `internal/ratelimit/ratelimit_test.go`). No testcontainers, no new deps.
3. **In-process harness**: `httptest.NewServer` wrapping the real
   `server.NewPublic(...)` handler (plus `server.NewAdmin(...)`), never an
   exec'd binary.
4. **CI runs them**: add a `postgres` service to `.github/workflows/ci.yml`
   with a setup step that creates the unprivileged `pratu` role
   (`NOSUPERUSER NOBYPASSRLS` — RLS is silently inert under superuser; see
   `scripts/devdb/01-app-role.sql`), then export
   `PRATU_TEST_DATABASE_URL` for the existing `go test ./...` step. The
   janitor/ratelimit tests come back to life in CI for free.
5. **Tenant-per-test isolation**: migrate once per suite, then each test
   creates its own Tenant (unique slug). A Tenant is a fully isolated
   identity namespace, so no truncation/cleanup between tests, and every
   test doubles as an RLS-isolation test.
6. **Matrix** (must-have; see Acceptance below): negotiation, form-post
   journeys, error persistence across rollback, flow-read CSRF gate,
   open-redirect, fatal codes, legacy fallback, verification + recovery
   chains (One-Time Codes read from the `courier_messages` outbox),
   rate-limit redirect, `mfa_required` held state. **Not** social callback
   (needs a fake OIDC provider) and not full SMS-factor journeys.
7. **Location**: `internal/server/integration_test.go`, `package server`,
   following the existing env-gated file style.
8. **Tenants are created through the admin API handler** (`POST
   /admin/tenants` with the `ui` block), not `storage.TenantStore` — the
   test must exercise the path operators use.
9. **The harness runs `storage.Migrate` itself** at suite start
   (migrations are idempotent), so one command works against an empty
   database.
10. **Make target**: `test-integration` = `db-up` + `go test` with
    `PRATU_TEST_DATABASE_URL` defaulting to the compose database, which
    publishes on 35432 to stay clear of a Postgres already on 5432.

## Wiring map (verified)

The harness assembles exactly what `cmd/pratu/main.go` (lines ~85–140) does,
minus listeners:

| Piece | How |
| --- | --- |
| Pool | `storage.Connect(ctx, url)` — refuses superuser/BYPASSRLS roles, so the CI role setup matters |
| Migrations | `storage.Migrate(ctx, pool)` (idempotent, ordered by filename) |
| Cipher | Skip `storage.SetCipher` (nil = plaintext at rest) — tests don't need encryption |
| Resolver | `tenant.NewResolver("pratu.test", storage.NewTenantStore(pool))`; requests select the Tenant via `req.Host = "<slug>.pratu.test"` |
| Breach checker | Stub `password.BreachChecker` (interface: `BreachCount(ctx, password) (int, error)`) returning 0 — no HIBP network calls |
| Limiter | `ratelimit.New(pool)` (real, Postgres counters) |
| Providers | `oauth2.NewProviders([]byte("test-system-secret..."))` — needed for the OAuth2-challenge-uses-`ui.login_url` test |
| Public handler | `server.NewPublic(pool, resolver, breach, limiter, providers, true /* referenceUI */, slog…)` |
| Admin handler | `server.NewAdmin(pool, "test-root-key", "pratu.test", providers)` |
| Courier | Do **not** start `drainCourier`; One-Time Codes sit in the `courier_messages` outbox (`payload->>'code'`, filter by `recipient`, latest first) — reading the table directly avoids the log-tailing race entirely |

HTTP client per test: `http.Client` with a fresh `cookiejar` and
`CheckRedirect: func(...) error { return http.ErrUseLastResponse }` so 303s
can be asserted instead of followed. HTML-ness is signalled per request via
`Accept: text/html` or a form-encoded body; JSON clients send
`Accept: application/json`.

## Gotchas (learned the hard way)

- **Per-IP rate limits are global across tests**: `limitFlowCreatePerIP` is
  30/min and `httptest` requests all arrive from the same RemoteAddr. The
  suite will blow through it and 429/redirect spuriously. With no trusted
  proxies configured, `clientIP` falls back to `RemoteAddr` — but
  `httptest.NewServer` gives every connection the same loopback address, so
  the harness must isolate limiter keys some other way. Options: give each
  test its own limiter-visible IP by registering the test server behind
  `server.SetTrustedProxies` (loopback trusted) and setting
  `X-Forwarded-For` per test, or space tests under the budget. Recommended:
  trusted-proxy + per-test XFF; the rate-limit test then reuses one IP
  deliberately. Reset `SetTrustedProxies(nil)` when done (it is global —
  see `proxy_test.go` doing the same).
- **`storage.Connect` enforces the unprivileged role**: connecting CI as
  the default `postgres` superuser fails by design.
- **Send caps**: One-Time Code deliveries have a 60s per-address cooldown
  (`sendCooldown`). Use a distinct address per test; never re-request a
  code for the same address within a test.
- **Registration under the default `required` verification policy** holds
  the session and 303s to the verification screen — tests that just want a
  signed-in Identity should create their Tenant with
  `"verification": "deferred"`.
- **TOTP for the `mfa_required` test**: enroll through the public API
  (register → login (cookie session) → `POST /self-service/mfa/totp/enroll`
  → generate a code from the returned secret with the existing
  `github.com/pquerna/otp/totp` dep → confirm). Do not insert credentials
  directly: TOTP configs are in `encryptedCredentialKinds` and go through
  the cipher path.
- **Flow messages are written in a second transaction** after the failed
  submission's rollback (`redirectFailure` in
  `internal/server/browserflow.go`) — asserting messages via
  `GET /self-service/flows/{id}` after a failed submit is exactly the
  regression test for that.

## Acceptance matrix

Each row is one test (or table case) driving real HTTP:

1. **Negotiation**: `GET /self-service/login/browser` → 303 to
   `ui.login_url?flow=` for `Accept: text/html`; 200 JSON for
   `application/json` and for `*/*`; `POST .../login/api` (API flow) never
   redirects regardless of Accept.
2. **Form-post journey**: registration by
   `application/x-www-form-urlencoded` (`traits.email=…` nesting) → 303 to
   `default_return_url` + `pratu_session` cookie; then login form post →
   303 + cookie.
3. **Error persistence across rollback**: login form post with wrong
   password → 303 back to the login screen; `GET /self-service/flows/{id}`
   returns `messages: [{type: error, text: invalid credentials}]` and the
   same flow remains submittable (succeeds with the right password).
4. **JSON contract unchanged**: same wrong-password submit with
   `Accept: application/json` → 401 `{"error":…}`, no Location header.
5. **Flow-read gate**: `GET /self-service/flows/{id}` without the creating
   CSRF cookie → 404; with it → 200; an API flow's id → 404 always.
6. **Open redirect**: `?return_to=` with an unrelated origin and with
   `//evil.example.com` → 400; same-origin path and configured-screen
   origin → accepted and honoured on success (Location = return_to).
7. **Fatal codes**: unknown/expired flow id (HTML) → 303
   `error_url?code=flow_expired`; bad csrf_token (HTML form post) → 303
   `?code=csrf_violation`; JSON clients keep 400/403.
8. **Rate limited**: hammer one IP past a per-IP limit (pick the smallest,
   `limitLoginPerID` = 5/min via one identifier) → HTML client 303
   `?code=rate_limited`, JSON client 429 + Retry-After.
9. **Held state, verification**: registration on a `required`-verification
   Tenant → 303 to `verification_url?flow=<verification flow id>`; that
   flow reads back `kind: verification`, `state: code_required`; wrong code
   303s back with `incorrect code`; the code from `courier_messages`
   completes it → 303 + session cookie.
10. **Held state, MFA**: Identity with a confirmed TOTP factor; login form
    post → 303 back to `login_url?flow=<same id>`; flow reads back
    `state: mfa_required`, `ui.methods: [totp]`; `POST
    /self-service/login/totp` with a generated code → 303 to the return
    URL + session cookie.
11. **Recovery chain**: address form post → 303, flow `state:
    code_required` with the anti-enumeration info message (same response
    shape for a nonexistent address); outbox code → `password_required`;
    new password → 303 + session cookie.
12. **Legacy fallback**: Tenant created with only deprecated top-level
    `login_url` → browser flow creation 303s there; `GET /oauth2/auth`
    (valid client) 302s there with `login_challenge=`; a Tenant with a
    `ui` block sends OAuth2 challenges to `ui.login_url` instead.
13. **Reference UI fallback**: Tenant with no `ui` config on a server with
    referenceUI=true → 303 `/ui/?flow=`; with referenceUI=false → 200 JSON.
    (Two `NewPublic` instances over the same pool.)
14. **Admin validation**: `ui` block with a relative URL → 400; the created
    tenant echoes the `ui` block back.

## Suggested stages

1. Harness: env gate, pool, migrate, handler assembly, tenant-factory
   helper (admin API), client helper (jar, no-follow), outbox reader,
   XFF/trusted-proxy IP isolation. One smoke test (matrix row 1).
2. Rows 2–8 (core contract).
3. Rows 9–11 (held states + One-Time Code journeys).
4. Rows 12–14 (fallbacks + admin).
5. `Makefile` `test-integration` target + `ci.yml` postgres service, role
   step, env var. Verify the janitor/ratelimit tests now run in CI too.

## Out of scope

- Social sign-in callback tests (needs a stub OIDC provider — separate task).
- SMS second-factor journeys (courier-wise identical to verification; TOTP
  covers the held-state logic).
- Browser/JS e2e of the reference UI.
- Load/latency testing of the limiter.
