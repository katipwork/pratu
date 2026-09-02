# Task: TypeScript SDK for Next.js (`@pratu/nextjs`)

**Status: designed, not implemented.** The server-behavior survey and the
design below were done 2026-09-02 against v0.4.0; no SDK code exists yet.
The survey facts carry file references so nothing has to be re-derived —
verify a fact only if the referenced code has since changed.

Read [CONTEXT.md](../../CONTEXT.md) first and use its vocabulary verbatim
(Tenant, Identity, Session, One-Time Code, Self-Service Flow, Browser
Flow, Verification, Recovery, …) in code, types, docs, and messages —
`identity`, never `user`.

## Problem

Pratu is headless and currently SDK-less: a Next.js app integrating today
hand-rolls `fetch` calls against the public API and has to discover the
hard parts by reading Go source — that the server sets host-only cookies
and answers no CORS preflight (so a browser on another origin simply
cannot call it), that Browser Flow submissions need a flow-scoped
`csrf_token` while session-authenticated endpoints need a session-scoped
`X-CSRF-Token`, and that server-side Next.js code must forward the
incoming request's cookies and re-emit Pratu's `Set-Cookie` headers onto
its own response. Every consumer would rebuild the same plumbing,
probably wrong. Ship it once, typed, as `@pratu/nextjs`.

## Server facts the design rests on (surveyed at v0.4.0)

1. **Cookies are host-only.** `pratu_session` and `pratu_csrf` are set
   with `Path=/`, `HttpOnly`, `SameSite=Lax`, no `Domain` attribute;
   `Secure` comes from `requestSecure` (direct TLS, or
   `X-Forwarded-Proto: https` from a configured trusted proxy) —
   `internal/server/csrf.go`, `internal/server/proxy.go`.
2. **There is no CORS handling anywhere** (no `Access-Control-*` in
   `internal/`). Browser JavaScript on a different origin cannot talk to
   Pratu directly; same-origin (via a proxy) or server-side calls are the
   only paths.
3. **CSRF is a double-submit HMAC** (`internal/server/csrf.go`): the
   `pratu_csrf` cookie holds a per-browser secret; a token is
   `HMAC(secret, scope)` where scope is the flow ID (Browser Flow
   submissions, `csrf_token` in the body — the flow-creation response
   carries the right token) or the literal `"session"`
   (cookie-authenticated state-changing session endpoints,
   `X-CSRF-Token` header, bootstrapped from the `csrf_token` field of
   `GET /sessions/whoami`). Header-token auth (`X-Session-Token` /
   `Authorization: Bearer`) skips CSRF entirely.
4. **MFA enrolment confirms validate both scopes** — `X-CSRF-Token`
   (session) *and* body `csrf_token` (flow) — `internal/server/mfa.go`,
   `mfa_sms.go`. The SDK must send both in cookie mode.
5. **Browser Flow endpoints are content-negotiated** (ADR 0006). The SDK
   always sends `Accept: application/json` and gets the documented JSON
   contract — no 303s to screens. `api/public.openapi.yaml` (v0.4.0) is
   the authoritative surface, including passwordless One-Time Code login
   (ADR 0007) and the held-login shapes.
6. **No `X-Forwarded-Host`.** The issuer — and the social sign-in
   `redirect_uri` (`socialRedirectURI`, `internal/server/social.go:51`) —
   come from the actual `Host` header. A social round trip therefore
   always sets its Session cookie on the *tenant hostname*: an app-origin
   proxy cannot complete social sign-in (limitation documented below).
7. **Rate limits** (`internal/server/limits.go`, per-IP counters are
   DB-backed and survive restarts): flow creation 30/min/IP, login
   30/min/IP and **5/min/identifier**, registration **20/hour/IP**,
   verification 30/min/IP, resend 10/min/IP, recovery 10/min/IP,
   per-Address send cooldown 1/min. These budgets shape the E2E plan.
8. **Courier has a webhook driver** for capturing One-Time Codes in
   tests: `courier.driver: webhook` + `courier.webhook_url` (env
   `PRATU_COURIER_WEBHOOK_URL`) POSTs each message as JSON
   `{id, tenant_id, channel, recipient, template, payload}` with the
   code at `payload.code`; templates seen: `verification_code`,
   `recovery_code`, `login_code`. The outbox drains every 2 s
   (`cmd/pratu/main.go` `drainCourier`). Far better than grepping the
   log driver's output.
9. **Admin API** (`:4434`, `Authorization: Bearer <root key>`, dev key
   `devroot`): `POST /admin/tenants` accepts `slug`, `name`,
   `verification: required|deferred`, `first_factor: [password|code]`,
   `mfa: off|optional|required`, `password`, `ui{…}`;
   `PATCH /admin/tenants/{slug}` updates policy partially. The default
   Identity Schema seeded at creation is email identifier with
   verification + recovery annotations.
10. **Networking gotchas**: Node resolves `*.pratu.localhost` (→ `::1`)
    through getaddrinfo, and the server listens on all interfaces — but
    undici's `fetch` strips a manually set `Host` header, so clients
    must target the real tenant URL
    (`http://{slug}.pratu.localhost:4433`), never
    `localhost` + `Host:` override the way the curl E2E convention does.

## Settled design

### Package

- Lives at `sdk/nextjs/` in this repo; npm name `@pratu/nextjs`,
  version `0.1.0`, Apache-2.0, `repository.directory` set.
- ESM-only, `"type": "module"`, Node ≥ 20 (needs
  `Headers.getSetCookie`), built with plain `tsc`
  (`module`/`moduleResolution: NodeNext`, `strict`, declarations,
  `.js` import specifiers). No bundler, no runtime dependencies.
- Two entry points:
  - `.` — the isomorphic typed core: `PratuClient` + all types. Usable
    in client components (pointed at the proxy path), route handlers,
    server actions, or any Node/edge runtime.
  - `./server` — Next.js App Router helpers; the only entry that
    touches `next/*`.
- `peerDependencies: { "next": ">=14.2.0 <16" }`; devDeps only
  `typescript`, `vitest`, `next`, `@types/node`.
- Scripts: `build`, `typecheck`, `test:unit`, `test:e2e`, `prepack`.

### Core client (`src/client.ts`, `src/types.ts`, `src/errors.ts`)

Config:

```ts
interface PratuClientConfig {
  baseUrl: string                       // tenant origin, or '' / '/auth' in the browser
  fetch?: typeof fetch
  sessionToken?: string | (() => MaybePromise<string | null | undefined>)
  cookieHeader?: () => MaybePromise<string | undefined>   // server-side cookie mode
  onSetCookie?: (setCookies: string[]) => MaybePromise<void>
}
```

- Every request sends `Accept: application/json`; JSON bodies;
  `Set-Cookie` captured via `getSetCookie()` and handed to
  `onSetCookie` (browsers manage cookies natively; the hooks are for
  server use).
- **Types mirror `api/public.openapi.yaml` field-for-field** (`Flow`,
  `Identity`, `Session`, `Address`, `AuthResult`, `HeldLogin`,
  `VerificationInfo`, `SocialProvider`, flow/message/UI enums…), snake
  case preserved — the wire shape is the contract; do not camelize.
- **`FlowRef`** = `string | { id, csrf_token? } | { flow_id, csrf_token? }`
  so a `Flow`, a `VerificationInfo`, or an enrolment response can be
  passed straight back into a submit; the flow-scoped `csrf_token` is
  auto-filled into the body from the ref.
- **Held logins are not exceptions.** `submitLogin` / `submitLoginCode`
  return `LoginOutcome = (AuthResult & { held?: false }) |
  (HeldLogin & { held: true })`; the `held` discriminator is
  synthesized from HTTP 403 (both shapes can carry
  `state: "verification_required"`, so `state` alone cannot
  discriminate). Document that `held` is SDK-synthesized. All other
  non-2xx → `throw new PratuError(status, message, details,
  retryAfter?)` (`retryAfter` parsed from 429's `Retry-After`).
- **Session-scope CSRF is automatic**: in cookie mode (no
  `sessionToken`), the first state-changing session-authenticated call
  (`logout`, `revokeSession`, `revokeOtherSessions`, the six MFA
  endpoints, `acceptOAuth2Challenge`) bootstraps by calling `whoami()`,
  caches its `csrf_token` on the instance, and sends it as
  `X-CSRF-Token`. Token mode never sends CSRF.
- Method surface (every public endpoint except `/oauth2/token`,
  `/oauth2/introspect`, `/oauth2/revoke` — relying-party concerns for
  standard OAuth2 tooling — and health):
  `createRegistrationBrowserFlow({schema?, returnTo?})` /
  `createRegistrationApiFlow({schema?})` / `submitRegistration(flow,
  {method:'password', traits, password} | {method:'code', traits})`;
  `createLoginBrowserFlow({returnTo?})` / `createLoginApiFlow()` /
  `getFlow(id)` / `submitLogin(flow, {identifier, password})` /
  `sendLoginCode(flow, {identifier})` / `submitLoginCode(flow, {code})` /
  `submitLoginTotp(flow, {code})` / `sendLoginSms(flow)` /
  `submitLoginSms(flow, {code})`;
  `submitVerification(flow, {code})` / `resendVerification(flow)`;
  `createRecoveryBrowserFlow({returnTo?})` / `createRecoveryApiFlow()` /
  `submitRecovery(flow, {address})` / `submitRecoveryCode(flow, {code})`
  / `submitRecoveryTotp(flow, {code})` / `sendRecoverySms(flow)` /
  `submitRecoverySms(flow, {code})` /
  `submitRecoveryPassword(flow, {password})`;
  `enrollTotp()` / `confirmTotp(enrollment, {code})` / `removeTotp()` /
  `enrollSms({phone})` / `confirmSms(enrollment, {code})` /
  `removeSms()`;
  `listSocialProviders()` / `socialSignInUrl(providerId)`;
  `whoami()` / `logout()` / `listSessions()` / `revokeOtherSessions()` /
  `revokeSession(id)`;
  `getOAuth2Challenge(challenge)` /
  `acceptOAuth2Challenge(challenge, {grantScopes?})` /
  `rejectOAuth2Challenge(challenge)`.

### Next.js layer (`src/server/`)

One factory the app instantiates once (`lib/pratu.ts`):

```ts
createPratu({ baseUrl?, basePath?, loginPath?, fetch? }): {
  client(): Promise<PratuClient>
  getSession(): Promise<Whoami | null>
  handlers: { GET, POST, DELETE }
  middleware(req: Request, opts?): Promise<Response | undefined>
}
```

`baseUrl` defaults to `process.env.PRATU_URL` (throw a descriptive
error when absent), `basePath` `'/auth'`, `loginPath` `'/login'`.

- **`client()`** binds a `PratuClient` to the incoming request via
  `next/headers` (dynamic `import('next/headers')` so nothing else in
  the module graph hard-requires Next): seeds an in-memory cookie jar
  from the request's `Cookie` header, `onSetCookie` updates the jar
  *and* re-emits through `cookies().set(...)`. The jar overlay is what
  makes create-flow-then-submit work inside a single server action —
  the `pratu_csrf` set by creation isn't in the incoming header yet.
  Requires a Set-Cookie attribute parser (`maxAge<=0`/expired → delete;
  Next 15's `cookies()` is async — `await` it, which is also
  Next-14-compatible).
  Known constraint to document: flow creation cannot run during Server
  Component render (`cookies().set` throws there by Next's design) —
  create flows in server actions, route handlers, or the browser.
- **`getSession()`**: `client().whoami()`, mapping `PratuError` 401 →
  `null`. Read-only, so safe in Server Components.
- **`handlers`** — a catch-all proxy route
  (`app/auth/[...pratu]/route.ts`,
  `export const { GET, POST, DELETE } = pratu.handlers`) that makes
  Pratu same-origin for the browser, which is what makes host-only
  cookies and no-CORS workable at all (facts 1–2). Mechanics:
  - Path = request pathname minus `basePath`; safelist `/self-service/*`
    and `/sessions*`, else 404 — never an open proxy.
  - Forward method, query, body (buffered `arrayBuffer` is fine — flow
    bodies are small), and only these request headers: `cookie`,
    `accept`, `content-type`, `x-csrf-token`, `user-agent` (Session
    device metadata), `accept-language`, plus pass-through
    `x-forwarded-for` / `x-forwarded-proto` (honored only when the
    operator lists the Next server as a trusted proxy; harmless
    otherwise).
  - `redirect: 'manual'` (Node runtime returns the 3xx itself), rewrite
    a `Location` starting with `baseUrl` to `basePath`, copy status,
    forward every `Set-Cookie` verbatim (correct *because* the cookies
    are host-only with `Path=/` — the browser rescopes them to the app
    origin), and copy only `content-type`, `retry-after`,
    `cache-control` — never `content-length`/`content-encoding`
    (undici already decompressed the body; forwarding the encoding
    header is the classic proxy corruption bug).
- **`middleware(req)`** — route protection for `middleware.ts`, built
  on standard `Request`/`Response`/`URL` only (no `next/server`
  import, edge-safe): no `pratu_session` cookie → 307 to
  `loginPath?return_to=<pathname+search>`; cookie present and
  `verify !== false` → `whoami` with the forwarded `Cookie` header,
  401 → same redirect; otherwise `undefined` (caller falls through to
  `NextResponse.next()`).

### Deployment shapes (README material)

- **A. Same-hostname path routing (production-grade, everything
  works):** the Tenant's custom domain *is* the app's domain; the
  fronting proxy routes `/self-service/*`, `/sessions*`, `/oauth2/*`,
  `/.well-known/*` to Pratu and the rest to Next. Cookies, issuer, and
  social sign-in are all first-party; the SDK proxy is unnecessary
  (browser `baseUrl` is `''`).
- **B. SDK proxy (zero infra, dev-friendly):** Pratu on its tenant
  hostname, app anywhere, `handlers` mounted at `basePath`. Everything
  works **except the social sign-in round trip** (fact 6: the callback
  sets the cookie on the tenant host). State it plainly in the README;
  the server-side fix (honor `X-Forwarded-Host` from trusted proxies,
  or a configurable cookie domain) is a separate server task, not this
  one.

## Non-goals

- No React hooks/context (`useSession`, providers) — client components
  use the core client against the proxy path; hooks can layer on later.
- No Admin API client (root-key material does not belong in an app SDK;
  E2E setup uses raw `fetch`).
- No OAuth2 relying-party helpers (`/oauth2/token` & co.).
- No CJS build, no bundler, no codegen from the OpenAPI spec (the
  hand-written types stay readable and the spec is small; parity is
  asserted by tests, not tooling).
- No server changes — in particular no CORS and no `X-Forwarded-Host`
  (candidate follow-up tasks if shape B's social limitation starts to
  matter).

## Verification plan (acceptance)

Per the house cadence: live-verify end to end before committing.

1. **Unit tests** (vitest, injected `fetch`): flow-creation URL/query
   building and `Accept` header; `held` union from 403 vs `PratuError`
   from 401/429 (`retryAfter`); `csrf_token` auto-fill from `FlowRef`;
   session-CSRF bootstrap (cookie mode calls `whoami` once, caches;
   token mode sends no CSRF); Set-Cookie parser and jar overlay
   precedence; proxy: safelist 404, upstream URL, header
   forward/strip sets, Set-Cookie pass-through, `Location` rewrite;
   middleware: redirect target and `return_to`, verify-mode 401 path.
2. **Live E2E** (vitest, sequential, env-gated): global setup builds
   the server (`make build`), ensures Postgres (`docker compose up -d
   --wait postgres`, skipped when `PRATU_E2E_DATABASE_URL` is set),
   runs `pratu migrate`, then spawns its *own* `pratu serve` on
   `:14433/:14434` with a generated config whose Courier is
   `webhook` → a local sink that appends messages to a JSONL file the
   tests poll (fact 8; codes arrive ≤ ~3 s). Fresh Tenant per run
   (random slug, `first_factor: ["password","code"]`), unique
   addresses, and — because the budgets are DB-backed (fact 7) — at
   most **2 registrations per run** with logins split across the two
   identities to stay under 5/min/identifier:
   - T1 identity A: Browser Flow registration (password) →
     `verification_required` → One-Time Code from sink →
     `submitVerification` issues the Session (cookie in jar) → `whoami`.
   - T2: `logout` (exercises the session-CSRF bootstrap) → `whoami`
     throws 401.
   - T3 A: password login → `held` false, `whoami`.
   - T4 A: passwordless login — `sendLoginCode` → code → 
     `submitLoginCode` → active aal1.
   - T5 identity B: register+verify condensed; `enrollTotp` →
     confirm (tiny RFC-6238 generator in test utils) → aal2; logout;
     password login → `held: true, state: mfa_required` →
     `submitLoginTotp` → aal2.
   - T6 B: Recovery — `submitRecovery` → code → `submitRecoveryCode` →
     `second_factor_required` (Recovery never bypasses MFA) →
     `submitRecoveryTotp` → `set_password` → `submitRecoveryPassword`
     → recovered; old password now 401.
   - T7 A: API flow — `submitLogin` → `session_token`; token-mode
     client `whoami` / `listSessions` / `revokeOtherSessions` /
     `logout`.
3. **Example app** — `examples/nextjs/`: minimal App Router app
   (`lib/pratu.ts`, `middleware.ts` protecting `/dashboard`,
   `app/auth/[...pratu]/route.ts`, `/login` page + `/login/submit`
   route handler doing create-flow-then-submit in one invocation,
   `/dashboard` Server Component via `getSession`, `/logout` route),
   depending on the SDK via `file:../../sdk/nextjs`. Uses route
   handlers rather than server actions so it is curl-verifiable; the
   README shows the server-action variant. Live check against `next
   dev` + a dev Tenant (`verification: deferred` so seeding needs no
   code): unauthenticated `/dashboard` → 307 `/login`; proxied flow
   creation sets `pratu_csrf` on the app origin; form login → 303 →
   `/dashboard` renders the Identity's email; `/logout` → protected
   again.
4. **CI**: add an `sdk` job to `.github/workflows/ci.yml` — setup-node
   (cache on `sdk/nextjs/package-lock.json`), `npm ci`, `build`,
   `test:unit`; then reuse the existing postgres service + app-role
   script and setup-go to run `test:e2e` with
   `PRATU_E2E_DATABASE_URL=postgres://pratu:pratu@localhost:5432/pratu?sslmode=disable`.

## Implementation notes

- Root `.gitignore` needs `node_modules/`, `sdk/nextjs/dist/`, the E2E
  tmp dir, `examples/nextjs/.next/`, `next-env.d.ts`.
- Docs to touch: `sdk/nextjs/README.md` (install, both deployment
  shapes, quickstart for login/registration/logout/MFA, the
  RSC-flow-creation and social-under-proxy caveats), root `README.md`
  (short SDK section), `CHANGELOG.md` under Unreleased. No CONTEXT.md
  change (no new domain terms) and no `api/` change (no new routes), so
  the spec-parity check is untouched.
- E2E budget discipline while iterating: the registration budget is
  20/hour/IP shared with everything else on the machine (fact 7) — run
  the full suite sparingly, iterate with `vitest -t`.
- The curl-convention caveat (fact 10) belongs in the E2E helper
  comments so nobody "simplifies" tenant URLs into
  `localhost` + `Host:`.
