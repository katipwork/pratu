# Changelog

## Unreleased

- Dependency upgrades clearing the open Dependabot alerts, none reachable
  from this code (`govulncheck` reports nothing before or after):
  `google.golang.org/grpc` 1.82.1 → 1.83.1 (CVE-2026-84304, an HTTP/2
  server-side OOM — this binary runs no gRPC server),
  `github.com/gorilla/websocket` 1.5.0 → 1.5.3 (GHSA-w67g-5rqw-f597, weak
  PRNG for mask keys — no WebSocket endpoints here), and the OTLP trace
  exporter stack 1.21.0 → 1.43.0 (CVE-2026-39882, unbounded response-body
  reads from the operator-configured collector). All three are indirect
  dependencies pulled in through fosite; upgraded to keep the tree clean.

## v0.4.0 — 2026-09-02

- Passwordless first factor ([ADR 0007](docs/adr/0007-passwordless-first-factor.md),
  [#5](https://github.com/katipwork/pratu/issues/5)): a tenant may accept a
  One-Time Code to a verification-annotated Address as a first factor, so a
  phone-first product can register and sign people in with no password
  credential at all. Opt in per tenant with
  `first_factor: ["password"] | ["code"] | ["password","code"]`; the default
  stays `["password"]`, so existing tenants are untouched.
  - New `POST /self-service/login/code/send` (identifier in, uniform
    `code_sent` out — identically for identifiers that do not exist, and
    when the delivery caps refuse the send, so it is no enumeration oracle)
    and `POST /self-service/login/code` (code in, the same AuthResult a
    password login returns).
  - `POST /self-service/registration` accepts `method: "code"`, writing no
    password credential. The session is always withheld until the Address
    is proven, even under `verification: deferred`.
  - Proving a login code marks the Address verified; a code-only login is
    `aal1`, so an enrolled second factor is still owed on top of it.
  - `ui.fields` omits `password` for tenants that do not accept one, and
    `ui.methods` advertises a flow's accepted first factors.
- `PATCH /admin/tenants/{slug}` edits a tenant's name and policy, which
  previously could only be set at creation. Absent keys are left alone,
  so one policy can be flipped without resending the rest; a present key
  replaces its value outright, nested `password` and `ui` blocks
  included. The patched policy is validated whole and written under a row
  lock, so a rejected patch changes nothing and concurrent edits queue
  rather than overwrite. The slug stays immutable.

## v0.3.1 — 2026-09-02

Security patch. No API change.

- `go-jose/v3` 3.0.3 → 3.0.5, closing a parsing denial of service
  (CVE-2025-27144) and a JWE decryption panic (CVE-2026-34986). This is
  the one that mattered: `GET /oauth2/auth` reaches `jose.ParseSigned`
  through fosite, so the vulnerable code sat behind an unauthenticated
  endpoint.
- `golang.org/x/crypto` 0.41.0 → 0.55.0, `golang.org/x/text` 0.29.0 →
  0.41.0, and the transitive `grpc`, `otel`, `x/net`, and `protobuf`
  modules fosite pulls in. The loud `x/crypto` advisories are all in its
  `ssh`, `ssh/agent`, `ssh/knownhosts`, and `openpgp` packages, none of
  which this binary links — upgraded to keep the tree clean, not because
  they were reachable.
- The `go` directive moves to 1.26.7, the toolchain the release image
  already builds with (`golang:1.26-alpine`). CI resolves its Go version
  from `go.mod`, so it had been testing on 1.26.1 — an older standard
  library than the one shipping, with known reachable issues in
  `crypto/tls`, `crypto/x509`, `net/http`, and `html/template`.

`govulncheck ./...` now reports no vulnerabilities reachable from this
code. Published images built before this release were already free of the
standard-library issues; the `go-jose` one affected them.

## v0.3.0 — 2026-09-02

- Redirect-driven Browser Flows (ADR 0006): a Browser Flow client that
  prefers `text/html` — or posts an HTML form — is now driven by 303
  redirects to the tenant's own screens instead of being shown raw JSON.
  Flow creation lands on the screen with `?flow=`, a failed submission
  returns there with its messages persisted on the flow, failures with no
  flow to return to land on the error screen with `?code=`, and completed
  flows land on `return_to` or the tenant's default return URL. Clients
  that ask for `application/json` keep the previous contract, and API
  flows are untouched.
- Browser Flow submissions accept `application/x-www-form-urlencoded`, so
  a plain HTML form can drive a flow end to end (`traits.email=…` nests
  into the traits object).
- `GET /self-service/flows/{id}`: a screen re-reads the flow it landed
  on — the step it waits on (`state`), the fields to render, available
  second-factor methods, and the last submission's messages. Readable
  only by the browser that created the flow.
- Per-tenant `ui` config block: `login_url`, `registration_url`,
  `recovery_url`, `verification_url`, `error_url`, `default_return_url`,
  `allowed_return_urls`. It supersedes the top-level `login_url` (OAuth2
  challenges now use `ui.login_url`) and `social_return_url`, both still
  read as fallbacks. `return_to` is validated against the origins of the
  configured screens plus the allow-list, so it cannot become an open
  redirect.
- Tenants that configure no screens fall back to the embedded reference
  UI when the server serves it; the reference UI renders `?flow=` and
  `?code=` landings.
- Integration tests for the Browser Flow contract: the real handlers over
  a real Postgres (negotiation, form-post journeys, error persistence
  across rollback, flow-read binding, open redirects, fatal codes, rate
  limiting, verification/MFA/recovery journeys, legacy config, reference
  UI fallback). `make test-integration` runs them; CI now provisions
  Postgres, so the previously-skipped janitor and rate-limit tests run
  there too.
- `storage.Migrate` takes an advisory lock, so replicas (or test suites)
  starting together no longer race to apply the same migration.
- The compose database publishes on 35432, clear of a Postgres a
  developer machine may already run on 5432.

**Upgrading**: apply migration `0014_flow_ui_state.sql` (`pratu migrate`).
Browser-flow clients that send `Accept: text/html` now receive redirects
where they used to receive JSON; clients that ask for
`application/json` — or send the `*/*` that `fetch` defaults to — are
unaffected, as are API flows. A tenant with no `ui` block keeps the old
responses unless the server serves the reference UI, in which case its
HTML clients land there. `login_url` and `social_return_url` still work;
`ui.login_url` and `ui.default_return_url` supersede them.


## v0.2.0 — 2026-08-26

- Custom domains: tenants claim hostnames outside the base domain
  (admin CRUD; globally unique, base-domain shadowing refused). The
  resolver falls back from subdomain to the domain table; issuer, JWKS,
  cookies, and flows follow the Host automatically. TLS for custom
  domains is the fronting proxy's job (see ADR 0003).
- Reference login UI: an optional embedded page (`public.reference_ui`)
  at `/ui/` driving every browser flow — login, schema-rendered
  registration, verification, TOTP/SMS, recovery, social buttons, and
  the OAuth2 login/consent handshake. Off by default; the server stays
  headless.
- `GET /self-service/social`: public listing of a tenant's social
  providers (ids/labels) for rendering sign-in buttons.
- OpenAPI 3.0 specs for both APIs (`api/*.openapi.yaml`), validated and
  mechanically cross-checked against the registered routes.
- SECURITY.md with private vulnerability reporting (enabled on GitHub),
  scope, and a deployment hardening checklist.
- Startup log line when the reference UI is enabled.

## v0.1.0 — 2026-08-26

First release. Everything below is new.

- Multi-tenant core: hostname-addressed tenants, shared tables with forced
  Postgres RLS (server refuses superuser/BYPASSRLS roles), per-tenant
  policy config.
- Named, versioned per-tenant Identity Schemas (JSON Schema with `pratu`
  annotations for identifiers and addresses), admin-managed.
- Self-service flows (API and browser+CSRF variants): registration with
  verify-before-first-session policy, login, verification with resend,
  three-step code-proven recovery (anti-enumeration, revokes other
  sessions, never bypasses MFA), logout.
- Passwords: Argon2id, NIST-style policy, HIBP k-anonymity breach check
  (per-tenant toggle, fail-open).
- Second factors: TOTP and SMS one-time codes; aal1/aal2 sessions;
  per-tenant off/optional/required policy; enrolment gated on proving the
  factor; removal requires aal2.
- Social sign-in (per-tenant registry): generic OIDC + GitHub;
  verified-email-only auto-linking; passwordless registration from claims;
  MFA handover after social first factor.
- OAuth2/OIDC provider on ory/fosite: auth-code + PKCE + refresh, OIDC
  discovery and per-tenant rotatable RS256 JWKS, Hydra-style
  login/consent challenges, per-scope consent with a reject path, JWT
  access tokens (15 min), rotating refresh tokens with reuse-revocation,
  introspection, revocation; admin-managed clients (public clients are
  PKCE-only).
- Sessions: server-side, device metadata, list/targeted-revoke/log-out-
  other-devices, admin kill-switch.
- Abuse protection: Postgres fixed-window rate limits (per IP and per
  identifier), SMS send caps per address and per tenant, uniform
  anti-enumeration responses.
- Courier: transactional outbox for email/SMS with retry/backoff; log and
  webhook drivers.
- At-rest AES-256-GCM encryption for TOTP secrets, factor phone numbers,
  signing keys, and social client secrets, with key-list rotation and a
  startup upgrade sweep.
- Signing-key lifecycle: rotate/list/delete via admin API; retired keys
  stay in the JWKS.
- Janitors for expired flows/sessions/codes/OAuth2 rows/courier messages
  under RLS-safe policies.
- Trusted-proxy support: X-Forwarded-For/-Proto honored only from
  configured CIDR ranges.
