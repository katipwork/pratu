# Changelog

## v0.5.0 — 2026-09-04

- Capability-limited admin keys ([ADR 0009](docs/adr/0009-capability-limited-admin-keys.md),
  [#10](https://github.com/katipwork/pratu/issues/10)): besides the
  unrestricted root key, `admin.keys` configures any number of keys that
  each hold a capability set (`tenants:create`, `clients:*`, …) and
  optionally a set of tenant slug patterns. A provisioner that creates a
  tenant and its OAuth2 client from application code can now hold a
  credential that does those two things, instead of one that can rewrite
  every tenant in the system.
  - Every admin route names its capability where it is registered, so a
    route cannot exist without one and there is no path-matching
    middleware to fall out of step with the route table. A route carrying
    `{slug}` has its tenant scope checked automatically; the two routes
    that name no single tenant are registered through a differently-named
    helper and check it themselves — creating a tenant against the slug in
    its body, listing them by filtering the result.
  - A tenant-restricted key is refused any request naming a tenant it
    cannot check, and its tenant listing shows only its own: the list of
    slugs is the list of customers.
  - Config is validated at startup: an unknown capability, a duplicate key
    name, a secret shared with another key or the root key, or a secret
    under 16 characters stops the process, rather than leaving a key that
    silently grants nothing.
  - `403` (recognised key, missing capability) is now distinct from `401`
    (unrecognised key), and names the capability it wanted. Deployments
    that configure no `admin.keys` are unchanged, and the root key still
    does everything.
  - Each secret can be kept out of the config file as
    `PRATU_ADMIN_KEY_<NAME>`.
- Rate-limited responses always carry `Retry-After` when there is any
  wait, rounded up. A window with less than a second left truncated to
  `0`, which dropped the header entirely and left the client to guess —
  and would have told it to retry immediately had it been sent.
- Per-tenant login throttle ([#11](https://github.com/katipwork/pratu/issues/11)):
  `login_throttle: { max_attempts, window_seconds }` in the tenant config,
  settable at creation and through `PATCH /admin/tenants/{slug}`. The
  per-identifier login limit was a fixed 5/minute, which is right for
  production and hostile to an e2e suite: a handful of well-known
  identities signing in at the start of many specs tripped it, and the runs
  failed on the throttle rather than on anything they asserted. A test
  tenant can now be given room while production tenants keep the default,
  which is unchanged for every tenant that configures nothing.
  - Deliberately a knob that can weaken brute-force protection: it reaches
    one tenant at a time and only an operator holding the admin key can
    turn it. The per-IP login limit is platform-wide — attackers spread
    across tenants — and is not configurable per tenant, so relaxing a
    tenant cannot escape it.
  - `window_seconds` is capped at an hour. A throttle is a short-term
    control; a longer window is account lockout, and in practice comes from
    mistyping seconds as milliseconds.
- Tenants can be removed ([ADR 0008](docs/adr/0008-tenant-disable-not-delete.md),
  [#8](https://github.com/katipwork/pratu/issues/8)): `DELETE
  /admin/tenants/{slug}` disables one and `POST /admin/tenants/{slug}/enable`
  brings it back. Until now a tenant could be created but never removed, so
  a provisioning saga that compensated left an orphan behind forever and dev
  instances accreted dead tenants.
  - Disabling is a soft delete. The tenant resolves from no hostname — by
    slug or by custom domain — so its Self-Service Flows, OAuth2 endpoints,
    JWKS and discovery all stop answering at once, while nothing it owns is
    destroyed. Sessions are not revoked, only made unreachable, so enabling
    restores the tenant whole instead of signing everyone out.
  - The slug stays held. Freeing it would let `{slug}.{base_domain}` come to
    mean a different identity namespace, so re-use has to be deliberate:
    creating a tenant on a held slug still gets 409, now with a message
    saying a disabled tenant holds it.
  - `DELETE /admin/tenants/{slug}?purge=true` is the irreversible one:
    it destroys the tenant and everything it owns and frees the slug for
    re-use. Refused with 409 unless the tenant is already disabled, so
    destruction is a deliberate second step and a wrong slug in a script
    costs a disable rather than a customer's identities. A `purge` value
    that is not a boolean is a 400, never read as the safer verb.
    Tenant-owned tables are swept by their `ON DELETE CASCADE` foreign
    keys; the platform-level `rate_limits` counters, which have none, are
    deleted explicitly so a purged tenant leaves no identifiers behind.
  - The admin API stays open on a disabled tenant — listable, readable,
    patchable, sub-resources and all — because an operator who cannot see
    what they closed cannot undo it. Public resolution cannot reach one at
    all: the filter lives in the store behind `tenant.Store`, not in the
    handlers.
  - Disabling is idempotent, `disabled_at` keeping the moment it first went
    off, so a compensating saga can run twice. An absent slug is a 404.
  - Not a revocation primitive: an already-issued access token stays valid
    until it expires (15 minutes), though its JWKS endpoint is gone.
- `PATCH /admin/tenants/{slug}/clients/{id}`
  ([#7](https://github.com/katipwork/pratu/issues/7)) edits a client's
  `name`, `scopes` and `redirect_uris`, which previously could only be set
  at creation. Absent keys are left alone and a present key replaces its
  value outright, the same semantics `PATCH /admin/tenants/{slug}` has.
  Retrofitting a custom scope, or adding a redirect_uri when a tenant
  gains a custom domain, is a metadata edit again instead of a
  DELETE + re-create that churned the `client_id` and secret every
  consumer holds. `client_id`, the secret and `first_party` are not
  editable, and saying otherwise in the body is a 400 rather than a
  silent no-op.
- `POST /admin/tenants/{slug}/clients/{id}/rotate-secret`
  ([#9](https://github.com/katipwork/pratu/issues/9)) mints a fresh secret
  for a confidential OAuth2 client and returns it once, leaving the
  `client_id` untouched. Previously a secret was returned only at
  creation, so losing or leaking one left `DELETE` + re-create as the
  only recovery — churning the `client_id` that every consumer is
  configured with, for what is really a credential swap. The previous
  secret stops authenticating immediately; public clients have no secret
  and are refused with 409.

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
