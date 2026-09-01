# Pratu

**Pratu** (ประตู, Thai for "door") is a headless, multi-tenant authentication server and OAuth2/OIDC provider, inspired by the [Ory](https://www.ory.sh) ecosystem and built as a single coherent system where Ory splits across Kratos and Hydra.

> ⚠️ v0.1.0 is feature-complete against its design but has not been independently security-audited. Evaluate accordingly before production use.

## What it does

- **Multi-tenancy as the core primitive**: each tenant is a fully isolated identity namespace — its own end-users, schemas, OAuth2 clients, signing keys, and policy — addressed by its own hostname (`{slug}.{base_domain}`, or claimed custom domains with TLS at your fronting proxy), which makes cookie isolation browser-enforced and gives every tenant its own OIDC issuer. Isolation is defended in depth by Postgres row-level security; the server refuses to run under a role that bypasses RLS.
- **Schema-driven identities**: per-tenant, named, versioned JSON Schemas validate identity traits and annotate which traits are login identifiers and verification/recovery addresses. Old identities keep the schema version that validated them.
- **Self-service flows**, API-token and browser-cookie (CSRF-protected) alike: registration with verify-before-first-session policy, login, recovery (one-time codes, anti-enumeration, revokes other sessions, never bypasses MFA), verification, logout.
- **Credentials & MFA**: Argon2id passwords under a NIST 800-63B policy (length + Pwned-Passwords k-anonymity breach check; deliberately no composition rules), TOTP and SMS one-time codes as second factors with aal1/aal2 sessions.
- **Social sign-in**: per-tenant registry of generic OIDC providers and GitHub; auto-links only via provider-verified email matching a verified address, registers passwordless identities otherwise.
- **OAuth2/OIDC provider** on [ory/fosite](https://github.com/ory/fosite): authorization code + PKCE + refresh grants, per-tenant rotatable RS256 keys and JWKS/discovery, Hydra-style login/consent challenges against the tenant's own UI, per-scope consent with a deny path, refresh rotation with reuse-revocation, introspection and revocation.
- **Sessions** are server-side, listable, and revocable — per device, "log out other devices", and an admin kill-switch.
- **Abuse protection**: Postgres-backed rate limits per IP and per identifier, SMS-pumping caps (per phone, per tenant), uniform anti-enumeration responses.
- **Operations**: message delivery through an outbox-drained Courier (log/webhook drivers), at-rest AES-256-GCM encryption for impersonation-grade secrets with key rotation, expired-row janitors, trusted-proxy support for forwarded headers, single binary, one YAML config with env overrides.
- **Reference login UI** (optional, `public.reference_ui`): an embedded zero-build page at `/ui/` covering every flow — a working login experience before a tenant builds its own, and copyable example code.

The domain vocabulary lives in [CONTEXT.md](CONTEXT.md); load-bearing decisions in [docs/adr](docs/adr). The API is specified in [api/public.openapi.yaml](api/public.openapi.yaml) (tenant-facing self-service + OAuth2) and [api/admin.openapi.yaml](api/admin.openapi.yaml) (management plane).

## Quickstart

Requires Go 1.26+ and Docker.

```sh
cp pratu.example.yaml pratu.yaml
make db-up          # start Postgres (with a non-superuser app role — RLS depends on it)
make migrate        # apply migrations
make run            # public API :4433, admin API :4434
```

Create a tenant and register a user:

```sh
export PRATU_ADMIN_ROOT_KEY=devroot   # set before `make run`
curl -X POST -H "Authorization: Bearer devroot" \
  -d '{"slug":"acme","name":"Acme Inc"}' http://localhost:4434/admin/tenants

flow=$(curl -s -X POST -H "Host: acme.pratu.localhost" \
  http://localhost:4433/self-service/registration/api | jq -r .id)
curl -X POST -H "Host: acme.pratu.localhost" \
  -d '{"method":"password","traits":{"email":"you@example.com"},"password":"correct-horse-battery"}' \
  "http://localhost:4433/self-service/registration?flow=$flow"
```

Tenant hostnames work locally without DNS setup: browsers and curl resolve `*.localhost` to `127.0.0.1`, so tenant `acme` lives at `http://acme.pratu.localhost:4433`. The one-time verification code lands in the server log (the dev Courier driver).

For production set, at minimum: `PRATU_ADMIN_ROOT_KEY`, `PRATU_OAUTH2_SYSTEM_SECRET` (enables the OAuth2 provider), `PRATU_ENCRYPTION_KEYS` (seals secrets at rest), and `public.trusted_proxies` if behind a load balancer.

## Tests

```sh
make test              # unit tests; the database-backed ones skip themselves
make test-integration  # everything, against a real Postgres (it migrates itself)
```

The integration tests drive the real handlers over a real database — flows,
RLS, CSRF cookies, redirects. They run when `PRATU_TEST_DATABASE_URL` points
at a database whose role is unprivileged (no superuser, no `BYPASSRLS`), and
skip when it is unset. Override the URL when port 5432 is taken:

```sh
make test-integration PRATU_TEST_DATABASE_URL=postgres://pratu:pratu@localhost:5433/pratu?sslmode=disable
```

## License

[Apache-2.0](LICENSE)
