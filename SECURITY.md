# Security Policy

Pratu is an authentication server: security reports are the most valuable
contribution this project can receive. Thank you for making one.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's private
vulnerability reporting: [Security → Report a
vulnerability](https://github.com/katipwork/pratu/security/advisories/new)
on this repository. Do not open a public issue for anything you believe
is exploitable.

What to include: the affected endpoint or component, a reproduction
(curl transcripts against a local `make db-up && make run` deployment are
ideal), and your assessment of impact — especially whether tenant
isolation, credential confidentiality, or token integrity is affected.

This is a solo-maintained project. Expectations:

- **Acknowledgment** within 7 days.
- **Assessment and fix plan** within 30 days for anything confirmed.
- **Coordinated disclosure**: please allow up to 90 days before public
  disclosure; fixes ship as a patch release with credit in the advisory
  and changelog unless you prefer otherwise.
- There is **no bug bounty**; credit and gratitude are what's on offer.

## Supported versions

Only the latest release line receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Scope

In scope — the properties Pratu exists to provide:

- **Tenant isolation**: any way one tenant's data, sessions, tokens, or
  configuration is readable or writable from another tenant's context.
- **Authentication bypass**: login, MFA (aal2), verification, or recovery
  reachable without the proofs they demand; MFA or recovery downgrade.
- **Token integrity**: forging or altering access/ID tokens, session
  tokens, one-time codes, authorization codes, or refresh tokens;
  bypassing refresh rotation reuse-revocation or consent restrictions.
- **Secret exposure**: paths that reveal password hashes, TOTP secrets,
  signing keys, client secrets, or session tokens.
- **CSRF or cookie-isolation failures** in browser flows.
- **Anti-abuse bypasses with security impact**: e.g. defeating one-time
  code attempt budgets or per-identifier login limits.
- **Anti-enumeration failures**: responses or timing that reveal whether
  an account exists where the design promises uniformity.

Out of scope:

- Volumetric denial of service and resource-exhaustion reports without a
  protocol-level amplification defect.
- Reports against deployments that ignore the hardening checklist below
  (e.g. no TLS, superuser database role — the server refuses that one
  anyway, unset encryption keys).
- Missing browser-hardening headers on the headless JSON API where they
  have no effect.
- Vulnerabilities purely in third-party dependencies without a Pratu-
  specific exploit path (report upstream; a heads-up is still welcome).
- Social engineering of maintainers or tenants.

## Deployment hardening checklist

The server's guarantees assume:

- TLS in front of both listeners; `public.trusted_proxies` set when
  behind a load balancer (forwarded headers are ignored otherwise).
- The admin listener (`:4434`) unreachable from the public internet.
- `PRATU_ADMIN_ROOT_KEY`, `PRATU_OAUTH2_SYSTEM_SECRET`, and
  `PRATU_ENCRYPTION_KEYS` set to strong values and stored in a secret
  manager.
- A dedicated non-superuser Postgres role (the server refuses
  superuser/BYPASSRLS roles at startup — do not work around it).
- The Courier `log` driver never used outside development: it writes
  live one-time codes to the log.

Design decisions with security consequences are recorded in
[docs/adr](docs/adr); the threat-relevant vocabulary is in
[CONTEXT.md](CONTEXT.md).
