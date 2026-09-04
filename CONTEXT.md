# Pratu

Pratu (ประตู, Thai for "door") is a headless, multi-tenant authentication server (identity + OAuth2/OIDC provider), API-first in the style of the Ory ecosystem. Built from scratch in Go for the author's own products, published as open source.

## Language

**Tenant**:
A customer organisation, owning a fully isolated identity namespace: its identities, Identity Schemas, OAuth2 clients, and configuration belong to exactly one tenant. The same person at two tenants is two unrelated identities. Removing a tenant means **disabling** it: it then resolves from no hostname and its whole public surface closes, while everything it owns — and its slug — survives until an operator enables it again. Destroying a disabled tenant and freeing its slug is a second, explicit act: **purging** it (ADR 0008).
_Avoid_: Organization, project, workspace, realm; _deleted_ for a disabled tenant (nothing is destroyed), suspended, archived

**Identity**:
A person (or service account) known to exactly one tenant. Holds traits, credentials, and addresses.
_Avoid_: User, account, principal

**Traits**:
The identity's own data (email, phone, name, …), validated by the tenant's Identity Schema. Traits are the identity's public shape; credentials are never traits.
_Avoid_: Attributes, profile, metadata

**Identity Schema**:
A JSON Schema, defined per tenant, that validates traits and annotates which traits serve as login identifiers and verification/recovery addresses. Schemas are named and versioned: updating one appends an immutable new version, and each identity keeps the version that validated it.
_Avoid_: User model, custom fields

**Session**:
Server-side proof that an identity authenticated, referenced by an HTTP-only cookie (browsers) or an opaque bearer session token (native apps). Listable and revocable; never a JWT.
_Avoid_: Login token, auth token

**One-Time Code**:
A short-lived numeric code delivered to an address (email or phone) to prove control of it — used for recovery, verification, SMS second-factor login, and (for tenants that opt in) passwordless first-factor login. Never a clickable magic link.
_Avoid_: Magic link, OTP link

**Second Factor**:
An additional proof (TOTP or SMS One-Time Code) required to raise a session from aal1 to aal2. First factors are passwords and, where a tenant opts in via `first_factor`, One-Time Codes to an address (ADR 0007); a code-only login is still aal1.
_Avoid_: 2FA method, MFA device

**Login/Consent Challenge**:
The Hydra-style handshake for OAuth2 flows: the authorization endpoint redirects the browser to the tenant's own UI with a challenge ID; the UI drives a Self-Service Flow, then redeems the challenge to continue the OAuth2 flow. Consent is skippable per first-party OAuth2 client.

**Address**:
An email or phone number belonging to an identity, declared by Identity Schema annotations as usable for verification, recovery, and/or SMS second factor.
_Avoid_: Contact, channel

**Verification**:
Proving control of an Address with a One-Time Code. Per-tenant policy decides whether it must happen before the first session (the default) or may be deferred.
_Avoid_: Activation, confirmation

**Recovery**:
Regaining access to an identity by proving control of a recovery-annotated Address with a One-Time Code, then setting a new password. Success revokes every other session and marks the address verified.
_Avoid_: Password reset, forgot password

**Social Provider**:
A per-tenant registry entry for an external sign-in source: a generic OIDC provider or GitHub. A social account maps to at most one identity via its provider-subject identifier; it auto-links to an existing identity only through a provider-verified email matching a verified Address.
_Avoid_: IdP, connection, federation

**Courier**:
The component that delivers One-Time Codes and notifications over email and SMS, using platform-level provider credentials and per-tenant templates, draining a persistent outbox.
_Avoid_: Mailer, notifier, sender

**Self-Service Flow**:
A stateful, server-driven interaction (login, registration, recovery, …) exposed as JSON describing its UI nodes and errors; clients render it however they like. The server is headless — it ships no UI. A flow is either an API flow (bearer tokens, no cookies) or a Browser Flow.
_Avoid_: Form, wizard, journey

**Browser Flow**:
A Self-Service Flow whose client authenticates with the host-scoped session cookie instead of bearer tokens; it carries CSRF protection, and completing it sets the cookie rather than returning a session token. Clients that ask for HTML are driven by redirects to the tenant's configured UI screens — errors return the browser to the flow's screen, never as raw JSON; clients that ask for JSON get the flow as JSON.
_Avoid_: Web flow, cookie mode
