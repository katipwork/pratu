# Pratu

Pratu (ประตู, Thai for "door") is a headless, multi-tenant authentication server (identity + OAuth2/OIDC provider), API-first in the style of the Ory ecosystem. Built from scratch in Go for the author's own products, published as open source.

## Language

**Tenant**:
A customer organisation, owning a fully isolated identity namespace: its identities, Identity Schemas, OAuth2 clients, and configuration belong to exactly one tenant. The same person at two tenants is two unrelated identities.
_Avoid_: Organization, project, workspace, realm

**Identity**:
A person (or service account) known to exactly one tenant. Holds traits, credentials, and addresses.
_Avoid_: User, account, principal

**Traits**:
The identity's own data (email, phone, name, …), validated by the tenant's Identity Schema. Traits are the identity's public shape; credentials are never traits.
_Avoid_: Attributes, profile, metadata

**Identity Schema**:
A JSON Schema, defined per tenant, that validates traits and annotates which traits serve as login identifiers and verification/recovery addresses.
_Avoid_: User model, custom fields

**Session**:
Server-side proof that an identity authenticated, referenced by an HTTP-only cookie (browsers) or an opaque bearer session token (native apps). Listable and revocable; never a JWT.
_Avoid_: Login token, auth token

**One-Time Code**:
A short-lived numeric code delivered to an address (email or phone) to prove control of it — used for recovery, verification, and SMS second-factor login. Never a clickable magic link.
_Avoid_: Magic link, OTP link

**Second Factor**:
An additional proof (TOTP or SMS One-Time Code) required to raise a session from aal1 to aal2. Passwords are the only first factor in v1.
_Avoid_: 2FA method, MFA device

**Login/Consent Challenge**:
The Hydra-style handshake for OAuth2 flows: the authorization endpoint redirects the browser to the tenant's own UI with a challenge ID; the UI drives a Self-Service Flow, then redeems the challenge to continue the OAuth2 flow. Consent is skippable per first-party OAuth2 client.

**Address**:
An email or phone number belonging to an identity, declared by Identity Schema annotations as usable for verification, recovery, and/or SMS second factor.
_Avoid_: Contact, channel

**Verification**:
Proving control of an Address with a One-Time Code. Per-tenant policy decides whether it must happen before the first session (the default) or may be deferred.
_Avoid_: Activation, confirmation

**Courier**:
The component that delivers One-Time Codes and notifications over email and SMS, using platform-level provider credentials and per-tenant templates, draining a persistent outbox.
_Avoid_: Mailer, notifier, sender

**Self-Service Flow**:
A stateful, server-driven interaction (login, registration, recovery, …) exposed as JSON describing its UI nodes and errors; clients render it however they like. The server is headless — it ships no UI.
_Avoid_: Form, wizard, journey
