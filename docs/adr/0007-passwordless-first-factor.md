# Passwordless first factor: One-Time Code login, per-tenant opt-in

A Tenant may allow an Identity to authenticate by proving control of a verification-annotated Address with a One-Time Code, with no password credential involved. The knob is `first_factor` in the tenant config — `["password"]`, `["code"]`, or `["password","code"]` — defaulting to `["password"]`, so every existing Tenant is untouched. The Login Flow gains a send/submit endpoint pair (`POST /self-service/login/code/send`, `POST /self-service/login/code`) mirroring the SMS Second Factor pair, and Registration accepts `method:"code"`, creating an Identity with no password credential — an existing state, since social sign-in already registers passwordless identities. This exists because phone-first consumer products (Thailand and much of SE Asia) identify people by mobile number; for them the password is the one credential nobody wants, while the phone is already proven at registration.

Decisions that were open questions, settled here:

- **Anti-enumeration mirrors Recovery exactly.** The send endpoint answers a uniform `code_sent` whether or not the identifier exists; a send-cap refusal is suppressed into the same uniform response, never a 429. Anything else is an oracle for "is this number registered".
- **A code-only login is `aal1`.** One factor is one factor, whatever its relative strength. The tenant MFA policy applies unchanged on top; the degenerate case of an SMS Second Factor enrolled on the same phone that received the first-factor code is accepted, not special-cased.
- **Proving the login code proves the Address.** The Address is marked verified and a code login never bounces into a separate Verification step. Registration via `method:"code"` always holds the Session until the Address is proven, even under `verification: deferred` — a passwordless Identity with an unproven Address has no credential at all.
- **Recovery is unchanged; code login subsumes it.** For a passwordless Identity, "recover" *is* "log in with a code". Recovery on such an Identity would set a first password — harmless dead weight on a `["code"]`-only Tenant, whose UI simply doesn't offer Recovery.
- **Send caps stay as they are.** A mistyped code burns one of the limited code attempts, not a send; the per-Address cooldown gates only *re-sending*, so it cannot lock a fumbling person out of sign-in. A separate budget for the login path is a follow-up if real friction appears.
- **The mechanism is channel-agnostic, the scope is phone.** The code goes to the Address the submitted identifier resolves to, on that Address's own channel; the Courier already delivers on both. Email codes are the same mechanism and remain numeric One-Time Codes — never magic links.

## Consequences

- CONTEXT.md no longer says passwords are the only first factor; the Second Factor entry now names both.
- A Login Flow advertises its accepted first-factor methods through the existing `ui.methods`, and `ui.fields` on a Registration Flow requires `password` only when `"password"` is in the tenant's `first_factor`.
- The existing `login:ip` and `login:id` rate limits apply to both new endpoints; codes ride the existing flow-scoped code storage and attempt budget.
- The AuthResult of a code login is byte-for-byte the shape of a password login, including the `mfa_required` held state, session cookie vs `session_token`, and `return_to` handling (ADR 0006).
