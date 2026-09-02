# Task: Passwordless first factor — sign in with a One-Time Code

**Status: implemented** — `internal/server/login_code.go`,
`internal/server/login_code_integration_test.go`, and the `first_factor`
tenant config; recorded as
[ADR 0007](../adr/0007-passwordless-first-factor.md). Analysis of
[GitHub issue #5](https://github.com/katipwork/pratu/issues/5).

Two things found while building it, both now part of the design:

- **The One-Time Code slot on a login flow is shared.** A flow held at
  `mfa_required` already carries a second-factor code; accepting it at
  the first-factor endpoint would skip the factor it was sent for.
  `POST /self-service/login/code` therefore refuses a flow whose first
  factor is already proven (`login_code.go`, and the regression test
  `TestSecondFactorCodeCannotOpenASession`).
- **A passwordless registration needs its identifier to *be* an
  Address.** Traits with a verification address that no identifier
  matches would create an Identity nothing can ever sign into, so
  `method:"code"` rejects them.
- **Tenant policy had no way to change.** `first_factor` was settable
  only at tenant creation, which makes the feature unreachable for every
  tenant that already exists. Added `PATCH /admin/tenants/{slug}`
  (partial: absent keys untouched, patched policy validated whole, row
  locked) with `storage.TenantStore.Update`.

Read
[CONTEXT.md](../../CONTEXT.md) first and use its vocabulary verbatim
(Tenant, Identity, Address, One-Time Code, Verification, Recovery,
Self-Service Flow, Browser Flow, Courier, …).

## Problem

An Identity that registered with a phone-only Identity Schema has a
proven Address, a proven delivery path (Courier), and a working login
identifier — but cannot sign in without a password, because both submit
handlers hard-reject every method except `"password"`:

```
internal/server/selfservice.go:166 (registration), :321 (login)
if body.Method != "password" { … "unsupported method; use \"password\"" }
```

`ui.fields` on a phone-only registration flow also still emits a
required `password` field, so a tenant UI cannot render the form it
wants. The nearest workaround — a hidden password plus Recovery-driven
sign-in — revokes every other Session on each login and abuses Recovery.

Consumer products in Thailand/SE Asia identify people by mobile number;
for them the password is the credential nobody wants. Everything up to
the credential already works in v0.3.1 (phone-only Identity Schema,
SMS Verification, phone as login identifier).

## Settled design (do not relitigate; recorded as ADR 0007)

1. **Per-tenant opt-in: `first_factor`.** New field on `tenant.Config`
   (`internal/tenant/tenant.go`):
   `first_factor: ["password"] | ["code"] | ["password","code"]`, with
   `EffectiveFirstFactor()` defaulting to `["password"]` — existing
   tenants are untouched. Admin tenant create/update
   (`internal/server/admin.go`) validates the values. CONTEXT.md's
   *"Passwords are the only first factor in v1"* (under Second Factor)
   is updated accordingly.

2. **Login endpoints mirror the SMS Second Factor pair**
   (`internal/server/mfa_sms.go` is the template):

   ```
   POST /self-service/login/code/send?flow={id}   {identifier, csrf_token}
        → {"state":"code_sent","message":"if the identifier exists, a code was sent"}
   POST /self-service/login/code?flow={id}        {code, csrf_token}
        → AuthResult, byte-for-byte the shape of a password login
   ```

   Both are Browser-Flow-aware: content negotiation, `failSubmission` /
   `failFatal` / `advanceFlow` / `redirectToScreen`, form posts, CSRF —
   exactly as the existing submit handlers (ADR 0006). `send` doubles
   as resend. Rejected with the usual unsupported-method message when
   `"code"` is not in the tenant's `first_factor`.

3. **Anti-enumeration mirrors Recovery exactly**
   (`internal/server/recovery.go` `submitRecoveryAddress`): unknown
   identifier → same `code_sent` response, nothing sent, nothing stored;
   a send-cap refusal is suppressed (logged, uniform response), never a
   429; the flow advances to `StateCodeRequired` either way. A later
   wrong-code submit answers "incorrect code" uniformly (no code on the
   flow ≡ wrong code, as `checkFactorCode` already does).

4. **Which Address gets the code.** The submitted identifier must
   itself resolve (after `identity.Normalize`) to a
   verification-annotated Address of the Identity it identifies; the
   code goes to that Address on its own channel. Mechanically the
   channel is not restricted — the Courier delivers One-Time Codes on
   both — but the motivating scope is `sms`; email codes are the same
   mechanism and remain codes, never links. New Courier template
   `login_code`.

5. **AAL is explicit: a code-only login is `aal1`.** One factor is one
   factor. The tenant MFA policy applies unchanged on top: an enrolled
   Second Factor still holds the flow at `StateMFARequired`, and
   `mfa: required` still demands aal2. The degenerate case — SMS
   Second Factor enrolled on the same phone that just received the
   first-factor code — is accepted and documented in the ADR, not
   special-cased in v1.

6. **Verification is subsumed on success.** Proving the login code
   proves the Address: mark it verified (as Recovery already does) and
   never bounce a code-login into a separate Verification step. On
   registration via `method:"code"` the existing
   registration→verification hold *is* the code proof — and it is
   always required for that method, even under `verification:
   deferred`, because a passwordless Identity with an unproven Address
   has no credential at all.

7. **Registration accepts `method:"code"`** when the tenant's
   `first_factor` includes `"code"`: no password field, traits must
   contain a verification-annotated Address that is also a login
   identifier, Identity is created with no password credential (an
   existing state — social sign-in already registers passwordless
   identities). `ui.fields` for such a flow omits `password`
   (required only when password ∈ `first_factor`); the flow advertises
   its first-factor methods through the existing `ui.methods`.

8. **Recovery is left unchanged; code login subsumes it.** For a
   passwordless Identity, "recover" *is* "log in with a code". Recovery
   on such an Identity would set a first password — harmless dead
   weight on a `["code"]`-only tenant, whose UI simply doesn't offer
   Recovery. No server change; the ADR states it.

9. **Send caps stay as they are** (`internal/server/limits.go`:
   per-Address cooldown 1/minute, daily caps, tenant SMS ceiling).
   Rationale, stated in the ADR: a mistyped code burns one of
   `otp.MaxAttempts` attempts, not a send — the cooldown only gates
   *re-sending*, so it does not lock a fumbling person out of sign-in.
   A separate budget is a follow-up if real friction shows up. The
   existing `login:ip` and `login:id` limiters apply to both new
   endpoints.

## Non-goals

- No magic links, ever (CONTEXT.md).
- No change to Recovery, Verification, or Second Factor semantics.
- No per-flow "choose your method" negotiation UI beyond `ui.methods`.
- No separate send budget for the login path in v1 (see 9).

## Implementation notes

As built: `completeFirstFactor` / `respondLogin` in
`internal/server/selfservice.go` are the single completion path both
first factors resolve through; `storage.FindLoginCodeAddress` resolves
an identifier to the Address that *is* that identifier; `createTenant`
and the new `PATCH` share `validateTenantConfig`, so the two cannot
accept different policies.

The harness now clears the endpoint budgets for a client IP when it hands
one out (`clearIPBudget`, alongside the existing `clearSendCooldown`):
per-IP rate-limit counters live in the database and outlive a process,
while the test addresses restart from the same sequence every run, so
back-to-back runs inside a limit window were inheriting each other's
spending and flaking `TestRateLimitedRedirect` (~1 run in 12).

- `internal/flow/flow.go`: extend `LoginContext` (e.g. code-path
  identity + address IDs); reuse `StateCodeRequired`. Codes ride the
  existing flow-scoped storage (`storage.ReplaceCode` /
  `CodeForFlow` / `checkFactorCode`).
- `internal/server/selfservice.go`: gate `method` checks on
  `EffectiveFirstFactor()`; fix `ui.fields`/`ui.methods` for both
  login and registration flow creation and `GET /self-service/flows/{id}`.
- New handlers belong next to their siblings (a
  `login_code.go` mirroring `mfa_sms.go` reads well); routes in
  `internal/server/public.go`.
- Success path of `POST /self-service/login/code` must reuse the same
  completion code as password login: MFA hold, session/cookie vs
  `session_token`, `return_to` redirect — do not fork a second copy.
- Update: `api/` spec, reference UI (`internal/server/ui`) if it can
  cheaply render the code method, `pratu.example.yaml`, README, and
  CHANGELOG. Done already: ADR 0007 and the CONTEXT.md first-factor
  sentences.

## Acceptance

Unit tests plus integration tests in the existing harness
(`internal/server/integration_test.go`, env-gated on
`PRATU_TEST_DATABASE_URL`, One-Time Codes read from the
`courier_messages` outbox):

1. Default tenant (no `first_factor`): behavior byte-for-byte today's —
   code endpoints answer unsupported-method, password login untouched.
2. `["code"]` tenant, phone-only Identity Schema: register with
   `method:"code"` → `verification_required` hold → prove code →
   active Session, Address verified, Identity has no password
   credential; `ui.fields` never contains `password`.
3. Same tenant: full login journey — create flow, `code/send`,
   code from outbox, `code` submit → AuthResult identical in shape to
   a password login (API flow: `session_token`; Browser Flow: cookie +
   303 to `return_to`).
4. Anti-enumeration: `code/send` with an unknown identifier returns the
   identical response and enqueues nothing; under send-cap refusal the
   response is still uniform (nothing enqueued, no 429).
5. Wrong code burns attempts (`otp.MaxAttempts` → "too many attempts")
   without triggering the send cooldown; resend within the cooldown is
   refused on the send path only.
6. `["password","code"]` tenant: both methods work; `ui.methods`
   advertises both.
7. MFA interplay: Identity with TOTP enrolled on an `mfa: optional`
   tenant → code login lands at `StateMFARequired`, completes to aal2;
   code-only login without a Second Factor is aal1.
8. `method:"code"` registration under `verification: deferred` still
   holds the Session until the Address is proven.
9. CSRF and flow-expiry failures on both endpoints behave per ADR 0006
   (Browser Flow: redirect to screen/error URL; API flow: JSON).
