# Task: Redirect-driven Browser Flows (Ory Kratos model)

**Status: implemented.** Kept as the record of what was decided and built;
see [ADR 0006](../adr/0006-content-negotiated-browser-flows.md) and the
CHANGELOG entry. Read [CONTEXT.md](../../CONTEXT.md) first and use its
vocabulary verbatim (Tenant, Identity, Self-Service Flow, Browser Flow,
One-Time Code, …).

## Problem

Every Self-Service endpoint answers JSON unconditionally, even on Browser
Flows. Navigating a browser to `GET /self-service/login/browser` paints a flow
object on the user's screen; a failed form submit paints an error object.
The server also cannot accept a plain HTML form post (`readJSON` only).

## Settled design (do not relitigate)

1. **Ory Kratos model, content-negotiated.** On Browser Flow endpoints:
   requests that prefer `text/html` get 303 redirects; requests that prefer
   `application/json` keep today's JSON responses byte-for-byte. API flows
   (`/api` variants, bearer tokens) never redirect.
2. **Flow creation redirects.** `GET /self-service/{login,registration,recovery}/browser`
   for an HTML client: create the flow, then 303 to the Tenant's configured
   UI URL for that kind with `?flow=<id>` appended.
3. **Submit errors persist onto the flow, then redirect back.** Recoverable
   errors (invalid credentials, traits validation, password rejected,
   identifier taken, unsupported method) are stored on the flow as UI
   messages; the browser is 303'd back to `ui.<kind>_url?flow=<id>`. The UI
   re-fetches the flow to render them.
4. **New endpoint `GET /self-service/flows/{id}`** returns the flow: kind,
   expiry, state, UI fields, persisted messages, and a fresh `csrf_token`.
   Browser flows are readable **only** when the request carries the CSRF
   cookie that created the flow (compare like `flowCSRF` does). API flows do
   not need this endpoint.
5. **Fatal errors go to the error screen.** Errors with no flow to return to
   (flow not found/expired, CSRF violation, rate limited, internal error) 303
   to `ui.error_url?code=<code>`. Codes: `flow_expired`, `csrf_violation`,
   `rate_limited`, `internal_error`, `unknown_schema`. No error persistence in
   v1 — the query param is the whole payload (lightweight option, chosen
   deliberately).
6. **Form posts.** Browser Flow submit endpoints additionally accept
   `application/x-www-form-urlencoded`; `csrf_token` arrives as a form field.
   A form-encoded request counts as an HTML client for negotiation purposes.
7. **Per-tenant `ui` config block** in `tenant.Config`:
   `login_url`, `registration_url`, `recovery_url`, `verification_url`,
   `error_url`, `default_return_url`, `allowed_return_urls` (list).
   - OAuth2 Login/Consent Challenge redirect uses `ui.login_url`; the old
     top-level `login_url` stays readable as a fallback (deprecated, not
     removed). Same for `social_return_url` → `ui.default_return_url`.
   - Expose the block through the admin tenant create/update API
     (`internal/server/admin.go`), validating URLs the way `LoginURL` is
     validated today.
8. **Success redirects + `return_to`.** Browser flow creation accepts
   `?return_to=`; store it in the flow's context. On success an HTML client is
   303'd to it, else to `ui.default_return_url`; if neither is set, fall back
   to JSON. Open-redirect guard: `return_to` must match the origin of one of
   the configured UI URLs, or match `allowed_return_urls`
   (scheme+host[+path-prefix] match, Ory-style). Reject invalid `return_to`
   at flow creation with a 400 (JSON) — do not silently drop it.
9. **Held states.** For HTML clients:
   - `verification_required` → 303 to `ui.verification_url?flow=<verification flow id>`
     (the verification flow already has its own ID — see `verificationInfo.FlowID`
     in `internal/server/verification.go`).
   - `mfa_required` → 303 back to `ui.login_url?flow=<login flow id>`. The
     flow JSON from `GET /self-service/flows/{id}` must expose a `state`
     (e.g. `choose_method`, `mfa_required`, `verification_required`) plus the
     available `methods`, so the UI can render the right step.
10. **Fallback when unconfigured.** If the Tenant has no `ui` URLs and the
    server runs with `public.reference_ui: true`, default the URLs to the
    embedded reference UI pages under `/ui/`. If the reference UI is off,
    keep today's JSON behaviour (silent backward compatibility).
11. **CONTEXT.md** already updated (Browser Flow definition). Keep new code
    comments in the same domain language.

## Current-state map (verified)

| What | Where |
| --- | --- |
| Routes | `internal/server/public.go` (`/self-service/...`) |
| Flow create/submit handlers | `internal/server/selfservice.go` (`createFlowHandler`, `submitLogin`, `submitRegistration`) |
| Recovery / verification / MFA handlers | `internal/server/recovery.go`, `verification.go`, `mfa.go`, `mfa_sms.go` |
| JSON helpers (`writeError`, `readJSON`) | `internal/server/json.go` |
| CSRF (`ensureCSRFCookie`, `csrfToken`, `flowCSRF`) | `internal/server/csrf.go` |
| Flow model + contexts | `internal/flow/flow.go` |
| Flow storage (`CreateFlow`, `GetFlow`, `UpdateFlowContext`, `DeleteFlow`) | `internal/storage/flow.go` |
| Flows table | `internal/storage/migrations/0002_identities.sql` (+ `0003`, `0008` alters); next migration number is **0014** |
| Tenant config (`LoginURL`, `SocialReturnURL`) | `internal/tenant/tenant.go` |
| Admin tenant API (accepts `login_url`, `social_return_url`) | `internal/server/admin.go` (~line 91) |
| OAuth2 challenge redirect via `LoginURL` | `internal/server/oauth2.go` (~lines 97–124) |
| Social callback redirect pattern (`fail()`, `EffectiveSocialReturnURL`) | `internal/server/social.go` |
| Reference UI mount (`/ui/`), `public.reference_ui` flag | `internal/server/ui.go`, `internal/config/config.go` |

Note: on submit failure the enclosing tenant transaction rolls back, so the
flow row survives — but that same rollback will discard persisted UI messages.
Persist messages in a **separate** transaction (or after rollback) when the
submit fails.

## Suggested stages

1. **Tenant `ui` config block** + admin API + `Effective*` accessors with
   legacy fallbacks + reference-UI defaults. Unit tests on fallback order.
2. **Flow read model**: migration 0014 (`ui_messages jsonb`, `state text`,
   `return_to text` — or fold `return_to` into context), storage funcs,
   `GET /self-service/flows/{id}` with CSRF-cookie gate.
3. **Negotiation helper**: one function deciding JSON vs redirect from
   `Accept` + `Content-Type` + `f.Browser`; helpers `redirectToUI(w, r, url, flowID)`
   and `redirectToError(w, r, t, code)` (303). Use everywhere below.
4. **Form-encoded parsing** alongside `readJSON` on Browser Flow submits.
5. **Wire login + registration**: creation redirects, error persistence +
   redirect-back, success redirect with `return_to` guard, held states (9).
6. **Wire recovery + verification + MFA enroll** the same way.
7. **Fold in social + OAuth2**: social callback success → return-URL chain,
   social failure → `error_url`; OAuth2 challenge → `EffectiveLoginUIURL`.
8. **Reference UI**: pages read `?flow=`, fetch `GET /self-service/flows/{id}`,
   render fields/messages, submit as form posts. Serves as the end-to-end
   proof of the whole feature.

Each stage should land with tests (see `internal/server/proxy_test.go` for the
existing test style). Highest-value tests: negotiation matrix (HTML vs JSON vs
API flow), CSRF-cookie gate on flow reads, open-redirect rejection, error
persistence surviving the rolled-back submit transaction, and legacy
`login_url`/`social_return_url` fallbacks.

## Out of scope

- Persisted error objects with IDs (`GET /self-service/errors?id=`) — v1 uses
  `error_url?code=` only.
- Changing API-flow behaviour in any way.
- New flow kinds, consent UI redesign, per-flow-kind `return_to` allow-lists.
