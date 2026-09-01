# Content-negotiated Browser Flows: HTML clients are redirect-driven

Browser Flows were shipping raw JSON to the browser: navigating to `GET /self-service/login/browser` printed a flow object on screen, and a failed form submit printed an error object. We adopted the Ory Kratos model: on Browser Flow endpoints, a client that prefers `text/html` is driven by 303 redirects to the Tenant's configured UI screens — flow creation redirects to the screen with `?flow=<id>`, submit errors persist onto the flow and redirect back to that screen, and fatal errors (expired flow, CSRF violation) redirect to a configured error screen — while a client that asks for `application/json` keeps the existing JSON contract untouched, so SPAs and the API flow are unaffected.

We chose per-request content negotiation over a per-tenant switch or redirect-always because the same Tenant commonly serves both a form-post UI and a fetch-based SPA, and the `Accept` header is the only signal that distinguishes them per request.

## Consequences

- Browser Flow submit endpoints also accept `application/x-www-form-urlencoded`, so a plain HTML form can drive a flow end to end.
- Flows persist their UI error messages, and a new `GET /self-service/flows/{id}` endpoint exposes fields, messages, and state — readable only by the holder of the CSRF cookie that created the flow.
- Redirect targets live in a per-tenant `ui` config block (`login_url`, `registration_url`, `recovery_url`, `verification_url`, `error_url`, `default_return_url`, `allowed_return_urls`) which absorbs the older top-level `login_url` (OAuth2 Login/Consent Challenge UI) and `social_return_url`; the old fields remain readable as fallbacks.
- `return_to` is honoured on browser flow creation and validated against the origins of the configured UI URLs plus the explicit `allowed_return_urls` list, to prevent open redirects.
- When a Tenant configures no UI URLs, HTML clients fall back to the embedded reference UI if the server enables it, else to the previous JSON behaviour.
