package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/ratelimit"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

type publicAPI struct {
	pool      *pgxpool.Pool
	breach    password.BreachChecker
	limiter   *ratelimit.Limiter
	providers *oauth2.Providers // nil disables the OAuth2 endpoints
	// referenceUI reports whether the built-in screens are served, so a
	// tenant that configured none still has somewhere to redirect to.
	referenceUI bool
	log         *slog.Logger
}

// dummyHash keeps login timing uniform when the identifier is unknown.
var dummyHash = func() string {
	h, err := argon2id.CreateHash("pratu-timing-equalizer", argon2id.DefaultParams)
	if err != nil {
		panic(err)
	}
	return h
}()

// flowResponse is the JSON shape of a created flow: what to render, where
// to submit. The ui block will grow toward full node descriptions as the
// flow engine matures.
type flowResponse struct {
	flow.Flow
	CSRFToken string `json:"csrf_token,omitempty"`
	UI        struct {
		Fields []identity.Field `json:"fields"`
		// Methods lists the second factors a flow can be continued
		// with, when it waits on one.
		Methods []string `json:"methods,omitempty"`
	} `json:"ui"`
}

func (a *publicAPI) createFlowHandler(kind flow.Kind, browser bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := requestTenant(r)
		if !a.allow(w, r, "flow:ip:"+clientIP(r), limitFlowCreatePerIP, time.Minute) {
			return
		}
		var csrfSec string
		if browser {
			var err error
			if csrfSec, err = ensureCSRFCookie(w, r); err != nil {
				internalError(w, err)
				return
			}
		}
		// A browser flow may name where to land when it completes; an
		// unvalidated target would make this an open redirect.
		returnTo, ok := validateReturnTo(t, r, r.URL.Query().Get("return_to"))
		if !ok {
			writeError(w, http.StatusBadRequest, "return_to is not an allowed URL for this tenant")
			return
		}
		var resp flowResponse
		err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
			var flowContext any
			switch kind {
			case flow.KindRegistration:
				// The schema (selectable via ?schema=, defaulting to
				// "default") is pinned into the flow so a mid-flow schema
				// update cannot shift validation.
				name := r.URL.Query().Get("schema")
				if name == "" {
					name = "default"
				}
				schema, err := storage.CurrentSchema(r.Context(), tx, name)
				if err != nil {
					return err
				}
				flowContext = flow.RegistrationContext{SchemaID: schema.ID}
				resp.UI.Fields = registrationFields(t, schema)
				resp.UI.Methods = firstFactorMethods(t)
			case flow.KindRecovery:
				resp.UI.Fields = []identity.Field{
					{Name: "address", Type: "text", Title: "Recovery address", Required: true},
				}
			default:
				resp.UI.Fields = loginFields(t)
				resp.UI.Methods = firstFactorMethods(t)
			}
			f, err := storage.CreateFlowWith(r.Context(), tx, t.ID, kind, flowContext, browser,
				storage.FlowOptions{
					ReturnTo:        returnTo,
					CSRFFingerprint: csrfFingerprint(csrfSec),
					State:           flow.StateChooseMethod,
				})
			if err != nil {
				return err
			}
			resp.Flow = *f
			if browser {
				resp.CSRFToken = csrfToken(csrfSec, f.ID)
			}
			return nil
		})
		if errors.Is(err, storage.ErrSchemaNotFound) {
			if a.redirectToError(w, r, t, errCodeUnknownSchema) {
				return
			}
			writeError(w, http.StatusBadRequest, "unknown identity schema")
			return
		}
		if err != nil {
			if a.redirectToError(w, r, t, errCodeInternal) {
				logError(err)
				return
			}
			internalError(w, err)
			return
		}
		// An HTML client asked for a screen, not a flow object: send it to
		// the tenant's screen with the flow to render.
		if browser && a.redirectToScreen(w, r, t, kind, resp.Flow.ID) {
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (a *publicAPI) submitRegistration(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "reg:ip:"+clientIP(r), limitRegisterPerIP, time.Hour) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Method    string          `json:"method"`
		Traits    json.RawMessage `json:"traits"`
		Password  string          `json:"password"`
		CSRFToken string          `json:"csrf_token"`
	}
	if !readSubmission(w, r, &body) {
		return
	}
	if !t.Config.AllowsFirstFactor(body.Method) {
		a.failSubmission(w, r, t, flow.KindRegistration, flowID,
			http.StatusBadRequest, unsupportedFirstFactor(t))
		return
	}
	// A code registration writes no password credential: the Address it
	// must prove is the whole credential (ADR 0007).
	codeOnly := body.Method == tenant.FirstFactorCode
	var hash string
	if !codeOnly {
		if !a.validatePassword(w, r, t, flow.KindRegistration, flowID, body.Password) {
			return
		}
		var err error
		if hash, err = argon2id.CreateHash(body.Password, argon2id.DefaultParams); err != nil {
			internalError(w, err)
			return
		}
	}

	var (
		ident       *identity.Identity
		sess        *session.Session
		token       string
		verif       *verificationInfo
		holdSession bool
		browser     bool
		returnTo    string
	)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindRegistration)
		if err != nil {
			return err
		}
		browser = f.Browser
		returnTo = f.ReturnTo
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		var fctx flow.RegistrationContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		var schema *identity.Schema
		if fctx.SchemaID != "" {
			schema, err = storage.SchemaByID(r.Context(), tx, fctx.SchemaID)
		} else {
			// Flows created before schema pinning existed.
			schema, err = storage.CurrentSchema(r.Context(), tx, "default")
		}
		if err != nil {
			return err
		}
		if msgs := schema.ValidateTraits(body.Traits); msgs != nil {
			return validationError{msgs}
		}
		identifiers := schema.Identifiers(body.Traits)
		if len(identifiers) == 0 {
			return validationError{[]string{"traits contain no login identifier"}}
		}
		// Without a password, the only way back in is a code to an Address
		// the person can name at the login screen — so one identifier must
		// itself be a verification address, or this identity is unusable.
		if codeOnly && !identifiesAVerificationAddress(schema, body.Traits, identifiers) {
			return validationError{[]string{
				"traits contain no verifiable address usable as a login identifier"}}
		}
		ident, err = storage.CreateIdentity(r.Context(), tx, t.ID, schema.ID, body.Traits, hash, identifiers)
		if err != nil {
			return err
		}
		addrs, err := storage.CreateAddresses(r.Context(), tx, t.ID, ident.ID, schema.Addresses(body.Traits))
		if err != nil {
			return err
		}
		ident.Addresses = addrs

		// Registration and verification are one continuous flow: a code
		// goes out immediately, and under the default "required" policy
		// the session is withheld until the address is proven.
		var target *identity.Address
		for i := range addrs {
			if addrs[i].ForVerification {
				target = &addrs[i]
				break
			}
		}
		// A code registration always holds the session, even under
		// "deferred": an unproven Address would leave no credential at all.
		holdSession = target != nil && (t.Config.VerificationRequired() || codeOnly)
		if target != nil {
			verif, err = a.startVerification(r, tx, t, ident.ID, *target, holdSession, f.Browser)
			if err != nil {
				return err
			}
		}
		if !holdSession {
			sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, ident.ID, session.AAL1, deviceFrom(r))
		}
		return err
	})
	if err != nil {
		var ve validationError
		var rl errRateLimited
		switch {
		case errors.Is(err, storage.ErrFlowNotFound):
			a.failFatal(w, r, t, errCodeFlowExpired,
				http.StatusBadRequest, "registration flow not found or expired")
		case errors.Is(err, errCSRF):
			a.failFatal(w, r, t, errCodeCSRF,
				http.StatusForbidden, "invalid or missing csrf_token")
		case errors.As(err, &ve):
			a.failSubmission(w, r, t, flow.KindRegistration, flowID,
				http.StatusBadRequest, "invalid traits", ve.msgs...)
		case errors.Is(err, storage.ErrIdentifierTaken):
			a.failSubmission(w, r, t, flow.KindRegistration, flowID,
				http.StatusConflict, "an account with this identifier already exists")
		case errors.As(err, &rl):
			if !a.redirectToError(w, r, t, errCodeRateLimited) {
				writeRateLimited(w, rl.retryAfter)
			}
		default:
			internalError(w, err)
		}
		return
	}

	resp := map[string]any{"identity": ident}
	if verif != nil {
		resp["verification"] = verif
	}
	if holdSession {
		resp["state"] = "verification_required"
		// The verification flow is the browser's next screen; it carries
		// its own id, so the UI lands ready to take the One-Time Code.
		if browser && a.redirectToScreen(w, r, t, flow.KindVerification, verif.FlowID) {
			return
		}
	} else {
		resp["state"] = "active"
		resp["session"] = sess
		if browser {
			setSessionCookie(w, r, token, sess.ExpiresAt)
			if a.redirectAfterSuccess(w, r, t, returnTo) {
				return
			}
		} else {
			resp["session_token"] = token
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *publicAPI) submitLogin(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Method     string `json:"method"`
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
		CSRFToken  string `json:"csrf_token"`
	}
	if !readSubmission(w, r, &body) {
		return
	}
	// A code login has its own two-step endpoint pair; say so rather than
	// refusing a method the tenant does in fact accept.
	if body.Method == tenant.FirstFactorCode && t.Config.AllowsFirstFactor(tenant.FirstFactorCode) {
		a.failSubmission(w, r, t, flow.KindLogin, flowID, http.StatusBadRequest,
			`method "code" starts at POST /self-service/login/code/send`)
		return
	}
	if !t.Config.AllowsFirstFactor(tenant.FirstFactorPassword) || body.Method != "password" {
		a.failSubmission(w, r, t, flow.KindLogin, flowID,
			http.StatusBadRequest, unsupportedFirstFactor(t))
		return
	}
	if !a.allow(w, r, "login:ip:"+clientIP(r), limitLoginPerIP, time.Minute) {
		return
	}
	if !a.allowLoginAttempt(w, r, t, identity.Normalize(body.Identifier)) {
		return
	}

	var out loginOutcome
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindLogin)
		if err != nil {
			return err
		}
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		identityID, hash, err := storage.PasswordCredential(r.Context(), tx, identity.Normalize(body.Identifier))
		if errors.Is(err, storage.ErrNoCredential) {
			// Equalize timing with the real verification path before
			// returning the uniform failure.
			_, _ = argon2id.ComparePasswordAndHash(body.Password, dummyHash)
			return errInvalidCredentials
		}
		if err != nil {
			return err
		}
		match, err := argon2id.ComparePasswordAndHash(body.Password, hash)
		if err != nil {
			return err
		}
		if !match {
			return errInvalidCredentials
		}
		return a.completeFirstFactor(r, tx, t, f, identityID, &out)
	})
	if err != nil {
		var rl errRateLimited
		switch {
		case errors.Is(err, storage.ErrFlowNotFound):
			a.failFatal(w, r, t, errCodeFlowExpired,
				http.StatusBadRequest, "login flow not found or expired")
		case errors.Is(err, errCSRF):
			a.failFatal(w, r, t, errCodeCSRF,
				http.StatusForbidden, "invalid or missing csrf_token")
		case errors.Is(err, errInvalidCredentials):
			a.failSubmission(w, r, t, flow.KindLogin, flowID,
				http.StatusUnauthorized, "invalid credentials")
		case errors.As(err, &rl):
			if !a.redirectToError(w, r, t, errCodeRateLimited) {
				writeRateLimited(w, rl.retryAfter)
			}
		default:
			internalError(w, err)
		}
		return
	}
	a.respondLogin(w, r, t, flowID, &out)
}

// loginOutcome is what a proven first factor resolves to: a session, a
// second factor held on the same flow, or a verification detour. Both
// first factors (password and One-Time Code) resolve through it, so the
// two paths cannot drift apart.
type loginOutcome struct {
	sess         *session.Session
	token        string
	verif        *verificationInfo
	mfaRequired  bool
	mfaMethods   []string
	enrollNeeded bool
	browser      bool
	returnTo     string
}

// completeFirstFactor turns a proven first factor into an outcome, inside
// the caller's tenant transaction. It runs only post-authentication, so
// nothing it does reveals anything to enumeration.
func (a *publicAPI) completeFirstFactor(r *http.Request, tx pgx.Tx, t *tenant.Tenant,
	f *flow.Flow, identityID string, out *loginOutcome) error {

	out.browser = f.Browser
	out.returnTo = f.ReturnTo

	// Under the "required" policy an identity with no verified address
	// gets a fresh code, not a session. A first-factor One-Time Code has
	// already verified the address it proved, so this cannot fire for it.
	if t.Config.VerificationRequired() {
		addrs, err := storage.AddressesForIdentity(r.Context(), tx, identityID)
		if err != nil {
			return err
		}
		if unverified := allUnverified(addrs); unverified != nil {
			out.verif, err = a.startVerification(r, tx, t, identityID, *unverified, true, f.Browser)
			return err
		}
	}

	// Second factor: any enrolled factor turns the flow into a held
	// mfa_required state instead of a session.
	if t.Config.EffectiveMFA() != tenant.MFAOff {
		methods, err := enrolledFactors(r.Context(), tx, identityID)
		if err != nil {
			return err
		}
		if len(methods) > 0 {
			out.mfaRequired = true
			out.mfaMethods = methods
			if err := storage.UpdateFlowContext(r.Context(), tx, f.ID, flow.LoginContext{
				IdentityID: identityID,
				PasswordOK: true,
			}); err != nil {
				return err
			}
			// The flow stays open on its second-factor step, so a
			// redirected browser knows which screen to render.
			return storage.SetFlowUI(r.Context(), tx, f.ID, flow.StateMFARequired, nil)
		}
		out.enrollNeeded = t.Config.EffectiveMFA() == tenant.MFARequired
	}

	if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
		return err
	}
	var err error
	out.sess, out.token, err = storage.CreateSession(r.Context(), tx, t.ID, identityID, session.AAL1, deviceFrom(r))
	return err
}

// respondLogin writes the AuthResult of a completed first factor. Every
// first factor answers through here, so a code login is byte-for-byte a
// password login.
func (a *publicAPI) respondLogin(w http.ResponseWriter, r *http.Request, t *tenant.Tenant,
	flowID string, out *loginOutcome) {

	if out.verif != nil {
		if out.browser && a.redirectToScreen(w, r, t, flow.KindVerification, out.verif.FlowID) {
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"state":        "verification_required",
			"verification": out.verif,
		})
		return
	}
	if out.mfaRequired {
		// The second factor is owed on this same login flow: back to the
		// login screen, which reads the flow's state to render the step.
		if out.browser && a.redirectToScreen(w, r, t, flow.KindLogin, flowID) {
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"state":   "mfa_required",
			"methods": out.mfaMethods,
		})
		return
	}

	state := "active"
	if out.enrollNeeded {
		state = "mfa_enrollment_required"
	}
	resp := map[string]any{"state": state, "session": out.sess}
	if out.browser {
		setSessionCookie(w, r, out.token, out.sess.ExpiresAt)
		// Enrolment is owed but the session is real; the UI decides what
		// to do with it, so only a plain success redirects.
		if !out.enrollNeeded && a.redirectAfterSuccess(w, r, t, out.returnTo) {
			return
		}
	} else {
		resp["session_token"] = out.token
	}
	writeJSON(w, http.StatusOK, resp)
}

// unsupportedFirstFactor names what this tenant will actually accept.
func unsupportedFirstFactor(t *tenant.Tenant) string {
	allowed := t.Config.EffectiveFirstFactor()
	quoted := make([]string, len(allowed))
	for i, m := range allowed {
		quoted[i] = `"` + m + `"`
	}
	return "unsupported method; use " + strings.Join(quoted, " or ")
}

// validatePassword enforces the tenant's password policy, answering the
// request itself on rejection (back to the flow's screen for a browser).
// It runs before any transaction opens: the breach check is a network
// call and must not hold a transaction hostage.
func (a *publicAPI) validatePassword(w http.ResponseWriter, r *http.Request, t *tenant.Tenant,
	kind flow.Kind, flowID, candidate string) bool {
	pol := password.Policy{
		MinLength:   t.Config.Password.MinLength,
		BreachCheck: t.Config.Password.BreachCheckEnabled(),
	}
	violations, checkErr := password.Validate(r.Context(), candidate, pol, a.breach)
	if checkErr != nil {
		a.log.Warn("breach check unavailable; allowing password through (fail-open)", "error", checkErr)
	}
	if violations != nil {
		a.failSubmission(w, r, t, kind, flowID, http.StatusBadRequest, "password rejected", violations...)
		return false
	}
	return true
}

// loginFields is a login flow's opening step: the identifier, plus a
// password when the tenant accepts one as a first factor.
func loginFields(t *tenant.Tenant) []identity.Field {
	identifier := identity.Field{Name: "identifier", Type: "text", Title: "Email", Required: true}
	if t.Config.AllowsFirstFactor(tenant.FirstFactorCode) {
		// The identifier may well be a phone number here.
		identifier.Title = "Identifier"
	}
	fields := []identity.Field{identifier}
	if t.Config.AllowsFirstFactor(tenant.FirstFactorPassword) {
		fields = append(fields,
			identity.Field{Name: "password", Type: "password", Title: "Password", Required: true})
	}
	return fields
}

// registrationFields is the schema's traits, plus a password when the
// tenant accepts one — a code-only tenant must not be asked for one.
func registrationFields(t *tenant.Tenant, schema *identity.Schema) []identity.Field {
	fields := append([]identity.Field(nil), schema.Fields()...)
	if t.Config.AllowsFirstFactor(tenant.FirstFactorPassword) {
		fields = append(fields,
			identity.Field{Name: "password", Type: "password", Title: "Password", Required: true})
	}
	return fields
}

// firstFactorMethods advertises what may drive a flow's opening step.
// Empty for the password-only default, so clients of tenants that never
// opted in see exactly what they saw before.
func firstFactorMethods(t *tenant.Tenant) []string {
	if !t.Config.AllowsFirstFactor(tenant.FirstFactorCode) {
		return nil
	}
	return t.Config.EffectiveFirstFactor()
}

// identifiesAVerificationAddress reports whether any login identifier is
// itself a verification-annotated address, which is what a first-factor
// One-Time Code needs to have somewhere to go.
func identifiesAVerificationAddress(schema *identity.Schema, traits json.RawMessage, identifiers []string) bool {
	for _, spec := range schema.Addresses(traits) {
		if !spec.Verification {
			continue
		}
		for _, idf := range identifiers {
			if idf == spec.Value {
				return true
			}
		}
	}
	return false
}

// allUnverified returns the first verification-purpose address when the
// identity has such addresses but none verified, nil otherwise.
func allUnverified(addrs []identity.Address) *identity.Address {
	var first *identity.Address
	for i, a := range addrs {
		if !a.ForVerification {
			continue
		}
		if a.Verified {
			return nil
		}
		if first == nil {
			first = &addrs[i]
		}
	}
	return first
}

// sessionToken extracts the presented session token and whether it came
// from the cookie (cookie-sourced requests need CSRF proof for
// state-changing endpoints; header-sourced ones cannot be forged
// cross-site).
func sessionToken(r *http.Request) (token string, fromCookie bool) {
	if t := r.Header.Get("X-Session-Token"); t != "" {
		return t, false
	}
	if t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); t != "" && t != r.Header.Get("Authorization") {
		return t, false
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

func (a *publicAPI) whoami(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	token, fromCookie := sessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "no session token")
		return
	}

	var (
		sess  *session.Session
		ident *identity.Identity
	)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		var err error
		sess, err = storage.FindSessionByToken(r.Context(), tx, token)
		if err != nil {
			return err
		}
		ident, err = storage.FindIdentity(r.Context(), tx, sess.IdentityID)
		if err != nil {
			return err
		}
		ident.Addresses, err = storage.AddressesForIdentity(r.Context(), tx, ident.ID)
		return err
	})
	if errors.Is(err, storage.ErrSessionNotFound) {
		writeError(w, http.StatusUnauthorized, "session not found or expired")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	resp := map[string]any{
		"session":  sess,
		"identity": ident,
	}
	if fromCookie {
		// SPAs bootstrap their CSRF token here; CORS keeps it from
		// cross-origin readers.
		secret, err := ensureCSRFCookie(w, r)
		if err != nil {
			internalError(w, err)
			return
		}
		resp["csrf_token"] = csrfToken(secret, csrfSessionScope)
	}
	writeJSON(w, http.StatusOK, resp)
}

// logout revokes the current session and clears the cookie.
func (a *publicAPI) logout(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		return storage.DeleteSession(r.Context(), tx, sess.ID)
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "no session")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case err != nil:
		internalError(w, err)
	default:
		clearSessionCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]string{"state": "logged_out"})
	}
}

var errInvalidCredentials = errors.New("invalid credentials")

type validationError struct {
	msgs []string
}

func (validationError) Error() string { return "traits validation failed" }

func internalError(w http.ResponseWriter, err error) {
	// The error itself is server-side information; log it, tell the client
	// nothing beyond the status.
	logError(err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}
