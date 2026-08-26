package server

import (
	"encoding/json"
	"errors"
	"fmt"
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
	log       *slog.Logger
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
		var resp flowResponse
		err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
			f, err := storage.CreateFlow(r.Context(), tx, t.ID, kind, nil, browser)
			if err != nil {
				return err
			}
			resp.Flow = *f
			if browser {
				resp.CSRFToken = csrfToken(csrfSec, f.ID)
			}
			schema, err := storage.DefaultIdentitySchema(r.Context(), tx)
			if err != nil {
				return err
			}
			switch kind {
			case flow.KindRegistration:
				fields := append([]identity.Field(nil), schema.Fields()...)
				resp.UI.Fields = append(fields,
					identity.Field{Name: "password", Type: "password", Title: "Password", Required: true})
			case flow.KindRecovery:
				resp.UI.Fields = []identity.Field{
					{Name: "address", Type: "text", Title: "Recovery address", Required: true},
				}
			default:
				resp.UI.Fields = []identity.Field{
					{Name: "identifier", Type: "text", Title: "Email", Required: true},
					{Name: "password", Type: "password", Title: "Password", Required: true},
				}
			}
			return nil
		})
		if err != nil {
			internalError(w, err)
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
	if !readJSON(w, r, &body) {
		return
	}
	if body.Method != "password" {
		writeError(w, http.StatusBadRequest, "unsupported method; use \"password\"")
		return
	}
	if !a.validatePassword(w, r, t, body.Password) {
		return
	}

	hash, err := argon2id.CreateHash(body.Password, argon2id.DefaultParams)
	if err != nil {
		internalError(w, err)
		return
	}

	var (
		ident       *identity.Identity
		sess        *session.Session
		token       string
		verif       *verificationInfo
		holdSession bool
		browser     bool
	)
	err = storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindRegistration)
		if err != nil {
			return err
		}
		browser = f.Browser
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		schema, err := storage.DefaultIdentitySchema(r.Context(), tx)
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
		holdSession = target != nil && t.Config.VerificationRequired()
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
			writeError(w, http.StatusBadRequest, "registration flow not found or expired")
		case errors.Is(err, errCSRF):
			writeError(w, http.StatusForbidden, "invalid or missing csrf_token")
		case errors.As(err, &ve):
			writeError(w, http.StatusBadRequest, "invalid traits", ve.msgs...)
		case errors.Is(err, storage.ErrIdentifierTaken):
			writeError(w, http.StatusConflict, "an account with this identifier already exists")
		case errors.As(err, &rl):
			writeRateLimited(w, rl.retryAfter)
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
	} else {
		resp["state"] = "active"
		resp["session"] = sess
		if browser {
			setSessionCookie(w, r, token, sess.ExpiresAt)
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
	if !readJSON(w, r, &body) {
		return
	}
	if body.Method != "password" {
		writeError(w, http.StatusBadRequest, "unsupported method; use \"password\"")
		return
	}
	if !a.allow(w, r, "login:ip:"+clientIP(r), limitLoginPerIP, time.Minute) {
		return
	}
	if !a.allow(w, r, fmt.Sprintf("login:id:%s:%s", t.ID, identity.Normalize(body.Identifier)),
		limitLoginPerID, time.Minute) {
		return
	}

	var (
		sess  *session.Session
		token string
		verif *verificationInfo
	)
	var mfaRequired, enrollNeeded, browser bool
	var mfaMethods []string
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindLogin)
		if err != nil {
			return err
		}
		browser = f.Browser
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

		// Correct password, but under the "required" policy an identity
		// with no verified address gets a fresh code, not a session. Only
		// runs post-authentication, so it reveals nothing to enumeration.
		if t.Config.VerificationRequired() {
			addrs, err := storage.AddressesForIdentity(r.Context(), tx, identityID)
			if err != nil {
				return err
			}
			if unverified := allUnverified(addrs); unverified != nil {
				verif, err = a.startVerification(r, tx, t, identityID, *unverified, true, f.Browser)
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
				mfaRequired = true
				mfaMethods = methods
				return storage.UpdateFlowContext(r.Context(), tx, f.ID, flow.LoginContext{
					IdentityID: identityID,
					PasswordOK: true,
				})
			}
			enrollNeeded = t.Config.EffectiveMFA() == tenant.MFARequired
		}

		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, identityID, session.AAL1, deviceFrom(r))
		return err
	})
	if err != nil {
		var rl errRateLimited
		switch {
		case errors.Is(err, storage.ErrFlowNotFound):
			writeError(w, http.StatusBadRequest, "login flow not found or expired")
		case errors.Is(err, errCSRF):
			writeError(w, http.StatusForbidden, "invalid or missing csrf_token")
		case errors.Is(err, errInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid credentials")
		case errors.As(err, &rl):
			writeRateLimited(w, rl.retryAfter)
		default:
			internalError(w, err)
		}
		return
	}
	if verif != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"state":        "verification_required",
			"verification": verif,
		})
		return
	}
	if mfaRequired {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"state":   "mfa_required",
			"methods": mfaMethods,
		})
		return
	}

	state := "active"
	if enrollNeeded {
		state = "mfa_enrollment_required"
	}
	resp := map[string]any{"state": state, "session": sess}
	if browser {
		setSessionCookie(w, r, token, sess.ExpiresAt)
	} else {
		resp["session_token"] = token
	}
	writeJSON(w, http.StatusOK, resp)
}

// validatePassword enforces the tenant's password policy, answering the
// request itself on rejection. It runs before any transaction opens: the
// breach check is a network call and must not hold a transaction hostage.
func (a *publicAPI) validatePassword(w http.ResponseWriter, r *http.Request, t *tenant.Tenant, candidate string) bool {
	pol := password.Policy{
		MinLength:   t.Config.Password.MinLength,
		BreachCheck: t.Config.Password.BreachCheckEnabled(),
	}
	violations, checkErr := password.Validate(r.Context(), candidate, pol, a.breach)
	if checkErr != nil {
		a.log.Warn("breach check unavailable; allowing password through (fail-open)", "error", checkErr)
	}
	if violations != nil {
		writeError(w, http.StatusBadRequest, "password rejected", violations...)
		return false
	}
	return true
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
