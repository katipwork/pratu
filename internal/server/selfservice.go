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
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/ratelimit"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
)

type publicAPI struct {
	pool    *pgxpool.Pool
	breach  password.BreachChecker
	limiter *ratelimit.Limiter
	log     *slog.Logger
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
	UI struct {
		Fields []identity.Field `json:"fields"`
	} `json:"ui"`
}

func (a *publicAPI) createFlowHandler(kind flow.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := requestTenant(r)
		if !a.allow(w, r, "flow:ip:"+clientIP(r), limitFlowCreatePerIP, time.Minute) {
			return
		}
		var resp flowResponse
		err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
			f, err := storage.CreateFlow(r.Context(), tx, t.ID, kind, nil)
			if err != nil {
				return err
			}
			resp.Flow = *f
			schema, err := storage.DefaultIdentitySchema(r.Context(), tx)
			if err != nil {
				return err
			}
			if kind == flow.KindRegistration {
				fields := append([]identity.Field(nil), schema.Fields()...)
				resp.UI.Fields = append(fields,
					identity.Field{Name: "password", Type: "password", Title: "Password", Required: true})
			} else {
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
		Method   string          `json:"method"`
		Traits   json.RawMessage `json:"traits"`
		Password string          `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Method != "password" {
		writeError(w, http.StatusBadRequest, "unsupported method; use \"password\"")
		return
	}
	// Policy runs before the transaction opens: the breach check is a
	// network call and must not hold a database transaction hostage. A
	// rejected password leaves the flow intact for another try.
	pol := password.Policy{
		MinLength:   t.Config.Password.MinLength,
		BreachCheck: t.Config.Password.BreachCheckEnabled(),
	}
	violations, checkErr := password.Validate(r.Context(), body.Password, pol, a.breach)
	if checkErr != nil {
		a.log.Warn("breach check unavailable; allowing password through (fail-open)", "error", checkErr)
	}
	if violations != nil {
		writeError(w, http.StatusBadRequest, "password rejected", violations...)
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
	)
	err = storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		if err := storage.ConsumeFlow(r.Context(), tx, flowID, flow.KindRegistration); err != nil {
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
		addrs, err := storage.CreateAddresses(r.Context(), tx, t.ID, ident.ID, schema.VerifiableAddresses(body.Traits))
		if err != nil {
			return err
		}
		ident.Addresses = addrs

		// Registration and verification are one continuous flow: a code
		// goes out immediately, and under the default "required" policy
		// the session is withheld until the address is proven.
		holdSession = len(addrs) > 0 && t.Config.VerificationRequired()
		if len(addrs) > 0 {
			verif, err = a.startVerification(r, tx, t, ident.ID, addrs[0], holdSession)
			if err != nil {
				return err
			}
		}
		if !holdSession {
			sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, ident.ID)
		}
		return err
	})
	if err != nil {
		var ve validationError
		var rl errRateLimited
		switch {
		case errors.Is(err, storage.ErrFlowNotFound):
			writeError(w, http.StatusBadRequest, "registration flow not found or expired")
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
		resp["session_token"] = token
		resp["session"] = sess
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
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		if err := storage.ConsumeFlow(r.Context(), tx, flowID, flow.KindLogin); err != nil {
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
				verif, err = a.startVerification(r, tx, t, identityID, *unverified, true)
				return err
			}
		}
		sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, identityID)
		return err
	})
	if err != nil {
		var rl errRateLimited
		switch {
		case errors.Is(err, storage.ErrFlowNotFound):
			writeError(w, http.StatusBadRequest, "login flow not found or expired")
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

	writeJSON(w, http.StatusOK, map[string]any{
		"state":         "active",
		"session_token": token,
		"session":       sess,
	})
}

// allUnverified returns the first address when the identity has addresses
// but none verified, nil otherwise.
func allUnverified(addrs []identity.Address) *identity.Address {
	if len(addrs) == 0 {
		return nil
	}
	for _, a := range addrs {
		if a.Verified {
			return nil
		}
	}
	return &addrs[0]
}

func (a *publicAPI) whoami(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
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

	writeJSON(w, http.StatusOK, map[string]any{
		"session":  sess,
		"identity": ident,
	})
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
