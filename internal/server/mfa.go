package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
	"github.com/katipwork/pratu/internal/totp"
)

const totpMaxAttempts = 5

var errNoSession = errors.New("no valid session")

// totpConfig is the credential config for kind "totp".
// TODO: at-rest encryption of the secret needs a configured key; tracked
// as backlog alongside admin schema management.
type totpConfig struct {
	Secret string `json:"secret"`
}

func totpSecret(ctx context.Context, tx pgx.Tx, identityID string) (string, error) {
	raw, err := storage.CredentialConfig(ctx, tx, identityID, identity.CredentialTOTP)
	if err != nil || raw == nil {
		return "", err
	}
	var cfg totpConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	return cfg.Secret, nil
}

// requireSession resolves the request's session inside the caller's
// tenant transaction. enforceCSRF applies the session-scope CSRF check to
// cookie-sourced sessions (state-changing endpoints must set it).
func requireSession(ctx context.Context, tx pgx.Tx, r *http.Request, enforceCSRF bool) (*session.Session, error) {
	token, fromCookie := sessionToken(r)
	if token == "" {
		return nil, errNoSession
	}
	if fromCookie && enforceCSRF && !validCSRF(r, csrfSessionScope, r.Header.Get("X-CSRF-Token")) {
		return nil, errCSRF
	}
	s, err := storage.FindSessionByToken(ctx, tx, token)
	if errors.Is(err, storage.ErrSessionNotFound) {
		return nil, errNoSession
	}
	return s, err
}

func mfaHidden(t *tenant.Tenant) bool {
	return t.Config.EffectiveMFA() == tenant.MFAOff
}

// enrolledFactors lists the identity's second factors in preference
// order: TOTP before SMS (SMS is the weaker factor).
func enrolledFactors(ctx context.Context, tx pgx.Tx, identityID string) ([]string, error) {
	var methods []string
	secret, err := totpSecret(ctx, tx, identityID)
	if err != nil {
		return nil, err
	}
	if secret != "" {
		methods = append(methods, "totp")
	}
	phone, err := smsPhone(ctx, tx, identityID)
	if err != nil {
		return nil, err
	}
	if phone != "" {
		methods = append(methods, "sms")
	}
	return methods, nil
}

// enrollTOTP starts enrolment for the session's identity: a fresh secret,
// pending in a flow until a code proves the authenticator has it.
func (a *publicAPI) enrollTOTP(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if mfaHidden(t) {
		writeError(w, http.StatusNotFound, "second factors are not enabled for this tenant")
		return
	}
	if !a.allow(w, r, "totp:ip:"+clientIP(r), limitVerifyPerIP, time.Minute) {
		return
	}

	_, fromCookie := sessionToken(r)
	var csrfSec string
	if fromCookie {
		var err error
		if csrfSec, err = ensureCSRFCookie(w, r); err != nil {
			internalError(w, err)
			return
		}
	}

	var resp struct {
		FlowID    string    `json:"flow_id"`
		Secret    string    `json:"secret"`
		URI       string    `json:"uri"`
		CSRFToken string    `json:"csrf_token,omitempty"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		secret, err := totpSecret(r.Context(), tx, sess.IdentityID)
		if err != nil {
			return err
		}
		if secret != "" {
			return errAlreadyEnrolled
		}
		account, err := storage.IdentifierForIdentity(r.Context(), tx, sess.IdentityID)
		if err != nil {
			return err
		}
		newSecret, uri, err := totp.Generate(t.Name, account)
		if err != nil {
			return err
		}
		f, err := storage.CreateFlow(r.Context(), tx, t.ID, flow.KindTOTPEnroll, flow.TOTPEnrollContext{
			IdentityID: sess.IdentityID,
			SessionID:  sess.ID,
			Secret:     newSecret,
		}, fromCookie)
		if err != nil {
			return err
		}
		resp.FlowID, resp.Secret, resp.URI, resp.ExpiresAt = f.ID, newSecret, uri, f.ExpiresAt
		if fromCookie {
			resp.CSRFToken = csrfToken(csrfSec, f.ID)
		}
		return nil
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case errors.Is(err, errAlreadyEnrolled):
		writeError(w, http.StatusConflict, "TOTP already enrolled; remove it first")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, resp)
	}
}

// confirmTOTP activates a pending enrolment once its holder proves a code,
// and raises the current session to aal2.
func (a *publicAPI) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if mfaHidden(t) {
		writeError(w, http.StatusNotFound, "second factors are not enabled for this tenant")
		return
	}
	if !a.allow(w, r, "totp:ip:"+clientIP(r), limitVerifyPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Code      string `json:"code"`
		CSRFToken string `json:"csrf_token"`
	}
	if !readJSON(w, r, &body) {
		return
	}

	var (
		outcome verifyOutcome
		sess    *session.Session
	)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		var err error
		sess, err = requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindTOTPEnroll)
		if err != nil {
			return err
		}
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		var fctx flow.TOTPEnrollContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		if fctx.IdentityID != sess.IdentityID {
			return storage.ErrFlowNotFound
		}
		if fctx.Attempts >= totpMaxAttempts {
			outcome = verifyTooManyAttempts
			return nil
		}
		if !totp.Validate(body.Code, fctx.Secret) {
			fctx.Attempts++
			outcome = verifyWrongCode
			return storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx)
		}
		if err := storage.SetCredential(r.Context(), tx, t.ID, sess.IdentityID,
			identity.CredentialTOTP, totpConfig{Secret: fctx.Secret}); err != nil {
			return err
		}
		if err := storage.RaiseSessionAAL(r.Context(), tx, sess.ID); err != nil {
			return err
		}
		sess.AAL = session.AAL2
		return storage.DeleteFlow(r.Context(), tx, f.ID)
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "invalid or missing csrf token")
	case errors.Is(err, storage.ErrFlowNotFound):
		writeError(w, http.StatusBadRequest, "enrolment flow not found or expired")
	case err != nil:
		internalError(w, err)
	case outcome == verifyTooManyAttempts:
		writeError(w, http.StatusBadRequest, "too many attempts; start enrolment again")
	case outcome == verifyWrongCode:
		writeError(w, http.StatusBadRequest, "incorrect code")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"state": "enrolled", "session": sess})
	}
}

// unenrollTOTP removes the second factor; it demands the factor was just
// proven (aal2), so a stolen aal1 session cannot strip it.
func (a *publicAPI) unenrollTOTP(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		if !mfaHidden(t) && sess.AAL != session.AAL2 {
			return errAAL2Required
		}
		return storage.DeleteCredential(r.Context(), tx, sess.IdentityID, identity.CredentialTOTP)
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case errors.Is(err, errAAL2Required):
		writeError(w, http.StatusForbidden, "removing the second factor requires an aal2 session")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "unenrolled"})
	}
}

// submitLoginTOTP completes a login whose password step left the flow in
// mfa_required state.
func (a *publicAPI) submitLoginTOTP(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "totp:ip:"+clientIP(r), limitVerifyPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Code      string `json:"code"`
		CSRFToken string `json:"csrf_token"`
	}
	if !readJSON(w, r, &body) {
		return
	}

	var (
		outcome verifyOutcome
		sess    *session.Session
		token   string
		browser bool
	)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindLogin)
		if err != nil {
			return err
		}
		browser = f.Browser
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		var fctx flow.LoginContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		if !fctx.PasswordOK {
			return storage.ErrFlowNotFound
		}
		if fctx.FactorAttempts >= totpMaxAttempts {
			outcome = verifyTooManyAttempts
			return nil
		}
		secret, err := totpSecret(r.Context(), tx, fctx.IdentityID)
		if err != nil {
			return err
		}
		if secret == "" || !totp.Validate(body.Code, secret) {
			fctx.FactorAttempts++
			outcome = verifyWrongCode
			return storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx)
		}
		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, fctx.IdentityID, session.AAL2, deviceFrom(r))
		return err
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		writeError(w, http.StatusBadRequest, "login flow not found or expired")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "invalid or missing csrf_token")
	case err != nil:
		internalError(w, err)
	case outcome == verifyTooManyAttempts:
		writeError(w, http.StatusBadRequest, "too many attempts; start over")
	case outcome == verifyWrongCode:
		writeError(w, http.StatusUnauthorized, "incorrect code")
	default:
		resp := map[string]any{"state": "active", "session": sess}
		if browser {
			setSessionCookie(w, r, token, sess.ExpiresAt)
		} else {
			resp["session_token"] = token
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// submitRecoveryTOTP proves the second factor within a recovery flow —
// recovery does not bypass TOTP (ADR-adjacent decision recorded in the
// flow design).
func (a *publicAPI) submitRecoveryTOTP(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "recovery:ip:"+clientIP(r), limitRecoveryPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Code      string `json:"code"`
		CSRFToken string `json:"csrf_token"`
	}
	if !readJSON(w, r, &body) {
		return
	}

	var outcome verifyOutcome
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindRecovery)
		if err != nil {
			return err
		}
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		var fctx flow.RecoveryContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		if !fctx.CodeOK {
			return errRecoveryNotProven
		}
		if fctx.FactorAttempts >= totpMaxAttempts {
			outcome = verifyTooManyAttempts
			return nil
		}
		secret, err := totpSecret(r.Context(), tx, fctx.IdentityID)
		if err != nil {
			return err
		}
		if secret == "" || !totp.Validate(body.Code, secret) {
			fctx.FactorAttempts++
			outcome = verifyWrongCode
			return storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx)
		}
		fctx.SecondFactorOK = true
		return storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx)
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		writeError(w, http.StatusBadRequest, "recovery flow not found or expired")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "invalid or missing csrf_token")
	case errors.Is(err, errRecoveryNotProven):
		writeError(w, http.StatusBadRequest, "recovery code not yet verified")
	case err != nil:
		internalError(w, err)
	case outcome == verifyTooManyAttempts:
		writeError(w, http.StatusBadRequest, "too many attempts; start recovery again")
	case outcome == verifyWrongCode:
		writeError(w, http.StatusBadRequest, "incorrect code")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "set_password"})
	}
}

var (
	errAlreadyEnrolled = errors.New("totp already enrolled")
	errAAL2Required    = errors.New("aal2 session required")
)
