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
	"github.com/katipwork/pratu/internal/otp"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// smsConfig is the credential config for kind "sms": the enrolled,
// code-proven second-factor phone number.
type smsConfig struct {
	Phone string `json:"phone"`
}

func smsPhone(ctx context.Context, tx pgx.Tx, identityID string) (string, error) {
	raw, err := storage.CredentialConfig(ctx, tx, identityID, identity.CredentialSMS)
	if err != nil || raw == nil {
		return "", err
	}
	var cfg smsConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	return cfg.Phone, nil
}

// sendFactorCode installs a fresh code on the flow and enqueues its SMS
// delivery, under the full send caps.
func (a *publicAPI) sendFactorCode(ctx context.Context, tx pgx.Tx, t *tenant.Tenant, flowID, phone, template string) error {
	if err := a.allowSend(ctx, t, identity.ChannelSMS, phone); err != nil {
		return err
	}
	code, err := otp.Generate()
	if err != nil {
		return err
	}
	if err := storage.ReplaceCode(ctx, tx, t.ID, flowID, otp.Hash(code), time.Now().Add(otp.Lifetime)); err != nil {
		return err
	}
	return storage.EnqueueMessage(ctx, tx, t.ID, identity.ChannelSMS, phone, template, map[string]string{
		"code":   code,
		"tenant": t.Name,
	})
}

// checkFactorCode burns one attempt against the flow's code; failures set
// the outcome and commit (the budget must survive the rollback-free path).
func checkFactorCode(ctx context.Context, tx pgx.Tx, flowID, submitted string) (verifyOutcome, error) {
	code, err := storage.CodeForFlow(ctx, tx, flowID)
	if errors.Is(err, storage.ErrNoCode) {
		return verifyWrongCode, nil
	}
	if err != nil {
		return verifyOK, err
	}
	if code.Attempts >= otp.MaxAttempts {
		return verifyTooManyAttempts, nil
	}
	if err := storage.IncrementCodeAttempts(ctx, tx, code.ID); err != nil {
		return verifyOK, err
	}
	if time.Now().After(code.ExpiresAt) {
		return verifyCodeExpired, nil
	}
	if !otp.Matches(code.Hash, submitted) {
		return verifyWrongCode, nil
	}
	return verifyOK, nil
}

// enrollSMS starts second-factor enrolment for a phone number: pending in
// a flow, with a code sent to prove possession before it becomes a
// credential.
func (a *publicAPI) enrollSMS(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if mfaHidden(t) {
		writeError(w, http.StatusNotFound, "second factors are not enabled for this tenant")
		return
	}
	if !a.allow(w, r, "totp:ip:"+clientIP(r), limitVerifyPerIP, time.Minute) {
		return
	}

	var body struct {
		Phone string `json:"phone"`
	}
	if !readSubmission(w, r, &body) {
		return
	}
	phone, ok := identity.NormalizePhone(body.Phone)
	if !ok {
		writeError(w, http.StatusBadRequest, "phone must be in international format, e.g. +66812345678")
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
		Address   string    `json:"address"`
		CSRFToken string    `json:"csrf_token,omitempty"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		existing, err := smsPhone(r.Context(), tx, sess.IdentityID)
		if err != nil {
			return err
		}
		if existing != "" {
			return errAlreadyEnrolled
		}
		f, err := storage.CreateFlow(r.Context(), tx, t.ID, flow.KindSMSEnroll, flow.SMSEnrollContext{
			IdentityID: sess.IdentityID,
			SessionID:  sess.ID,
			Phone:      phone,
		}, fromCookie)
		if err != nil {
			return err
		}
		if err := a.sendFactorCode(r.Context(), tx, t, f.ID, phone, "mfa_enroll_code"); err != nil {
			return err
		}
		resp.FlowID, resp.Address, resp.ExpiresAt = f.ID, maskAddress(identity.ChannelSMS, phone), f.ExpiresAt
		if fromCookie {
			resp.CSRFToken = csrfToken(csrfSec, f.ID)
		}
		return nil
	})
	var rl errRateLimited
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case errors.Is(err, errAlreadyEnrolled):
		writeError(w, http.StatusConflict, "an SMS factor is already enrolled; remove it first")
	case errors.As(err, &rl):
		writeRateLimited(w, rl.retryAfter)
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, resp)
	}
}

// confirmSMS activates the pending phone once its holder proves the code,
// and raises the current session to aal2.
func (a *publicAPI) confirmSMS(w http.ResponseWriter, r *http.Request) {
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
	if !readSubmission(w, r, &body) {
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
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindSMSEnroll)
		if err != nil {
			return err
		}
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		var fctx flow.SMSEnrollContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		if fctx.IdentityID != sess.IdentityID {
			return storage.ErrFlowNotFound
		}
		outcome, err = checkFactorCode(r.Context(), tx, f.ID, body.Code)
		if err != nil || outcome != verifyOK {
			return err
		}
		if err := storage.SetCredential(r.Context(), tx, t.ID, sess.IdentityID,
			identity.CredentialSMS, smsConfig{Phone: fctx.Phone}); err != nil {
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
	case outcome == verifyCodeExpired:
		writeError(w, http.StatusBadRequest, "code expired; start enrolment again")
	case outcome == verifyWrongCode:
		writeError(w, http.StatusBadRequest, "incorrect code")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"state": "enrolled", "session": sess})
	}
}

// unenrollSMS removes the SMS factor; aal2 required for the same reason
// as TOTP.
func (a *publicAPI) unenrollSMS(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		if !mfaHidden(t) && sess.AAL != session.AAL2 {
			return errAAL2Required
		}
		return storage.DeleteCredential(r.Context(), tx, sess.IdentityID, identity.CredentialSMS)
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

// loginSMSSend delivers a login code to the enrolled phone for a flow
// held at mfa_required.
func (a *publicAPI) loginSMSSend(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "resend:ip:"+clientIP(r), limitResendPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if !readOptionalSubmission(w, r, &body) {
		return
	}

	var masked string
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindLogin)
		if err != nil {
			return err
		}
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
		phone, err := smsPhone(r.Context(), tx, fctx.IdentityID)
		if err != nil {
			return err
		}
		if phone == "" {
			return errNoSMSFactor
		}
		masked = maskAddress(identity.ChannelSMS, phone)
		return a.sendFactorCode(r.Context(), tx, t, f.ID, phone, "mfa_code")
	})
	a.respondFactorSend(w, r, t, flow.KindLogin, flowID, err, masked)
}

// loginSMSSubmit completes a held login with the delivered code.
func (a *publicAPI) loginSMSSubmit(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "totp:ip:"+clientIP(r), limitVerifyPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Code      string `json:"code"`
		CSRFToken string `json:"csrf_token"`
	}
	if !readSubmission(w, r, &body) {
		return
	}

	var (
		outcome  verifyOutcome
		sess     *session.Session
		token    string
		browser  bool
		returnTo string
	)
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindLogin)
		if err != nil {
			return err
		}
		browser = f.Browser
		returnTo = f.ReturnTo
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
		outcome, err = checkFactorCode(r.Context(), tx, f.ID, body.Code)
		if err != nil || outcome != verifyOK {
			return err
		}
		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, fctx.IdentityID, session.AAL2, deviceFrom(r))
		return err
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		a.failFatal(w, r, t, errCodeFlowExpired,
			http.StatusBadRequest, "login flow not found or expired")
	case errors.Is(err, errCSRF):
		a.failFatal(w, r, t, errCodeCSRF, http.StatusForbidden, "invalid or missing csrf_token")
	case err != nil:
		internalError(w, err)
	case outcome == verifyTooManyAttempts:
		a.failSubmission(w, r, t, flow.KindLogin, flowID,
			http.StatusBadRequest, "too many attempts; start over")
	case outcome == verifyCodeExpired:
		a.failSubmission(w, r, t, flow.KindLogin, flowID,
			http.StatusBadRequest, "code expired; request a new one")
	case outcome == verifyWrongCode:
		a.failSubmission(w, r, t, flow.KindLogin, flowID, http.StatusUnauthorized, "incorrect code")
	default:
		resp := map[string]any{"state": "active", "session": sess}
		if browser {
			setSessionCookie(w, r, token, sess.ExpiresAt)
			if a.redirectAfterSuccess(w, r, t, returnTo) {
				return
			}
		} else {
			resp["session_token"] = token
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// recoverySMSSend delivers a second-factor code within a recovery flow
// whose recovery code is already proven.
func (a *publicAPI) recoverySMSSend(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "recovery:ip:"+clientIP(r), limitRecoveryPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if !readOptionalSubmission(w, r, &body) {
		return
	}

	var masked string
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
		phone, err := smsPhone(r.Context(), tx, fctx.IdentityID)
		if err != nil {
			return err
		}
		if phone == "" {
			return errNoSMSFactor
		}
		masked = maskAddress(identity.ChannelSMS, phone)
		// The recovery code row has served its purpose (CodeOK is
		// recorded); the factor code takes its slot on the flow.
		return a.sendFactorCode(r.Context(), tx, t, f.ID, phone, "mfa_code")
	})
	a.respondFactorSend(w, r, t, flow.KindRecovery, flowID, err, masked)
}

// recoverySMSSubmit proves the SMS factor within recovery.
func (a *publicAPI) recoverySMSSubmit(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "recovery:ip:"+clientIP(r), limitRecoveryPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Code      string `json:"code"`
		CSRFToken string `json:"csrf_token"`
	}
	if !readSubmission(w, r, &body) {
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
		outcome, err = checkFactorCode(r.Context(), tx, f.ID, body.Code)
		if err != nil || outcome != verifyOK {
			return err
		}
		fctx.SecondFactorOK = true
		return storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx)
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		a.failFatal(w, r, t, errCodeFlowExpired,
			http.StatusBadRequest, "recovery flow not found or expired")
	case errors.Is(err, errCSRF):
		a.failFatal(w, r, t, errCodeCSRF, http.StatusForbidden, "invalid or missing csrf_token")
	case errors.Is(err, errRecoveryNotProven):
		a.failSubmission(w, r, t, flow.KindRecovery, flowID,
			http.StatusBadRequest, "recovery code not yet verified")
	case err != nil:
		internalError(w, err)
	case outcome == verifyTooManyAttempts:
		a.failSubmission(w, r, t, flow.KindRecovery, flowID,
			http.StatusBadRequest, "too many attempts; start recovery again")
	case outcome == verifyCodeExpired:
		a.failSubmission(w, r, t, flow.KindRecovery, flowID,
			http.StatusBadRequest, "code expired; request a new one")
	case outcome == verifyWrongCode:
		a.failSubmission(w, r, t, flow.KindRecovery, flowID, http.StatusBadRequest, "incorrect code")
	default:
		a.advanceFlow(r, t, flowID, flow.StatePasswordRequired)
		if a.redirectToScreen(w, r, t, flow.KindRecovery, flowID) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"state": "set_password"})
	}
}

// respondFactorSend answers a second-factor code delivery: a browser
// stays on the screen that asked for it.
func (a *publicAPI) respondFactorSend(w http.ResponseWriter, r *http.Request, t *tenant.Tenant,
	kind flow.Kind, flowID string, err error, masked string) {

	var rl errRateLimited
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		a.failFatal(w, r, t, errCodeFlowExpired, http.StatusBadRequest, "flow not found or expired")
	case errors.Is(err, errCSRF):
		a.failFatal(w, r, t, errCodeCSRF, http.StatusForbidden, "invalid or missing csrf_token")
	case errors.Is(err, errRecoveryNotProven):
		a.failSubmission(w, r, t, kind, flowID,
			http.StatusBadRequest, "recovery code not yet verified")
	case errors.Is(err, errNoSMSFactor):
		a.failSubmission(w, r, t, kind, flowID, http.StatusBadRequest, "no SMS factor enrolled")
	case errors.As(err, &rl):
		if !a.redirectToError(w, r, t, errCodeRateLimited) {
			writeRateLimited(w, rl.retryAfter)
		}
	case err != nil:
		internalError(w, err)
	default:
		if a.redirectToScreen(w, r, t, kind, flowID) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"state": "sent", "address": masked})
	}
}

var errNoSMSFactor = errors.New("no sms factor enrolled")
