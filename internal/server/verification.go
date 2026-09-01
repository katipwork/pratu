package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/otp"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// verificationInfo is the client-facing description of a pending
// verification: where to submit the code and where it was sent.
type verificationInfo struct {
	FlowID    string    `json:"flow_id"`
	Channel   string    `json:"channel"`
	Address   string    `json:"address"` // masked
	CSRFToken string    `json:"csrf_token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// startVerification creates a verification flow with a fresh One-Time
// Code and enqueues its delivery, all within the caller's tenant
// transaction. The send caps run first: when the address is over budget
// the whole transaction unwinds via errRateLimited. Browser-ness is
// inherited from the parent flow so CSRF protection carries through.
func (a *publicAPI) startVerification(r *http.Request, tx pgx.Tx, t *tenant.Tenant, identityID string, addr identity.Address, issueSession, browser bool) (*verificationInfo, error) {
	ctx := r.Context()
	if err := a.allowSend(ctx, t, addr.Channel, addr.Value); err != nil {
		return nil, err
	}
	vf, err := storage.CreateFlowWith(ctx, tx, t.ID, flow.KindVerification, flow.VerificationContext{
		IdentityID:   identityID,
		AddressID:    addr.ID,
		IssueSession: issueSession,
	}, browser, storage.FlowOptions{
		// The verification screen is the browser's next stop, so the flow
		// is bound to the same browser and opens on its code step.
		CSRFFingerprint: csrfFingerprint(csrfSecret(r)),
		State:           flow.StateCodeRequired,
	})
	if err != nil {
		return nil, err
	}
	code, err := otp.Generate()
	if err != nil {
		return nil, err
	}
	if err := storage.ReplaceCode(ctx, tx, t.ID, vf.ID, otp.Hash(code), time.Now().Add(otp.Lifetime)); err != nil {
		return nil, err
	}
	err = storage.EnqueueMessage(ctx, tx, t.ID, addr.Channel, addr.Value, "verification_code", map[string]string{
		"code":   code,
		"tenant": t.Name,
	})
	if err != nil {
		return nil, err
	}
	vi := &verificationInfo{
		FlowID:    vf.ID,
		Channel:   addr.Channel,
		Address:   maskAddress(addr.Channel, addr.Value),
		ExpiresAt: vf.ExpiresAt,
	}
	if browser {
		if secret := csrfSecret(r); secret != "" {
			vi.CSRFToken = csrfToken(secret, vf.ID)
		}
	}
	return vi, nil
}

type verifyOutcome int

const (
	verifyOK verifyOutcome = iota
	verifyWrongCode
	verifyCodeExpired
	verifyTooManyAttempts
)

func (a *publicAPI) submitVerification(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "verify:ip:"+clientIP(r), limitVerifyPerIP, time.Minute) {
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
		ident    *identity.Identity
		sess     *session.Session
		token    string
		browser  bool
		returnTo string
	)
	// Failed attempts must still commit (the attempt counter is the code's
	// brute-force budget), so non-infrastructure failures set outcome and
	// return nil instead of an error.
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindVerification)
		if err != nil {
			return err
		}
		browser = f.Browser
		returnTo = f.ReturnTo
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		var fctx flow.VerificationContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		code, err := storage.CodeForFlow(r.Context(), tx, f.ID)
		if err != nil {
			return err
		}
		if code.Attempts >= otp.MaxAttempts {
			outcome = verifyTooManyAttempts
			return nil
		}
		if err := storage.IncrementCodeAttempts(r.Context(), tx, code.ID); err != nil {
			return err
		}
		if time.Now().After(code.ExpiresAt) {
			outcome = verifyCodeExpired
			return nil
		}
		if !otp.Matches(code.Hash, body.Code) {
			outcome = verifyWrongCode
			return nil
		}

		if err := storage.MarkAddressVerified(r.Context(), tx, fctx.AddressID); err != nil {
			return err
		}
		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		ident, err = storage.FindIdentity(r.Context(), tx, fctx.IdentityID)
		if err != nil {
			return err
		}
		ident.Addresses, err = storage.AddressesForIdentity(r.Context(), tx, ident.ID)
		if err != nil {
			return err
		}
		if fctx.IssueSession {
			sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, ident.ID, session.AAL1, deviceFrom(r))
		}
		return err
	})
	if errors.Is(err, storage.ErrFlowNotFound) || errors.Is(err, storage.ErrNoCode) {
		a.failFatal(w, r, t, errCodeFlowExpired,
			http.StatusBadRequest, "verification flow not found or expired")
		return
	}
	if errors.Is(err, errCSRF) {
		a.failFatal(w, r, t, errCodeCSRF, http.StatusForbidden, "invalid or missing csrf_token")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	switch outcome {
	case verifyTooManyAttempts:
		a.failSubmission(w, r, t, flow.KindVerification, flowID,
			http.StatusBadRequest, "too many attempts; request a new code")
	case verifyCodeExpired:
		a.failSubmission(w, r, t, flow.KindVerification, flowID,
			http.StatusBadRequest, "code expired; request a new code")
	case verifyWrongCode:
		a.failSubmission(w, r, t, flow.KindVerification, flowID,
			http.StatusBadRequest, "incorrect code")
	default:
		resp := map[string]any{"state": "verified", "identity": ident}
		if sess != nil {
			resp["session"] = sess
			if browser {
				setSessionCookie(w, r, token, sess.ExpiresAt)
			} else {
				resp["session_token"] = token
			}
		}
		if browser && a.redirectAfterSuccess(w, r, t, returnTo) {
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (a *publicAPI) resendVerification(w http.ResponseWriter, r *http.Request) {
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

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindVerification)
		if err != nil {
			return err
		}
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		var fctx flow.VerificationContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		addr, err := storage.FindAddress(r.Context(), tx, fctx.AddressID)
		if err != nil {
			return err
		}
		if err := a.allowSend(r.Context(), t, addr.Channel, addr.Value); err != nil {
			return err
		}
		code, err := otp.Generate()
		if err != nil {
			return err
		}
		if err := storage.ReplaceCode(r.Context(), tx, t.ID, f.ID, otp.Hash(code), time.Now().Add(otp.Lifetime)); err != nil {
			return err
		}
		return storage.EnqueueMessage(r.Context(), tx, t.ID, addr.Channel, addr.Value, "verification_code", map[string]string{
			"code":   code,
			"tenant": t.Name,
		})
	})
	var rl errRateLimited
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		a.failFatal(w, r, t, errCodeFlowExpired,
			http.StatusBadRequest, "verification flow not found or expired")
	case errors.Is(err, errCSRF):
		a.failFatal(w, r, t, errCodeCSRF, http.StatusForbidden, "invalid or missing csrf_token")
	case errors.As(err, &rl):
		if !a.redirectToError(w, r, t, errCodeRateLimited) {
			writeRateLimited(w, rl.retryAfter)
		}
	case err != nil:
		internalError(w, err)
	default:
		// The code is on its way; the browser stays on the same screen.
		if a.redirectToScreen(w, r, t, flow.KindVerification, flowID) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"state": "sent"})
	}
}

// maskAddress hides most of an address in API responses: the recipient
// knows what they own; nobody else should learn it from a flow id.
func maskAddress(channel, value string) string {
	if channel == identity.ChannelEmail {
		if at := strings.IndexByte(value, '@'); at > 0 {
			return value[:1] + strings.Repeat("*", 4) + value[at:]
		}
	}
	if len(value) > 4 {
		return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
	}
	return strings.Repeat("*", len(value))
}
