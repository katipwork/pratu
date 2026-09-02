package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/otp"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Passwordless first factor (ADR 0007): an Identity signs in by proving
// control of a verification-annotated Address with a One-Time Code, on a
// tenant that opted into first_factor "code". Two steps, mirroring the
// SMS Second Factor pair: send, then submit.
//
// The send step is an enumeration oracle if it is anything but uniform —
// the response is the whole interaction — so it answers identically
// whether or not the identifier exists, exactly as Recovery does.

// codeSentMessage is the send step's entire answer, existence or not.
const codeSentMessage = "if the identifier exists, a code was sent to it"

// loginCodeAllowed gates both steps on the tenant's first-factor policy.
func (a *publicAPI) loginCodeAllowed(w http.ResponseWriter, r *http.Request, t *tenant.Tenant, flowID string) bool {
	if t.Config.AllowsFirstFactor(tenant.FirstFactorCode) {
		return true
	}
	a.failSubmission(w, r, t, flow.KindLogin, flowID,
		http.StatusBadRequest, unsupportedFirstFactor(t))
	return false
}

// loginCodeSend delivers a first-factor One-Time Code to the Address that
// is the submitted identifier. Doubles as the resend step.
func (a *publicAPI) loginCodeSend(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	flowID := r.URL.Query().Get("flow")
	if !a.loginCodeAllowed(w, r, t, flowID) {
		return
	}

	var body struct {
		Identifier string `json:"identifier"`
		CSRFToken  string `json:"csrf_token"`
	}
	if !readSubmission(w, r, &body) {
		return
	}
	if !a.allow(w, r, "login:ip:"+clientIP(r), limitLoginPerIP, time.Minute) {
		return
	}
	identifier := identity.Normalize(body.Identifier)
	if !a.allow(w, r, fmt.Sprintf("login:id:%s:%s", t.ID, identifier), limitLoginPerID, time.Minute) {
		return
	}

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindLogin)
		if err != nil {
			return err
		}
		if err := flowCSRF(r, f.Browser, f.ID, body.CSRFToken); err != nil {
			return err
		}
		addr, identityID, err := storage.FindLoginCodeAddress(r.Context(), tx, identifier)
		if errors.Is(err, storage.ErrNoCredential) {
			return nil // unknown identifier: same response, nothing sent
		}
		if err != nil {
			return err
		}
		// A send-cap refusal must also stay indistinguishable from a
		// miss, so drop the send instead of surfacing a 429.
		if err := a.allowSend(r.Context(), t, addr.Channel, addr.Value); err != nil {
			var rl errRateLimited
			if errors.As(err, &rl) {
				a.log.Warn("login code send suppressed by rate limit", "flow", f.ID)
				return nil
			}
			return err
		}
		code, err := otp.Generate()
		if err != nil {
			return err
		}
		if err := storage.ReplaceCode(r.Context(), tx, t.ID, f.ID, otp.Hash(code), time.Now().Add(otp.Lifetime)); err != nil {
			return err
		}
		err = storage.UpdateFlowContext(r.Context(), tx, f.ID, flow.LoginContext{
			IdentityID: identityID,
			AddressID:  addr.ID,
		})
		if err != nil {
			return err
		}
		return storage.EnqueueMessage(r.Context(), tx, t.ID, addr.Channel, addr.Value, "login_code", map[string]string{
			"code":   code,
			"tenant": t.Name,
		})
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		a.failFatal(w, r, t, errCodeFlowExpired,
			http.StatusBadRequest, "login flow not found or expired")
		return
	case errors.Is(err, errCSRF):
		a.failFatal(w, r, t, errCodeCSRF, http.StatusForbidden, "invalid or missing csrf_token")
		return
	case err != nil:
		internalError(w, err)
		return
	}
	// The flow moves to its code step whether or not the identifier
	// existed: the screen must look identical either way.
	a.advanceFlow(r, t, flowID, flow.StateCodeRequired, flow.Message{
		Type: flow.MessageInfo, Text: codeSentMessage,
	})
	if a.redirectToScreen(w, r, t, flow.KindLogin, flowID) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"state":   "code_sent",
		"message": codeSentMessage,
	})
}

// loginCodeSubmit completes a login with the delivered code. Proving the
// code proves the Address, so it is marked verified and the flow never
// detours through Verification.
func (a *publicAPI) loginCodeSubmit(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	flowID := r.URL.Query().Get("flow")
	if !a.loginCodeAllowed(w, r, t, flowID) {
		return
	}

	var body struct {
		Code      string `json:"code"`
		CSRFToken string `json:"csrf_token"`
	}
	if !readSubmission(w, r, &body) {
		return
	}
	if !a.allow(w, r, "login:ip:"+clientIP(r), limitLoginPerIP, time.Minute) {
		return
	}

	var (
		outcome verifyOutcome
		out     loginOutcome
	)
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
		// A flow past its first factor holds a *second*-factor code; that
		// step has its own endpoint, and accepting its code here would
		// skip it.
		if fctx.PasswordOK {
			return storage.ErrFlowNotFound
		}
		// An unknown identifier left no code on the flow, so it lands on
		// the same "incorrect code" as a wrong guess.
		outcome, err = checkFactorCode(r.Context(), tx, f.ID, body.Code)
		if err != nil || outcome != verifyOK {
			return err
		}
		if fctx.AddressID == "" {
			outcome = verifyWrongCode
			return nil
		}
		if err := storage.MarkAddressVerified(r.Context(), tx, fctx.AddressID); err != nil {
			return err
		}
		return a.completeFirstFactor(r, tx, t, f, fctx.IdentityID, &out)
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
		a.respondLogin(w, r, t, flowID, &out)
	}
}
