package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/otp"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
)

// Recovery is a three-step flow: submit a recovery address (the response
// never reveals whether it exists), prove the delivered One-Time Code,
// then set a new password — which revokes every other session and issues
// a fresh one. A recovered address counts as verified: the code proved
// control of it.

func (a *publicAPI) submitRecoveryAddress(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "recovery:ip:"+clientIP(r), limitRecoveryPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Address string `json:"address"`
	}
	if !readJSON(w, r, &body) {
		return
	}

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindRecovery)
		if err != nil {
			return err
		}
		addr, identityID, err := storage.FindRecoveryAddress(r.Context(), tx, identity.Normalize(body.Address))
		if errors.Is(err, storage.ErrNoCredential) {
			return nil // unknown address: same response, nothing sent
		}
		if err != nil {
			return err
		}
		// A send-cap refusal must also stay indistinguishable from a
		// miss, so drop the send instead of surfacing a 429.
		if err := a.allowSend(r.Context(), t, addr.Channel, addr.Value); err != nil {
			var rl errRateLimited
			if errors.As(err, &rl) {
				a.log.Warn("recovery send suppressed by rate limit", "flow", f.ID)
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
		err = storage.UpdateFlowContext(r.Context(), tx, f.ID, flow.RecoveryContext{
			IdentityID: identityID,
			AddressID:  addr.ID,
		})
		if err != nil {
			return err
		}
		return storage.EnqueueMessage(r.Context(), tx, t.ID, addr.Channel, addr.Value, "recovery_code", map[string]string{
			"code":   code,
			"tenant": t.Name,
		})
	})
	if errors.Is(err, storage.ErrFlowNotFound) {
		writeError(w, http.StatusBadRequest, "recovery flow not found or expired")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"state":   "code_sent",
		"message": "if the address exists, a code was sent to it",
	})
}

func (a *publicAPI) submitRecoveryCode(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "recovery:ip:"+clientIP(r), limitRecoveryPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}

	var outcome verifyOutcome
	nextState := "set_password"
	var factorMethods []string
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindRecovery)
		if err != nil {
			return err
		}
		var fctx flow.RecoveryContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		code, err := storage.CodeForFlow(r.Context(), tx, f.ID)
		if errors.Is(err, storage.ErrNoCode) {
			// No address submitted (or it didn't exist): a wrong-code
			// answer, not a distinguishable one.
			outcome = verifyWrongCode
			return nil
		}
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
		fctx.CodeOK = true
		if err := storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx); err != nil {
			return err
		}
		// Recovery does not bypass an enrolled second factor.
		if !mfaHidden(t) {
			methods, err := enrolledFactors(r.Context(), tx, fctx.IdentityID)
			if err != nil {
				return err
			}
			if len(methods) > 0 {
				nextState = "second_factor_required"
				factorMethods = methods
			}
		}
		return nil
	})
	if errors.Is(err, storage.ErrFlowNotFound) {
		writeError(w, http.StatusBadRequest, "recovery flow not found or expired")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	switch outcome {
	case verifyTooManyAttempts:
		writeError(w, http.StatusBadRequest, "too many attempts; start recovery again")
	case verifyCodeExpired:
		writeError(w, http.StatusBadRequest, "code expired; start recovery again")
	case verifyWrongCode:
		writeError(w, http.StatusBadRequest, "incorrect code")
	default:
		resp := map[string]any{"state": nextState}
		if factorMethods != nil {
			resp["methods"] = factorMethods
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (a *publicAPI) submitRecoveryPassword(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "recovery:ip:"+clientIP(r), limitRecoveryPerIP, time.Minute) {
		return
	}
	flowID := r.URL.Query().Get("flow")

	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
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
		ident *identity.Identity
		sess  *session.Session
		token string
		aal   string
	)
	err = storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, flowID, flow.KindRecovery)
		if err != nil {
			return err
		}
		var fctx flow.RecoveryContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		if !fctx.CodeOK {
			return errRecoveryNotProven
		}
		aal = session.AAL1
		if !mfaHidden(t) {
			methods, err := enrolledFactors(r.Context(), tx, fctx.IdentityID)
			if err != nil {
				return err
			}
			if len(methods) > 0 {
				if !fctx.SecondFactorOK {
					return errSecondFactorRequired
				}
				aal = session.AAL2
			}
		}
		if err := storage.SetPasswordCredential(r.Context(), tx, t.ID, fctx.IdentityID, hash); err != nil {
			return err
		}
		if err := storage.MarkAddressVerified(r.Context(), tx, fctx.AddressID); err != nil {
			return err
		}
		if _, err := storage.RevokeSessions(r.Context(), tx, fctx.IdentityID); err != nil {
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
		sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, ident.ID, aal)
		return err
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		writeError(w, http.StatusBadRequest, "recovery flow not found or expired")
	case errors.Is(err, errRecoveryNotProven):
		writeError(w, http.StatusBadRequest, "recovery code not yet verified")
	case errors.Is(err, errSecondFactorRequired):
		writeError(w, http.StatusForbidden, "second factor required; prove it via /self-service/recovery/totp or /self-service/recovery/sms first")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"state":         "recovered",
			"identity":      ident,
			"session":       sess,
			"session_token": token,
		})
	}
}

var (
	errRecoveryNotProven    = errors.New("recovery code not verified")
	errSecondFactorRequired = errors.New("second factor required")
)
