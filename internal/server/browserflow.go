package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Browser Flows drive HTML clients by redirect (ADR 0006): a client that
// prefers text/html — or posts an HTML form — is sent to the tenant's own
// screens and never shown raw JSON, while a client that asks for JSON
// keeps the unchanged contract. API flows never redirect.

// referenceUIScreen backs every screen for a tenant that configured
// none, when the server serves the reference UI. It reads ?flow= and
// ?code= the same way a tenant's own UI would.
const referenceUIScreen = "/ui/"

// Codes handed to the error screen. They name failures that have no flow
// left to return to.
const (
	errCodeFlowExpired   = "flow_expired"
	errCodeCSRF          = "csrf_violation"
	errCodeRateLimited   = "rate_limited"
	errCodeInternal      = "internal_error"
	errCodeUnknownSchema = "unknown_schema"
)

// wantsHTML reports whether this request should be driven by redirects.
// A form post is an HTML client by construction; otherwise the Accept
// header decides, and anything that does not ask for HTML (including the
// bare */* that fetch sends) keeps JSON.
func wantsHTML(r *http.Request) bool {
	if isFormSubmission(r) {
		return true
	}
	var htmlQ, jsonQ float64
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		media, q := parseAcceptPart(part)
		switch media {
		case "text/html", "application/xhtml+xml":
			if q > htmlQ {
				htmlQ = q
			}
		case "application/json":
			if q > jsonQ {
				jsonQ = q
			}
		}
	}
	return htmlQ > 0 && htmlQ >= jsonQ
}

func parseAcceptPart(part string) (media string, q float64) {
	q = 1
	fields := strings.Split(strings.TrimSpace(part), ";")
	media = strings.ToLower(strings.TrimSpace(fields[0]))
	for _, p := range fields[1:] {
		name, value, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || strings.TrimSpace(name) != "q" {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			q = v
		}
	}
	return media, q
}

// screenURL is the tenant's screen for a flow kind, falling back to the
// reference UI when the tenant configured none.
func (a *publicAPI) screenURL(t *tenant.Tenant, kind flow.Kind) string {
	var u string
	switch kind {
	case flow.KindLogin:
		u = t.Config.EffectiveLoginUIURL()
	case flow.KindRegistration:
		u = t.Config.EffectiveRegistrationUIURL()
	case flow.KindRecovery:
		u = t.Config.EffectiveRecoveryUIURL()
	case flow.KindVerification:
		u = t.Config.EffectiveVerificationUIURL()
	}
	if u == "" {
		u = a.defaultScreen()
	}
	return u
}

// errorScreenURL is where failures with no flow to return to land. A
// tenant that configured a login screen but no error screen keeps the
// browser inside its own UI rather than jumping to the reference one.
func (a *publicAPI) errorScreenURL(t *tenant.Tenant) string {
	if u := t.Config.EffectiveErrorUIURL(); u != "" {
		return u
	}
	if u := t.Config.EffectiveLoginUIURL(); u != "" {
		return u
	}
	return a.defaultScreen()
}

func (a *publicAPI) defaultScreen() string {
	if a.referenceUI {
		return referenceUIScreen
	}
	return ""
}

// returnTarget is where a completed browser flow sends the browser.
func (a *publicAPI) returnTarget(t *tenant.Tenant, flowReturnTo string) string {
	if flowReturnTo != "" {
		return flowReturnTo
	}
	if u := t.Config.EffectiveDefaultReturnURL(); u != "" {
		return u
	}
	return a.defaultScreen()
}

// validateReturnTo checks a client-supplied return_to against the
// tenant's allow-list: same-origin paths always pass, absolute URLs must
// share an origin with a configured screen or match an explicitly
// allowed prefix. Anything else is an open redirect.
func validateReturnTo(t *tenant.Tenant, r *http.Request, raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if !u.IsAbs() {
		// Root-relative paths stay on the tenant's own host.
		if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
			return raw, true
		}
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return raw, true
	}
	for _, screen := range t.Config.UIScreenURLs() {
		s, err := url.Parse(screen)
		if err != nil || !s.IsAbs() {
			continue
		}
		if strings.EqualFold(s.Scheme, u.Scheme) && strings.EqualFold(s.Host, u.Host) {
			return raw, true
		}
	}
	for _, allowed := range t.Config.UI.AllowedReturnURLs {
		a, err := url.Parse(allowed)
		if err != nil || !a.IsAbs() {
			continue
		}
		if !strings.EqualFold(a.Scheme, u.Scheme) || !strings.EqualFold(a.Host, u.Host) {
			continue
		}
		if a.Path == "" || a.Path == "/" || strings.HasPrefix(u.Path, strings.TrimSuffix(a.Path, "/")) {
			return raw, true
		}
	}
	return "", false
}

// redirectToScreen sends an HTML client to a flow's screen. It reports
// whether it answered the request.
func (a *publicAPI) redirectToScreen(w http.ResponseWriter, r *http.Request, t *tenant.Tenant, kind flow.Kind, flowID string) bool {
	if !wantsHTML(r) {
		return false
	}
	screen := a.screenURL(t, kind)
	if screen == "" {
		return false
	}
	http.Redirect(w, r, withParam(screen, "flow", flowID), http.StatusSeeOther)
	return true
}

// redirectToError sends an HTML client to the error screen with a code
// naming what went wrong.
func (a *publicAPI) redirectToError(w http.ResponseWriter, r *http.Request, t *tenant.Tenant, code string) bool {
	if !wantsHTML(r) {
		return false
	}
	screen := a.errorScreenURL(t)
	if screen == "" {
		return false
	}
	http.Redirect(w, r, withParam(screen, "code", code), http.StatusSeeOther)
	return true
}

// redirectAfterSuccess lands a completed browser flow.
func (a *publicAPI) redirectAfterSuccess(w http.ResponseWriter, r *http.Request, t *tenant.Tenant, flowReturnTo string) bool {
	if !wantsHTML(r) {
		return false
	}
	target := a.returnTarget(t, flowReturnTo)
	if target == "" {
		return false
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
	return true
}

// failSubmission answers a recoverable submission failure: the flow
// survives, so an HTML client goes back to its screen with the message
// persisted on the flow for the UI to render, while everyone else gets
// the JSON error unchanged.
func (a *publicAPI) failSubmission(w http.ResponseWriter, r *http.Request, t *tenant.Tenant,
	kind flow.Kind, flowID string, status int, message string, details ...string) {

	if a.redirectFailure(w, r, t, kind, flowID, message, details) {
		return
	}
	writeError(w, status, message, details...)
}

// failFatal answers a failure with no flow to go back to: HTML clients
// land on the error screen with a code naming it.
func (a *publicAPI) failFatal(w http.ResponseWriter, r *http.Request, t *tenant.Tenant,
	code string, status int, message string) {

	if a.redirectToError(w, r, t, code) {
		return
	}
	writeError(w, status, message)
}

// redirectFailure persists the failure onto the flow and redirects,
// reporting whether it answered the request. API flows and JSON clients
// are left to the caller.
func (a *publicAPI) redirectFailure(w http.ResponseWriter, r *http.Request, t *tenant.Tenant,
	kind flow.Kind, flowID, message string, details []string) bool {

	if !wantsHTML(r) || flowID == "" {
		return false
	}
	screen := a.screenURL(t, kind)
	if screen == "" {
		return false
	}
	// The submission's own transaction has rolled back by now, taking any
	// write it made with it; the messages need a transaction of their own.
	// The flow is re-read there to keep the step it was waiting on, and to
	// learn whether it is a browser flow at all.
	var browser bool
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.FlowByID(r.Context(), tx, flowID)
		if errors.Is(err, storage.ErrFlowNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !f.Browser {
			return nil
		}
		browser = true
		return storage.SetFlowUI(r.Context(), tx, f.ID, f.State, []flow.Message{{
			Type: flow.MessageError, Text: message, Details: details,
		}})
	})
	if err != nil {
		logError(err)
		return a.redirectToError(w, r, t, errCodeInternal)
	}
	if !browser {
		return false
	}
	http.Redirect(w, r, withParam(screen, "flow", flowID), http.StatusSeeOther)
	return true
}

// advanceFlow records the step a flow has moved on to, plus anything its
// screen should say about the move. Best-effort: the step is a rendering
// hint, so a failure to record it must not fail the request that
// succeeded.
func (a *publicAPI) advanceFlow(r *http.Request, t *tenant.Tenant, flowID, state string, msgs ...flow.Message) {
	if flowID == "" {
		return
	}
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		return storage.SetFlowUI(r.Context(), tx, flowID, state, msgs)
	})
	if err != nil {
		logError(err)
	}
}

// readFlow lets a UI that landed on its screen re-read the flow: which
// step it waits on, what to render, and why the last submission failed.
// A browser flow is readable only by the browser that created it.
func (a *publicAPI) readFlow(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	id := r.PathValue("id")

	var resp flowResponse
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.FlowByID(r.Context(), tx, id)
		if err != nil {
			return err
		}
		// API flows hold their state client-side and carry no cookie to
		// prove ownership with; they have nothing to read here.
		if !f.Browser || f.CSRFFingerprint == "" ||
			f.CSRFFingerprint != csrfFingerprint(csrfSecret(r)) {
			return storage.ErrFlowNotFound
		}
		resp.Flow = *f
		resp.CSRFToken = csrfToken(csrfSecret(r), f.ID)
		resp.UI.Fields, resp.UI.Methods, err = flowUI(r.Context(), tx, f)
		return err
	})
	if errors.Is(err, storage.ErrFlowNotFound) {
		writeError(w, http.StatusNotFound, "flow not found or expired")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// flowUI derives what a flow's screen should render from its kind and
// the step it waits on.
func flowUI(ctx context.Context, tx pgx.Tx, f *flow.Flow) ([]identity.Field, []string, error) {
	codeField := []identity.Field{{Name: "code", Type: "text", Title: "Code", Required: true}}

	switch f.Kind {
	case flow.KindRegistration:
		var fctx flow.RegistrationContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return nil, nil, err
		}
		var (
			schema *identity.Schema
			err    error
		)
		if fctx.SchemaID != "" {
			schema, err = storage.SchemaByID(ctx, tx, fctx.SchemaID)
		} else {
			schema, err = storage.CurrentSchema(ctx, tx, "default")
		}
		if err != nil {
			return nil, nil, err
		}
		fields := append([]identity.Field(nil), schema.Fields()...)
		return append(fields,
			identity.Field{Name: "password", Type: "password", Title: "Password", Required: true}), nil, nil

	case flow.KindVerification:
		return codeField, nil, nil

	case flow.KindRecovery:
		var fctx flow.RecoveryContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return nil, nil, err
		}
		switch f.State {
		case flow.StateCodeRequired:
			return codeField, nil, nil
		case flow.StateSecondFactorRequired:
			methods, err := enrolledFactors(ctx, tx, fctx.IdentityID)
			return codeField, methods, err
		case flow.StatePasswordRequired:
			return []identity.Field{
				{Name: "password", Type: "password", Title: "New password", Required: true},
			}, nil, nil
		}
		return []identity.Field{
			{Name: "address", Type: "text", Title: "Recovery address", Required: true},
		}, nil, nil

	case flow.KindLogin:
		if f.State == flow.StateMFARequired {
			var fctx flow.LoginContext
			if err := json.Unmarshal(f.Context, &fctx); err != nil {
				return nil, nil, err
			}
			methods, err := enrolledFactors(ctx, tx, fctx.IdentityID)
			return codeField, methods, err
		}
		return []identity.Field{
			{Name: "identifier", Type: "text", Title: "Email", Required: true},
			{Name: "password", Type: "password", Title: "Password", Required: true},
		}, nil, nil
	}
	return nil, nil, nil
}
