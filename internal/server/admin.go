package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/adminkey"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// NewAdmin builds the platform admin handler. It runs on its own listener
// and is never routed through tenant hostnames. Health checks are open;
// everything under /admin/ needs an admin key carrying the capability
// that route names (#10).
func NewAdmin(pool *pgxpool.Pool, ring *adminkey.Keyring, baseDomain string, providers *oauth2.Providers) http.Handler {
	admin := &adminAPI{pool: pool, tenants: storage.NewTenantStore(pool), providers: providers, baseDomain: strings.ToLower(baseDomain)}

	api := adminRouter{mux: http.NewServeMux()}
	// The two routes that name no single tenant: createTenant checks the
	// slug in its body, listTenants filters what it returns.
	api.handleGlobal("POST /admin/tenants", adminkey.TenantsCreate, admin.createTenant)
	api.handleGlobal("GET /admin/tenants", adminkey.TenantsRead, admin.listTenants)

	api.handle("GET /admin/tenants/{slug}", adminkey.TenantsRead, admin.getTenant)
	api.handle("PATCH /admin/tenants/{slug}", adminkey.TenantsUpdate, admin.updateTenant)
	// A purge additionally demands tenants:purge, asked for inside the
	// handler: one route, two levels of risk.
	api.handle("DELETE /admin/tenants/{slug}", adminkey.TenantsDisable, admin.deleteTenant)
	api.handle("POST /admin/tenants/{slug}/enable", adminkey.TenantsDisable, admin.enableTenant)
	api.handle("POST /admin/tenants/{slug}/clients", adminkey.ClientsCreate, admin.createClient)
	api.handle("GET /admin/tenants/{slug}/clients", adminkey.ClientsRead, admin.listClients)
	api.handle("PATCH /admin/tenants/{slug}/clients/{id}", adminkey.ClientsUpdate, admin.updateClient)
	api.handle("POST /admin/tenants/{slug}/clients/{id}/rotate-secret", adminkey.ClientsRotateSecret, admin.rotateClientSecret)
	api.handle("DELETE /admin/tenants/{slug}/clients/{id}", adminkey.ClientsDelete, admin.deleteClient)
	api.handle("GET /admin/tenants/{slug}/identities/{id}/sessions", adminkey.SessionsRead, admin.listIdentitySessions)
	api.handle("DELETE /admin/tenants/{slug}/identities/{id}/sessions", adminkey.SessionsRevoke, admin.revokeIdentitySessions)
	api.handle("POST /admin/tenants/{slug}/keys/rotate", adminkey.KeysRotate, admin.rotateKey)
	api.handle("GET /admin/tenants/{slug}/keys", adminkey.KeysRead, admin.listKeys)
	api.handle("DELETE /admin/tenants/{slug}/keys/{kid}", adminkey.KeysDelete, admin.deleteKey)
	api.handle("GET /admin/tenants/{slug}/schemas", adminkey.SchemasRead, admin.listSchemas)
	api.handle("GET /admin/tenants/{slug}/schemas/{name}", adminkey.SchemasRead, admin.getSchema)
	api.handle("PUT /admin/tenants/{slug}/schemas/{name}", adminkey.SchemasWrite, admin.putSchema)
	api.handle("PUT /admin/tenants/{slug}/social/{provider}", adminkey.SocialWrite, admin.putSocialProvider)
	api.handle("GET /admin/tenants/{slug}/social", adminkey.SocialRead, admin.listSocialProviders)
	api.handle("DELETE /admin/tenants/{slug}/social/{provider}", adminkey.SocialDelete, admin.deleteSocialProvider)
	api.handle("PUT /admin/tenants/{slug}/domains/{domain}", adminkey.DomainsWrite, admin.claimDomain)
	api.handle("GET /admin/tenants/{slug}/domains", adminkey.DomainsRead, admin.listDomains)
	api.handle("DELETE /admin/tenants/{slug}/domains/{domain}", adminkey.DomainsDelete, admin.releaseDomain)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/alive", alive)
	mux.HandleFunc("GET /health/ready", ready(pool))
	mux.Handle("/admin/", requireAdminKey(ring, api.mux))
	return mux
}

type adminAPI struct {
	pool       *pgxpool.Pool
	tenants    *storage.TenantStore
	providers  *oauth2.Providers // nil when OAuth2 is disabled
	baseDomain string
}

// slugPattern mirrors the CHECK constraint on tenants.slug; slugs become
// subdomain labels, so DNS rules apply.
var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// validateTenantConfig checks a whole tenant policy, whether it arrived
// as a create body or as the result of applying a patch — so the two
// paths cannot accept different things. Returns the message to answer
// with, or "" when the policy is good.
func validateTenantConfig(cfg tenant.Config) string {
	switch cfg.Verification {
	case "", tenant.VerificationRequired, tenant.VerificationDeferred:
	default:
		return `verification must be "required" or "deferred"`
	}
	if ml := cfg.Password.MinLength; ml != 0 && (ml < 8 || ml > password.MaxLength) {
		return fmt.Sprintf("password.min_length must be between 8 and %d", password.MaxLength)
	}
	if cfg.SMSDailyCap < 0 || cfg.SMSDailyCap > 1_000_000 {
		return "sms_daily_cap must be between 0 and 1000000"
	}
	if n := cfg.LoginThrottle.MaxAttempts; n < 0 || n > 1_000_000 {
		return "login_throttle.max_attempts must be between 0 and 1000000"
	}
	// A throttle is a short-term brute-force control; anything measured
	// in hours is account lockout, which is a different feature. The
	// ceiling is low enough to catch the typo that motivates it — a
	// window meant as 60 seconds written as 60000 milliseconds, which
	// would otherwise lock an identifier out for most of a day.
	if s := cfg.LoginThrottle.WindowSeconds; s < 0 || s > 3_600 {
		return "login_throttle.window_seconds must be between 0 and 3600"
	}
	switch cfg.MFA {
	case "", tenant.MFAOff, tenant.MFAOptional, tenant.MFARequired:
	default:
		return `mfa must be "off", "optional", or "required"`
	}
	if !validFirstFactor(cfg.FirstFactor) {
		return `first_factor must be a non-repeating subset of ["password", "code"]`
	}
	screens := []string{
		cfg.LoginURL, cfg.SocialReturnURL,
		cfg.UI.LoginURL, cfg.UI.RegistrationURL, cfg.UI.RecoveryURL,
		cfg.UI.VerificationURL, cfg.UI.ErrorURL, cfg.UI.DefaultReturnURL,
	}
	screens = append(screens, cfg.UI.AllowedReturnURLs...)
	for _, raw := range screens {
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err != nil || !u.IsAbs() {
			return "ui screen URLs must be absolute URLs"
		}
	}
	return ""
}

// validFirstFactor accepts an empty list (the default, passwords only)
// or any non-repeating subset of the known first factors.
func validFirstFactor(methods []string) bool {
	seen := make(map[string]bool, len(methods))
	for _, m := range methods {
		switch m {
		case tenant.FirstFactorPassword, tenant.FirstFactorCode:
		default:
			return false
		}
		if seen[m] {
			return false
		}
		seen[m] = true
	}
	return true
}

func (a *adminAPI) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug          string                     `json:"slug"`
		Name          string                     `json:"name"`
		Verification  string                     `json:"verification"`
		Password      tenant.PasswordConfig      `json:"password"`
		SMSDailyCap   int                        `json:"sms_daily_cap"`
		MFA           string                     `json:"mfa"`
		FirstFactor   []string                   `json:"first_factor"`
		UI            tenant.UIConfig            `json:"ui"`
		LoginThrottle tenant.LoginThrottleConfig `json:"login_throttle"`
		LoginURL      string                     `json:"login_url"`
		SocialReturn  string                     `json:"social_return_url"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if len(body.Slug) > 63 || !slugPattern.MatchString(body.Slug) {
		writeError(w, http.StatusBadRequest,
			"slug must be a valid DNS label: lowercase letters, digits, and inner hyphens, at most 63 characters")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// The tenant this request touches is the one it is about to make, so
	// its scope can only be checked now, against the slug in the body.
	if !a.require(w, r, adminkey.TenantsCreate, body.Slug) {
		return
	}
	cfg := tenant.Config{
		Verification:    body.Verification,
		Password:        body.Password,
		SMSDailyCap:     body.SMSDailyCap,
		MFA:             body.MFA,
		FirstFactor:     body.FirstFactor,
		UI:              body.UI,
		LoginThrottle:   body.LoginThrottle,
		LoginURL:        body.LoginURL,
		SocialReturnURL: body.SocialReturn,
	}
	if msg := validateTenantConfig(cfg); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	t, err := a.tenants.Create(r.Context(), body.Slug, body.Name, cfg, []byte(identity.DefaultSchemaJSON))
	if errors.Is(err, tenant.ErrSlugTaken) {
		// A slug held by a disabled tenant is a different situation from
		// one in live use, and the caller can act on the difference:
		// enable that tenant rather than go looking for another name.
		msg := "slug already in use"
		if held, ferr := a.tenants.FindBySlugIncludingDisabled(r.Context(), body.Slug); ferr == nil && held.Disabled() {
			msg = "slug is held by a disabled tenant; enable it or choose another slug"
		}
		writeError(w, http.StatusConflict, msg)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

// updateTenant edits one tenant's name and policy. Absent keys are left
// alone — an operator flipping one policy must not have to resend the
// whole config and risk wiping another. A key that is present replaces
// its value outright, nested blocks (`password`, `ui`) included.
func (a *adminAPI) updateTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          *string                     `json:"name"`
		Verification  *string                     `json:"verification"`
		Password      *tenant.PasswordConfig      `json:"password"`
		SMSDailyCap   *int                        `json:"sms_daily_cap"`
		MFA           *string                     `json:"mfa"`
		FirstFactor   *[]string                   `json:"first_factor"`
		UI            *tenant.UIConfig            `json:"ui"`
		LoginThrottle *tenant.LoginThrottleConfig `json:"login_throttle"`
		LoginURL      *string                     `json:"login_url"`
		SocialReturn  *string                     `json:"social_return_url"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Name != nil && *body.Name == "" {
		writeError(w, http.StatusBadRequest, "name cannot be emptied")
		return
	}

	var rejection string
	t, err := a.tenants.Update(r.Context(), r.PathValue("slug"), func(t *tenant.Tenant) error {
		if body.Name != nil {
			t.Name = *body.Name
		}
		cfg := t.Config
		if body.Verification != nil {
			cfg.Verification = *body.Verification
		}
		if body.Password != nil {
			cfg.Password = *body.Password
		}
		if body.SMSDailyCap != nil {
			cfg.SMSDailyCap = *body.SMSDailyCap
		}
		if body.MFA != nil {
			cfg.MFA = *body.MFA
		}
		if body.FirstFactor != nil {
			cfg.FirstFactor = *body.FirstFactor
		}
		if body.UI != nil {
			cfg.UI = *body.UI
		}
		if body.LoginThrottle != nil {
			cfg.LoginThrottle = *body.LoginThrottle
		}
		if body.LoginURL != nil {
			cfg.LoginURL = *body.LoginURL
		}
		if body.SocialReturn != nil {
			cfg.SocialReturnURL = *body.SocialReturn
		}
		// The patched policy is validated whole: a change is only ever
		// judged by what the tenant ends up with.
		if rejection = validateTenantConfig(cfg); rejection != "" {
			return errInvalidConfig
		}
		t.Config = cfg
		return nil
	})
	switch {
	case errors.Is(err, errInvalidConfig):
		writeError(w, http.StatusBadRequest, rejection)
	case errors.Is(err, tenant.ErrNotFound):
		writeError(w, http.StatusNotFound, "tenant not found")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, t)
	}
}

// errInvalidConfig unwinds the update transaction when the patched
// policy does not validate; the message travels beside it.
var errInvalidConfig = errors.New("invalid tenant config")

func (a *adminAPI) listTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := a.tenants.List(r.Context())
	if err != nil {
		internalError(w, err)
		return
	}
	// A tenant-restricted key sees its own tenants and no others: the
	// list of slugs is the list of customers, so an unfiltered listing
	// would leak exactly what the scope exists to hide.
	if g := grantsOf(r); g.TenantRestricted() {
		visible := ts[:0]
		for _, t := range ts {
			if g.Allows(adminkey.TenantsRead, t.Slug) {
				visible = append(visible, t)
			}
		}
		ts = visible
	}
	if ts == nil {
		ts = []tenant.Tenant{}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (a *adminAPI) getTenant(w http.ResponseWriter, r *http.Request) {
	t, err := a.tenants.FindBySlugIncludingDisabled(r.Context(), r.PathValue("slug"))
	if errors.Is(err, tenant.ErrNotFound) {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// deleteTenant disables by default and destroys only when asked in so
// many words, because the two outcomes differ by the whole value of a
// customer's identity namespace (ADR 0008).
//
// Disabling is the soft delete: the tenant stops resolving from any
// hostname, so every public surface it had closes at once, while nothing
// it owns is destroyed and its slug stays held. Disabling an
// already-disabled tenant answers as the first call did, so a
// compensating saga can run twice without special-casing.
//
// ?purge=true is the irreversible one, and is refused unless the tenant
// is already disabled: the two-step is what keeps a wrong slug in a
// script from costing a customer their identities.
func (a *adminAPI) deleteTenant(w http.ResponseWriter, r *http.Request) {
	purge := false
	if raw := r.URL.Query().Get("purge"); raw != "" {
		var err error
		if purge, err = strconv.ParseBool(raw); err != nil {
			// Never guess which of the two was meant. Silently disabling
			// for a caller who typed a purge would report success for
			// work that did not happen.
			writeError(w, http.StatusBadRequest, "purge must be true or false")
			return
		}
	}
	if !purge {
		a.setTenantDisabled(w, r, true)
		return
	}

	slug := r.PathValue("slug")
	// Disabling is reversible and destroying is not, so they are not the
	// same permission even though they share a route.
	if !a.require(w, r, adminkey.TenantsPurge, slug) {
		return
	}
	switch err := a.tenants.Purge(r.Context(), slug); {
	case errors.Is(err, tenant.ErrNotFound):
		writeError(w, http.StatusNotFound, "tenant not found")
	case errors.Is(err, tenant.ErrNotDisabled):
		writeError(w, http.StatusConflict,
			"disable the tenant before purging it: DELETE /admin/tenants/"+slug)
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "purged", "slug": slug})
	}
}

// enableTenant reopens a disabled tenant, sessions and all: nothing was
// revoked, so the tenant comes back whole rather than signed out.
func (a *adminAPI) enableTenant(w http.ResponseWriter, r *http.Request) {
	a.setTenantDisabled(w, r, false)
}

func (a *adminAPI) setTenantDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	t, err := a.tenants.SetDisabled(r.Context(), r.PathValue("slug"), disabled)
	switch {
	case errors.Is(err, tenant.ErrNotFound):
		writeError(w, http.StatusNotFound, "tenant not found")
	case err != nil:
		internalError(w, err)
	default:
		// Drop the cached signing material either way: a closed tenant
		// should hold none, and a reopened one rebuilds from storage.
		if a.providers != nil {
			a.providers.Invalidate(t.ID)
		}
		writeJSON(w, http.StatusOK, t)
	}
}
