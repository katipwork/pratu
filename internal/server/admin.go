package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// NewAdmin builds the platform admin handler. It runs on its own listener
// and is never routed through tenant hostnames. Health checks are open;
// everything under /admin/ requires the root API key.
func NewAdmin(pool *pgxpool.Pool, rootKey, baseDomain string, providers *oauth2.Providers) http.Handler {
	admin := &adminAPI{pool: pool, tenants: storage.NewTenantStore(pool), providers: providers, baseDomain: strings.ToLower(baseDomain)}

	api := http.NewServeMux()
	api.HandleFunc("POST /admin/tenants", admin.createTenant)
	api.HandleFunc("GET /admin/tenants", admin.listTenants)
	api.HandleFunc("GET /admin/tenants/{slug}", admin.getTenant)
	api.HandleFunc("PATCH /admin/tenants/{slug}", admin.updateTenant)
	api.HandleFunc("POST /admin/tenants/{slug}/clients", admin.createClient)
	api.HandleFunc("GET /admin/tenants/{slug}/clients", admin.listClients)
	api.HandleFunc("DELETE /admin/tenants/{slug}/clients/{id}", admin.deleteClient)
	api.HandleFunc("GET /admin/tenants/{slug}/identities/{id}/sessions", admin.listIdentitySessions)
	api.HandleFunc("DELETE /admin/tenants/{slug}/identities/{id}/sessions", admin.revokeIdentitySessions)
	api.HandleFunc("POST /admin/tenants/{slug}/keys/rotate", admin.rotateKey)
	api.HandleFunc("GET /admin/tenants/{slug}/keys", admin.listKeys)
	api.HandleFunc("DELETE /admin/tenants/{slug}/keys/{kid}", admin.deleteKey)
	api.HandleFunc("GET /admin/tenants/{slug}/schemas", admin.listSchemas)
	api.HandleFunc("GET /admin/tenants/{slug}/schemas/{name}", admin.getSchema)
	api.HandleFunc("PUT /admin/tenants/{slug}/schemas/{name}", admin.putSchema)
	api.HandleFunc("PUT /admin/tenants/{slug}/social/{provider}", admin.putSocialProvider)
	api.HandleFunc("GET /admin/tenants/{slug}/social", admin.listSocialProviders)
	api.HandleFunc("DELETE /admin/tenants/{slug}/social/{provider}", admin.deleteSocialProvider)
	api.HandleFunc("PUT /admin/tenants/{slug}/domains/{domain}", admin.claimDomain)
	api.HandleFunc("GET /admin/tenants/{slug}/domains", admin.listDomains)
	api.HandleFunc("DELETE /admin/tenants/{slug}/domains/{domain}", admin.releaseDomain)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/alive", alive)
	mux.HandleFunc("GET /health/ready", ready(pool))
	mux.Handle("/admin/", requireRootKey(rootKey, api))
	return mux
}

func requireRootKey(rootKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rootKey == "" {
			writeError(w, http.StatusServiceUnavailable, "admin API disabled: no root key configured")
			return
		}
		got := r.Header.Get("Authorization")
		want := "Bearer " + rootKey
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
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
		Slug         string                `json:"slug"`
		Name         string                `json:"name"`
		Verification string                `json:"verification"`
		Password     tenant.PasswordConfig `json:"password"`
		SMSDailyCap  int                   `json:"sms_daily_cap"`
		MFA          string                `json:"mfa"`
		FirstFactor  []string              `json:"first_factor"`
		UI           tenant.UIConfig       `json:"ui"`
		LoginURL     string                `json:"login_url"`
		SocialReturn string                `json:"social_return_url"`
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
	cfg := tenant.Config{
		Verification:    body.Verification,
		Password:        body.Password,
		SMSDailyCap:     body.SMSDailyCap,
		MFA:             body.MFA,
		FirstFactor:     body.FirstFactor,
		UI:              body.UI,
		LoginURL:        body.LoginURL,
		SocialReturnURL: body.SocialReturn,
	}
	if msg := validateTenantConfig(cfg); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	t, err := a.tenants.Create(r.Context(), body.Slug, body.Name, cfg, []byte(identity.DefaultSchemaJSON))
	if errors.Is(err, tenant.ErrSlugTaken) {
		writeError(w, http.StatusConflict, "slug already in use")
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
		Name         *string                `json:"name"`
		Verification *string                `json:"verification"`
		Password     *tenant.PasswordConfig `json:"password"`
		SMSDailyCap  *int                   `json:"sms_daily_cap"`
		MFA          *string                `json:"mfa"`
		FirstFactor  *[]string              `json:"first_factor"`
		UI           *tenant.UIConfig       `json:"ui"`
		LoginURL     *string                `json:"login_url"`
		SocialReturn *string                `json:"social_return_url"`
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
	if ts == nil {
		ts = []tenant.Tenant{}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (a *adminAPI) getTenant(w http.ResponseWriter, r *http.Request) {
	t, err := a.tenants.FindBySlug(r.Context(), r.PathValue("slug"))
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
