package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// NewAdmin builds the platform admin handler. It runs on its own listener
// and is never routed through tenant hostnames. Health checks are open;
// everything under /admin/ requires the root API key.
func NewAdmin(pool *pgxpool.Pool, rootKey string) http.Handler {
	admin := &adminAPI{tenants: storage.NewTenantStore(pool)}

	api := http.NewServeMux()
	api.HandleFunc("POST /admin/tenants", admin.createTenant)
	api.HandleFunc("GET /admin/tenants", admin.listTenants)
	api.HandleFunc("GET /admin/tenants/{slug}", admin.getTenant)

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
	tenants *storage.TenantStore
}

// slugPattern mirrors the CHECK constraint on tenants.slug; slugs become
// subdomain labels, so DNS rules apply.
var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

func (a *adminAPI) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug         string                `json:"slug"`
		Name         string                `json:"name"`
		Verification string                `json:"verification"`
		Password     tenant.PasswordConfig `json:"password"`
		SMSDailyCap  int                   `json:"sms_daily_cap"`
		MFA          string                `json:"mfa"`
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
	switch body.Verification {
	case "", tenant.VerificationRequired, tenant.VerificationDeferred:
	default:
		writeError(w, http.StatusBadRequest, `verification must be "required" or "deferred"`)
		return
	}
	if ml := body.Password.MinLength; ml != 0 && (ml < 8 || ml > password.MaxLength) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("password.min_length must be between 8 and %d", password.MaxLength))
		return
	}

	if body.SMSDailyCap < 0 || body.SMSDailyCap > 1_000_000 {
		writeError(w, http.StatusBadRequest, "sms_daily_cap must be between 0 and 1000000")
		return
	}
	switch body.MFA {
	case "", tenant.MFAOff, tenant.MFAOptional, tenant.MFARequired:
	default:
		writeError(w, http.StatusBadRequest, `mfa must be "off", "optional", or "required"`)
		return
	}

	cfg := tenant.Config{
		Verification: body.Verification,
		Password:     body.Password,
		SMSDailyCap:  body.SMSDailyCap,
		MFA:          body.MFA,
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
