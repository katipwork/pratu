package server

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Custom domain management (ADR 0003). Claiming here only routes the
// hostname; DNS (CNAME to the deployment) and TLS termination for the
// domain belong to the fronting proxy.

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$`)

// tenantBySlug is an admin lookup, so it sees disabled tenants too
// (ADR 0008).
func (a *adminAPI) tenantBySlug(w http.ResponseWriter, r *http.Request) *tenant.Tenant {
	t, err := a.tenants.FindBySlugIncludingDisabled(r.Context(), r.PathValue("slug"))
	if errors.Is(err, tenant.ErrNotFound) {
		writeError(w, http.StatusNotFound, "tenant not found")
		return nil
	}
	if err != nil {
		internalError(w, err)
		return nil
	}
	return t
}

func (a *adminAPI) claimDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(r.PathValue("domain"))
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		writeError(w, http.StatusBadRequest, "not a valid domain name")
		return
	}
	if domain == a.baseDomain || strings.HasSuffix(domain, "."+a.baseDomain) {
		writeError(w, http.StatusBadRequest,
			"domains under the base domain are addressed by tenant slug, not claimed")
		return
	}
	t := a.tenantBySlug(w, r)
	if t == nil {
		return
	}
	err := a.tenants.ClaimDomain(r.Context(), t.ID, domain)
	switch {
	case errors.Is(err, storage.ErrDomainTaken):
		writeError(w, http.StatusConflict, "domain is claimed by another tenant")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "claimed", "domain": domain})
	}
}

func (a *adminAPI) listDomains(w http.ResponseWriter, r *http.Request) {
	t := a.tenantBySlug(w, r)
	if t == nil {
		return
	}
	domains, err := a.tenants.ListDomains(r.Context(), t.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	if domains == nil {
		domains = []storage.TenantDomain{}
	}
	writeJSON(w, http.StatusOK, domains)
}

func (a *adminAPI) releaseDomain(w http.ResponseWriter, r *http.Request) {
	t := a.tenantBySlug(w, r)
	if t == nil {
		return
	}
	ok, err := a.tenants.ReleaseDomain(r.Context(), t.ID, strings.ToLower(r.PathValue("domain")))
	if err != nil {
		internalError(w, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "domain not claimed by this tenant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "released"})
}
