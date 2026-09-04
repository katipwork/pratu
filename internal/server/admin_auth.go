package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/katipwork/pratu/internal/adminkey"
)

// Admin authorization (#10). Two rules carry the whole design:
//
//   - Every route names its capability at registration, so a route
//     cannot exist without one. There is no path-matching middleware to
//     fall out of step with the route table.
//   - A route whose pattern carries {slug} has its tenant scope checked
//     for it. A route without one must be registered through
//     handleGlobal, whose name says the handler owns that decision.
//
// Both are enforced when the handler is built, so a mistake is a panic
// at startup rather than a permission that quietly does not apply.

type grantsKey struct{}

func withGrants(ctx context.Context, g adminkey.Grants) context.Context {
	return context.WithValue(ctx, grantsKey{}, g)
}

// grantsOf returns the authenticated caller's grants. The zero value
// grants nothing, so a request that somehow bypassed authentication is
// refused rather than waved through.
func grantsOf(r *http.Request) adminkey.Grants {
	g, _ := r.Context().Value(grantsKey{}).(adminkey.Grants)
	return g
}

// adminRouter registers admin routes, each with the capability it needs.
type adminRouter struct{ mux *http.ServeMux }

// handle registers a tenant-scoped route. The pattern must carry {slug}:
// the tenant it names is checked against the key's scope automatically,
// so a new route is confined without its author having to remember.
func (rt adminRouter) handle(pattern string, c adminkey.Capability, h http.HandlerFunc) {
	if !strings.Contains(pattern, "{slug}") {
		panic("adminRouter.handle: " + pattern + " has no {slug}; use handleGlobal")
	}
	rt.mux.HandleFunc(pattern, guard(c, true, h))
}

// handleGlobal registers a route that names no single tenant in its
// path. The capability is still enforced; confining the request to the
// key's tenants is the handler's job, because only it can work out which
// tenants the request touches.
func (rt adminRouter) handleGlobal(pattern string, c adminkey.Capability, h http.HandlerFunc) {
	if strings.Contains(pattern, "{slug}") {
		panic("adminRouter.handleGlobal: " + pattern + " carries {slug}; use handle")
	}
	rt.mux.HandleFunc(pattern, guard(c, false, h))
}

func guard(c adminkey.Capability, scoped bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g := grantsOf(r)
		// An unscoped route checks the capability only. Asking about the
		// tenant here would answer "no" for every restricted key, since
		// the request has not yet said which tenant it means — refusing a
		// provisioner the very creation its pattern exists to allow.
		ok := g.AllowsCapability(c)
		if scoped {
			ok = g.Allows(c, r.PathValue("slug"))
		}
		if !ok {
			forbid(w, c)
			return
		}
		h(w, r)
	}
}

// require is the extra check a handler makes when one route covers two
// levels of risk — disabling a tenant versus destroying it — or when the
// tenant is known only after the body is read.
func (a *adminAPI) require(w http.ResponseWriter, r *http.Request, c adminkey.Capability, slug string) bool {
	if grantsOf(r).Allows(c, slug) {
		return true
	}
	forbid(w, c)
	return false
}

// forbid names the capability that was missing. The caller holds a valid
// key, so telling it which permission it lacks reveals nothing it could
// not learn by trying, and saves an operator guessing.
func forbid(w http.ResponseWriter, c adminkey.Capability) {
	writeError(w, http.StatusForbidden, "this admin key lacks the capability "+string(c))
}

// requireAdminKey authenticates the bearer token and attaches its grants.
// Authorization is per route from there; this only establishes who is
// asking.
func requireAdminKey(ring *adminkey.Keyring, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ring.Empty() {
			writeError(w, http.StatusServiceUnavailable, "admin API disabled: no admin key configured")
			return
		}
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		grants, ok := ring.Lookup(presented)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(withGrants(r.Context(), grants)))
	})
}
