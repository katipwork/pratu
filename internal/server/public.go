// Package server assembles the two HTTP listeners: the public server,
// addressed via tenant hostnames, and the admin server, which must never
// be reachable through them.
package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/tenant"
)

type ctxKey int

const tenantKey ctxKey = 0

func requestTenant(r *http.Request) *tenant.Tenant {
	return r.Context().Value(tenantKey).(*tenant.Tenant)
}

// NewPublic builds the tenant-facing handler. Health checks are
// tenant-agnostic; everything else resolves the tenant from the Host
// header first.
func NewPublic(pool *pgxpool.Pool, resolver *tenant.Resolver) http.Handler {
	api := &publicAPI{pool: pool}

	tenanted := http.NewServeMux()
	tenanted.HandleFunc("POST /self-service/registration/api", api.createFlowHandler(flow.KindRegistration))
	tenanted.HandleFunc("POST /self-service/registration", api.submitRegistration)
	tenanted.HandleFunc("POST /self-service/login/api", api.createFlowHandler(flow.KindLogin))
	tenanted.HandleFunc("POST /self-service/login", api.submitLogin)
	tenanted.HandleFunc("GET /sessions/whoami", api.whoami)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/alive", alive)
	mux.HandleFunc("GET /health/ready", ready(pool))
	mux.Handle("/", resolveTenant(resolver, tenanted))
	return mux
}

func resolveTenant(resolver *tenant.Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, err := resolver.Resolve(r.Context(), r.Host)
		if errors.Is(err, tenant.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown tenant")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "tenant resolution failed")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey, t)))
	})
}

func alive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func ready(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unreachable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
