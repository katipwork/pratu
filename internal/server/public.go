// Package server assembles the two HTTP listeners: the public server,
// addressed via tenant hostnames, and the admin server, which must never
// be reachable through them.
package server

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/tenant"
)

// NewPublic builds the tenant-facing handler: self-service flows and
// OAuth2/OIDC endpoints will mount here, all resolved through the tenant
// Resolver. For now it serves health checks only.
func NewPublic(pool *pgxpool.Pool, resolver *tenant.Resolver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/alive", alive)
	mux.HandleFunc("GET /health/ready", ready(pool))
	return mux
}

func alive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func ready(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := pool.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"database unreachable"}`))
			return
		}
		w.Write([]byte(`{"status":"ok"}`))
	}
}
