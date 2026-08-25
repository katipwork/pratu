package server

import (
	"crypto/subtle"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewAdmin builds the platform admin handler. It runs on its own listener
// and is never routed through tenant hostnames. Health checks are open;
// everything under /admin/ requires the root API key.
func NewAdmin(pool *pgxpool.Pool, rootKey string) http.Handler {
	api := http.NewServeMux() // tenant, schema, and OAuth2 client management mount here

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/alive", alive)
	mux.HandleFunc("GET /health/ready", ready(pool))
	mux.Handle("/admin/", requireRootKey(rootKey, api))
	return mux
}

func requireRootKey(rootKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rootKey == "" {
			http.Error(w, "admin API disabled: no root key configured", http.StatusServiceUnavailable)
			return
		}
		got := r.Header.Get("Authorization")
		want := "Bearer " + rootKey
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
