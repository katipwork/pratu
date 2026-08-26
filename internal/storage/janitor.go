package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CleanupExpired removes dead rows across all tenants: expired flows
// (their one-time codes cascade), expired sessions, spent OAuth2 protocol
// rows, and delivered/abandoned courier messages past their audit window.
// It runs on the pool: the janitor_expired RLS policies permit exactly
// these deletes and nothing more.
func CleanupExpired(ctx context.Context, pool *pgxpool.Pool) (map[string]int64, error) {
	stmts := []struct {
		name string
		sql  string
	}{
		{"flows", `DELETE FROM flows WHERE expires_at <= now()`},
		{"sessions", `DELETE FROM sessions WHERE expires_at <= now()`},
		{"one_time_codes", `DELETE FROM one_time_codes WHERE expires_at <= now()`},
		{"oauth2_sessions", `DELETE FROM oauth2_sessions WHERE
			(kind IN ('code', 'pkce', 'oidc', 'access') AND created_at < now() - interval '1 day')
			OR created_at < now() - interval '31 days'`},
		{"courier_messages", `DELETE FROM courier_messages WHERE status <> 'pending' AND created_at < now() - interval '30 days'`},
	}
	deleted := make(map[string]int64, len(stmts))
	for _, s := range stmts {
		tag, err := pool.Exec(ctx, s.sql)
		if err != nil {
			return deleted, fmt.Errorf("janitor %s: %w", s.name, err)
		}
		if n := tag.RowsAffected(); n > 0 {
			deleted[s.name] = n
		}
	}
	return deleted, nil
}
