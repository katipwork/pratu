package storage

import (
	"context"
	"embed"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies embedded migrations that have not yet run, in filename
// order, each in its own transaction. It returns the versions applied by
// this call.
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`)
	if err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var applied []string
	for _, e := range entries {
		version := e.Name()

		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version,
		).Scan(&exists)
		if err != nil {
			return applied, err
		}
		if exists {
			continue
		}

		sql, err := migrationsFS.ReadFile("migrations/" + version)
		if err != nil {
			return applied, err
		}
		err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", version, err)
		}
		applied = append(applied, version)
	}
	return applied, nil
}
