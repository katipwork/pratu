package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/flow"
)

// Integration test; runs only against a migrated database:
//
//	PRATU_TEST_DATABASE_URL=postgres://pratu:pratu@localhost:5432/pratu?sslmode=disable go test ./internal/storage/
func TestCleanupExpired(t *testing.T) {
	url := os.Getenv("PRATU_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PRATU_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// A throwaway tenant keeps this test isolated; cascade cleans it up.
	var tenantID string
	slug := fmt.Sprintf("janitor-%d", time.Now().UnixNano())
	err = pool.QueryRow(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, 'Janitor Test') RETURNING id::text`, slug,
	).Scan(&tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)

	var liveFlow string
	err = InTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// One expired flow (backdated), one live.
		if _, err := tx.Exec(ctx,
			`INSERT INTO flows (tenant_id, kind, expires_at) VALUES ($1, 'login', now() - interval '1 hour')`,
			tenantID); err != nil {
			return err
		}
		f, err := CreateFlow(ctx, tx, tenantID, flow.KindLogin, nil, false)
		if err != nil {
			return err
		}
		liveFlow = f.ID
		// One stale OAuth2 code row, one fresh.
		for i, created := range []string{"now() - interval '2 days'", "now()"} {
			if _, err := tx.Exec(ctx, fmt.Sprintf(
				`INSERT INTO oauth2_sessions (kind, signature, tenant_id, request_id, client_id, requested_at, created_at)
				 VALUES ('code', $1, $2, 'req', 'client', now(), %s)`, created),
				fmt.Sprintf("sig-%s-%d", slug, i), tenantID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := CleanupExpired(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["flows"] < 1 {
		t.Errorf("expected at least 1 expired flow deleted, got %v", deleted)
	}
	if deleted["oauth2_sessions"] < 1 {
		t.Errorf("expected at least 1 stale oauth2 row deleted, got %v", deleted)
	}

	err = InTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		var flows, oauthRows int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM flows WHERE tenant_id = $1`, tenantID).Scan(&flows); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM oauth2_sessions WHERE tenant_id = $1`, tenantID).Scan(&oauthRows); err != nil {
			return err
		}
		if flows != 1 || oauthRows != 1 {
			t.Errorf("live rows must survive: flows=%d oauth=%d, want 1 and 1", flows, oauthRows)
		}
		if _, err := GetFlow(ctx, tx, liveFlow, flow.KindLogin); err != nil {
			t.Errorf("live flow should still load: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
