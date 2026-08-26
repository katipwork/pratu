// Package storage owns all Postgres access: connection pooling, embedded
// migrations, and the store implementations behind the domain packages'
// interfaces. Postgres is the only supported datastore (ADR 0002); tenant
// isolation is shared tables + tenant_id + RLS (ADR 0004).
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/secrets"
	"github.com/katipwork/pratu/internal/tenant"
)

// cipher guards secrets at rest (TOTP secrets, second-factor phones,
// tenant signing keys). nil means encryption is not configured and values
// are stored plaintext; set once at startup.
var cipher *secrets.Cipher

func SetCipher(c *secrets.Cipher) {
	cipher = c
}

func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, err
	}

	// Tenant isolation rests on RLS (ADR 0004), and superuser or BYPASSRLS
	// roles skip RLS entirely — running as one would silently disable the
	// isolation guarantee, so refuse outright.
	var elevated bool
	err = pool.QueryRow(pingCtx,
		`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&elevated)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("check database role: %w", err)
	}
	if elevated {
		pool.Close()
		return nil, errors.New("database role bypasses row-level security (superuser or BYPASSRLS); connect as an unprivileged role")
	}
	return pool, nil
}

// TenantStore implements tenant.Store on Postgres.
type TenantStore struct {
	pool *pgxpool.Pool
}

func NewTenantStore(pool *pgxpool.Pool) *TenantStore {
	return &TenantStore{pool: pool}
}

func (s *TenantStore) FindBySlug(ctx context.Context, slug string) (*tenant.Tenant, error) {
	var t tenant.Tenant
	var config []byte
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, slug, name, config FROM tenants WHERE slug = $1`, slug,
	).Scan(&t.ID, &t.Slug, &t.Name, &config)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find tenant by slug: %w", err)
	}
	if err := json.Unmarshal(config, &t.Config); err != nil {
		return nil, fmt.Errorf("parse tenant config: %w", err)
	}
	return &t, nil
}

// InTenant runs fn inside a transaction with app.tenant_id set, so RLS
// policies on tenant-owned tables (ADR 0004) apply to every statement fn
// executes. All tenant-scoped data access must go through this.
func InTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}
		return fn(tx)
	})
}
