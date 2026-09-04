package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/tenant"
)

// CreateTenant inserts a tenant and seeds it with the default Identity
// Schema in one transaction.
func (s *TenantStore) Create(ctx context.Context, slug, name string, cfg tenant.Config, defaultSchema []byte) (*tenant.Tenant, error) {
	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	t := &tenant.Tenant{Slug: slug, Name: name, Config: cfg}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO tenants (slug, name, config) VALUES ($1, $2, $3) RETURNING id::text`,
			slug, name, rawCfg,
		).Scan(&t.ID)
		if err != nil {
			return err
		}
		// The seeded schema is tenant-owned, so RLS requires the tenant
		// context even here.
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, t.ID); err != nil {
			return err
		}
		_, err = CreateIdentitySchema(ctx, tx, t.ID, "default", defaultSchema)
		return err
	})
	if isUniqueViolation(err) {
		return nil, tenant.ErrSlugTaken
	}
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	return t, nil
}

// Update applies a change to one tenant's name and policy inside a
// single transaction, with the row locked for the duration: two
// operators editing at once queue instead of losing each other's change.
// apply sees the stored tenant and mutates it; returning an error aborts
// the write and surfaces unchanged.
func (s *TenantStore) Update(ctx context.Context, slug string, apply func(*tenant.Tenant) error) (*tenant.Tenant, error) {
	var t tenant.Tenant
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var config []byte
		err := tx.QueryRow(ctx,
			`SELECT id::text, slug, name, config, disabled_at FROM tenants WHERE slug = $1 FOR UPDATE`, slug,
		).Scan(&t.ID, &t.Slug, &t.Name, &config, &t.DisabledAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return tenant.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(config, &t.Config); err != nil {
			return fmt.Errorf("parse tenant config: %w", err)
		}
		if err := apply(&t); err != nil {
			return err
		}
		rawCfg, err := json.Marshal(t.Config)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE tenants SET name = $2, config = $3 WHERE id = $1`, t.ID, t.Name, rawCfg)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SetDisabled switches a tenant off or back on (ADR 0008). Disabling is
// a soft delete: nothing the tenant owns is destroyed and its slug stays
// held, so its hostname can never come to mean a different namespace.
// Disabling an already-disabled tenant keeps the original timestamp, so
// the answer to a repeated call is the answer to the first one and a
// compensating saga can run twice without special-casing.
func (s *TenantStore) SetDisabled(ctx context.Context, slug string, disabled bool) (*tenant.Tenant, error) {
	set := `disabled_at = NULL`
	if disabled {
		set = `disabled_at = COALESCE(disabled_at, now())`
	}
	var t tenant.Tenant
	var config []byte
	err := s.pool.QueryRow(ctx,
		`UPDATE tenants SET `+set+` WHERE slug = $1
		  RETURNING id::text, slug, name, config, disabled_at`, slug,
	).Scan(&t.ID, &t.Slug, &t.Name, &config, &t.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("set tenant disabled: %w", err)
	}
	if err := json.Unmarshal(config, &t.Config); err != nil {
		return nil, fmt.Errorf("parse tenant config: %w", err)
	}
	return &t, nil
}

// Purge destroys a tenant and everything it owns, and frees its slug.
// Irreversible, and deliberately not reachable in one step: only an
// already-disabled tenant can be purged, so a wrong slug in a script
// costs a disable — undone with one call — rather than a customer's
// identities (ADR 0008).
func (s *TenantStore) Purge(ctx context.Context, slug string) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var id string
		var disabledAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT id::text, disabled_at FROM tenants WHERE slug = $1 FOR UPDATE`, slug,
		).Scan(&id, &disabledAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return tenant.ErrNotFound
		}
		if err != nil {
			return err
		}
		if disabledAt == nil {
			return tenant.ErrNotDisabled
		}
		// Rate-limit counters are platform-level and keyed by string, so
		// they are the one thing no foreign key sweeps up. Leaving them
		// would leave the purged tenant's identifiers behind — the keys
		// embed the tenant id as a segment, `login:id:<id>:<identifier>`.
		if _, err := tx.Exec(ctx,
			`DELETE FROM rate_limits WHERE key LIKE '%:' || $1 || ':%'`, id); err != nil {
			return err
		}
		// Everything else follows the foreign keys: every tenant-owned
		// table references tenants(id) ON DELETE CASCADE, and referential
		// actions bypass RLS, so the sweep is complete without a tenant
		// context.
		_, err = tx.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, id)
		return err
	})
	if err != nil && !errors.Is(err, tenant.ErrNotFound) && !errors.Is(err, tenant.ErrNotDisabled) {
		return fmt.Errorf("purge tenant: %w", err)
	}
	return err
}

// List returns every tenant, disabled ones included: the admin API is
// where an operator finds what they switched off.
func (s *TenantStore) List(ctx context.Context) ([]tenant.Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, slug, name, config, disabled_at FROM tenants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []tenant.Tenant
	for rows.Next() {
		var t tenant.Tenant
		var config []byte
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &config, &t.DisabledAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(config, &t.Config); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
