package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// List returns all tenants, newest first.
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
			`SELECT id::text, slug, name, config FROM tenants WHERE slug = $1 FOR UPDATE`, slug,
		).Scan(&t.ID, &t.Slug, &t.Name, &config)
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

func (s *TenantStore) List(ctx context.Context) ([]tenant.Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, slug, name, config FROM tenants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []tenant.Tenant
	for rows.Next() {
		var t tenant.Tenant
		var config []byte
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &config); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(config, &t.Config); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
