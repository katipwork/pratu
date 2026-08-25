package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/tenant"
)

// CreateTenant inserts a tenant and seeds it with the default Identity
// Schema in one transaction.
func (s *TenantStore) Create(ctx context.Context, slug, name string, defaultSchema []byte) (*tenant.Tenant, error) {
	t := &tenant.Tenant{Slug: slug, Name: name}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING id::text`,
			slug, name,
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
func (s *TenantStore) List(ctx context.Context) ([]tenant.Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, slug, name FROM tenants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []tenant.Tenant
	for rows.Next() {
		var t tenant.Tenant
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
