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

var ErrDomainTaken = errors.New("domain is claimed by another tenant")

// FindByDomain implements tenant.Store's custom-domain lookup. Like
// FindBySlug it is public resolution, so a disabled tenant is not found
// here even though its domain claim survives (ADR 0008).
func (s *TenantStore) FindByDomain(ctx context.Context, domain string) (*tenant.Tenant, error) {
	var t tenant.Tenant
	var config []byte
	err := s.pool.QueryRow(ctx,
		`SELECT t.id::text, t.slug, t.name, t.config
		   FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id
		  WHERE d.domain = $1 AND t.disabled_at IS NULL`, domain,
	).Scan(&t.ID, &t.Slug, &t.Name, &config)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tenant.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find tenant by domain: %w", err)
	}
	if err := json.Unmarshal(config, &t.Config); err != nil {
		return nil, fmt.Errorf("parse tenant config: %w", err)
	}
	return &t, nil
}

// TenantDomain describes one claimed custom domain.
type TenantDomain struct {
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
}

// ClaimDomain assigns a domain to a tenant. Idempotent for the same
// tenant; a domain held by another tenant is refused.
func (s *TenantStore) ClaimDomain(ctx context.Context, tenantID, domain string) error {
	var owner string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO tenant_domains (domain, tenant_id) VALUES ($1, $2)
		 ON CONFLICT (domain) DO UPDATE SET domain = EXCLUDED.domain
		 RETURNING tenant_id::text`,
		domain, tenantID,
	).Scan(&owner)
	if err != nil {
		return err
	}
	if owner != tenantID {
		return ErrDomainTaken
	}
	return nil
}

// ListDomains lists a tenant's custom domains.
func (s *TenantStore) ListDomains(ctx context.Context, tenantID string) ([]TenantDomain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT domain, created_at FROM tenant_domains WHERE tenant_id = $1 ORDER BY domain`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantDomain
	for rows.Next() {
		var d TenantDomain
		if err := rows.Scan(&d.Domain, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ReleaseDomain removes a tenant's claim on a domain.
func (s *TenantStore) ReleaseDomain(ctx context.Context, tenantID, domain string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM tenant_domains WHERE domain = $1 AND tenant_id = $2`, domain, tenantID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
