-- Tenant-owned custom domains (ADR 0003's promised lookup-table
-- addition): a Host that is not a base-domain subdomain resolves here.
-- Platform-level like tenants (the resolver runs before any tenant
-- context exists), so no RLS.
CREATE TABLE tenant_domains (
    domain     text PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_domains_tenant_idx ON tenant_domains (tenant_id);
