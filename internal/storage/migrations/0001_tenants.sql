-- Tenants are the platform-level namespace table and therefore carry no
-- tenant_id / RLS themselves. Every tenant-owned table added in later
-- migrations must include a tenant_id column referencing tenants(id) and
-- an RLS policy keyed on current_setting('app.tenant_id') (ADR 0004).

CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'),
    name       text NOT NULL,
    config     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
