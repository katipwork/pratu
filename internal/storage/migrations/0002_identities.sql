-- Identity, credential, flow, and session tables. All are tenant-owned:
-- tenant_id column + forced RLS keyed on app.tenant_id (ADR 0004), so they
-- are only reachable through storage.InTenant.

CREATE TABLE identity_schemas (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    schema     jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE identities (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    schema_id  uuid NOT NULL REFERENCES identity_schemas(id),
    traits     jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identity_credentials (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    kind        text NOT NULL, -- 'password'
    config      jsonb NOT NULL, -- password: {"hash": "$argon2id$..."}
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (identity_id, kind)
);

-- Normalized login identifiers (schema-annotated traits), unique per tenant.
CREATE TABLE identity_identifiers (
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identifier  text NOT NULL,
    identity_id uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    PRIMARY KEY (tenant_id, identifier)
);
CREATE INDEX identity_identifiers_identity_idx ON identity_identifiers (identity_id);

CREATE TABLE flows (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind       text NOT NULL, -- 'registration' | 'login'
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id      uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    token_hash       bytea NOT NULL UNIQUE, -- sha256 of the opaque session token
    authenticated_at timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_identity_idx ON sessions (tenant_id, identity_id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'identity_schemas', 'identities', 'identity_credentials',
        'identity_identifiers', 'flows', 'sessions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING '
            || '(tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
            || 'WITH CHECK '
            || '(tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)',
            t);
    END LOOP;
END $$;
