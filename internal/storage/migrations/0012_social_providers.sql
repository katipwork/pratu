-- Per-tenant social login provider registry (Q13, v1.1): generic OIDC
-- providers plus GitHub's OAuth2 dialect. Client secrets are encrypted
-- at rest when encryption is configured.
CREATE TABLE social_providers (
    tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id            text NOT NULL, -- slug, e.g. 'google', 'github'
    kind          text NOT NULL, -- 'oidc' | 'github'
    label         text NOT NULL,
    issuer        text NOT NULL DEFAULT '', -- oidc kind only
    client_id     text NOT NULL,
    client_secret text NOT NULL,
    scopes        jsonb NOT NULL DEFAULT '[]',
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE social_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE social_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON social_providers
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
