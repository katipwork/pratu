-- OAuth2/OIDC provider: per-tenant signing keys, clients, and protocol
-- session storage for fosite (ADR 0001, 0003; grilling Q17/Q18).

CREATE TABLE tenant_keys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid         text NOT NULL,
    private_pem text NOT NULL, -- at-rest encryption: same backlog as TOTP secrets
    active      boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kid)
);

CREATE TABLE oauth2_clients (
    id           text PRIMARY KEY, -- client_id
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         text NOT NULL,
    secret_hash  text,             -- NULL for public (PKCE-only) clients
    redirect_uris jsonb NOT NULL DEFAULT '[]',
    scopes       jsonb NOT NULL DEFAULT '["openid", "offline_access", "profile", "email"]',
    first_party  boolean NOT NULL DEFAULT false, -- consent step skipped
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- One row per issued artifact (authorize code, access/refresh token,
-- PKCE and OIDC session), keyed by kind + a server-side hash of fosite's
-- signature so raw secrets never land in the table.
CREATE TABLE oauth2_sessions (
    kind             text NOT NULL, -- code | access | refresh | pkce | oidc
    signature        text NOT NULL,
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id       text NOT NULL,
    client_id        text NOT NULL,
    requested_at     timestamptz NOT NULL,
    scopes           jsonb NOT NULL DEFAULT '[]',
    granted_scopes   jsonb NOT NULL DEFAULT '[]',
    form             text NOT NULL DEFAULT '',
    session          jsonb NOT NULL DEFAULT '{}',
    subject          text NOT NULL DEFAULT '',
    active           boolean NOT NULL DEFAULT true,
    access_signature text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, signature)
);
CREATE INDEX oauth2_sessions_request_idx ON oauth2_sessions (request_id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_keys', 'oauth2_clients', 'oauth2_sessions'] LOOP
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
