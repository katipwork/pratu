-- The janitor deletes dead rows across all tenants, but tenant-owned
-- tables carry forced RLS. These additional permissive policies OR with
-- tenant_isolation and cover only rows that are already expired: the
-- SELECT policy is required because a DELETE with a WHERE clause must
-- also read the rows it deletes, and reading is governed by
-- SELECT-applicable policies. Live data stays reachable exclusively
-- through the tenant context; app queries on these tables always filter
-- by unguessable ids and (where relevant) expiry, so visibility of dead
-- rows leaks nothing. (FK cascades, e.g. flows -> one_time_codes, bypass
-- RLS by design.)

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['flows', 'sessions', 'one_time_codes'] LOOP
        EXECUTE format('CREATE POLICY janitor_select ON %I FOR SELECT USING (expires_at <= now())', t);
        EXECUTE format('CREATE POLICY janitor_delete ON %I FOR DELETE USING (expires_at <= now())', t);
    END LOOP;
END $$;

-- OAuth2 rows expire by kind: codes/PKCE/OIDC sessions and JWT access
-- rows are minutes-lived (a day of slack), refresh tokens live 30 days
-- (31 with slack).
CREATE POLICY janitor_select ON oauth2_sessions
    FOR SELECT USING (
        (kind IN ('code', 'pkce', 'oidc', 'access') AND created_at < now() - interval '1 day')
        OR created_at < now() - interval '31 days'
    );
CREATE POLICY janitor_delete ON oauth2_sessions
    FOR DELETE USING (
        (kind IN ('code', 'pkce', 'oidc', 'access') AND created_at < now() - interval '1 day')
        OR created_at < now() - interval '31 days'
    );
