# Tenant isolation: shared tables with tenant_id, enforced by Row-Level Security

All tenant-owned rows live in shared tables carrying a `tenant_id` column; every request runs with `SET LOCAL app.tenant_id` and Postgres RLS policies deny cross-tenant access even when a query forgets its WHERE clause. We rejected schema-per-tenant and database-per-tenant: they make migrations O(tenants) and connection pooling painful, and RLS gives us the isolation guarantee without that operational tax.

**Consequences**: superuser and BYPASSRLS roles skip RLS entirely, so the server refuses to start when connected as one — the app role must be an ordinary role (table ownership is fine; policies use FORCE ROW LEVEL SECURITY). This was caught live: a dev database whose app user was the Postgres bootstrap superuser accepted one tenant's session token on another tenant's hostname.
