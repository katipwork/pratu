# Tenants are resolved by hostname: subdomains now, custom domains later

Each tenant is addressed by its own hostname — `{slug}.{base-domain}` via wildcard DNS/TLS in v1, tenant-owned custom domains (CNAME + on-demand ACME certs) as a later addition. A single TenantResolver component owns Host→Tenant; nothing else parses hostnames. Each tenant therefore gets its own OIDC issuer URL and JWKS.

**Update (custom domains shipped):** the lookup-table addition landed as `tenant_domains` — hosts outside the base domain resolve there, and issuer/JWKS/cookies follow the Host automatically. TLS for custom domains is the fronting proxy's job (e.g. a Caddy/LB with on-demand certificates); Pratu itself stays a plain-HTTP upstream.

We rejected Keycloak-style path prefixes (`/t/{slug}/...`): they share one cookie domain across all tenants, and RFC 6265 cookie `Path` attributes are not a security boundary, so tenant session isolation would depend on per-request server-side checks instead of being enforced by the browser.
