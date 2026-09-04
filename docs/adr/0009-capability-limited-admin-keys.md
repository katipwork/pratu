# Admin keys carry capabilities, declared by the route that needs them

The admin API accepts, besides the unrestricted root key, any number of configured keys that each hold a set of capabilities (`tenants:create`, `clients:*`, …) and optionally a set of Tenant slug patterns. Keys live in the config file — `admin.keys`, with each secret overridable as `PRATU_ADMIN_KEY_<NAME>` — and there is no API for managing them. Every admin route names the capability it requires at registration; a request whose key lacks it gets `403` naming the missing capability. This exists because the root key can do everything to every Tenant, which stopped being acceptable once a *service* needed admin access at runtime: a provisioner that creates a Tenant and its OAuth2 client from application code held a credential whose blast radius was the entire platform ([#10](https://github.com/katipwork/pratu/issues/10)).

Decisions that were open questions, settled here:

- **The route table carries the capability, not a middleware.** A middleware matching paths or methods is a second description of the routing table, and the two drift: the failure mode is a new route that matches no rule and is therefore unguarded. Instead `adminRouter.handle` takes the capability as a parameter, so a route cannot be registered without naming one, and the guard runs with the capability the route itself declared.

- **A route carrying `{slug}` has its Tenant scope checked for it.** `handle` panics at construction on a pattern without `{slug}`, and `handleGlobal` — for the two routes that name no single Tenant — panics on one with it. So the scoped case, which is every route but two, is enforced without an author having to remember, and the unscoped case is spelled differently enough to be noticed in review.

- **A tenant-restricted key is refused any request that names no Tenant it can check.** `Allows(capability, "")` is false for such a key: a scope that cannot be evaluated is not a scope that holds. The two routes where that would be wrong take responsibility explicitly — creating a Tenant checks the slug in the body, listing them filters the result to what the key may see, because the list of slugs is the list of customers.

- **Configuration, not a management API.** A key that can mint keys is root-equivalent, so a management API would recreate the problem one level up and need its own bootstrap story. A config file is reviewable, diffable, and already how the root key is set. Keys can be added later without invalidating this shape.

- **A capability that does not exist is a startup error.** `admin.keys` is validated when config loads: an unknown capability, a duplicate name, a key reusing another key's (or the root key's) secret, or a secret under 16 characters all stop the process. The alternative — ignoring what it cannot parse — turns a typo like `tenant:create` into a key that silently grants nothing, discovered when a provisioner fails in production.

- **Actions are split where the risk differs, not uniformly.** `tenants:update` is not `tenants:disable` is not `tenants:purge`, because renaming, closing and destroying a Tenant are not the same decision. `DELETE /admin/tenants/{slug}` is one route spanning two of those, so it demands `tenants:disable` at the route and additionally `tenants:purge` inside the handler when `?purge=true` (ADR 0008).

## Consequences

- The root key behaves exactly as before, and a deployment that configures no `admin.keys` is unchanged. With neither a root key nor any keys, the admin API answers `503` as it always has for a missing root key.
- `401` and `403` now mean different things on the admin API: an unrecognised key is unauthenticated, a recognised one lacking a capability is forbidden. The `403` names the capability, which tells the caller nothing it could not learn by trying and saves an operator guessing.
- Capabilities are enumerated in one place (`adminkey.All`); a new admin route must name one of them or add one, and config validates against the same list.
- Tenant patterns are an exact slug or a trailing-wildcard prefix. Wildcards elsewhere are rejected so a pattern cannot be read two ways.
- Nothing here narrows what the root key can do. A deployment that wants the blast radius actually reduced has to stop handing the root key to services — the capability keys are what it hands them instead.
