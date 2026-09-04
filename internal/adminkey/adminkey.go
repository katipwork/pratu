// Package adminkey defines the admin API's keys and the capabilities
// they carry. It exists so that a service needing admin access at
// runtime — a provisioner creating a Tenant and its OAuth2 client — can
// hold a credential that does those two things and nothing else, rather
// than the root key, whose blast radius is every Tenant in the system
// (#10).
//
// The capability list here is the whole vocabulary: config validates
// against it at load, and the admin router names one for every route, so
// a capability that does not exist is a startup error rather than a
// silently ungranted permission.
package adminkey

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

// Capability names one thing an admin key may do. The pair is
// resource:action, and actions are split where the risk differs: a key
// that may rename a Tenant is not thereby a key that may destroy one.
type Capability string

const (
	TenantsRead    Capability = "tenants:read"
	TenantsCreate  Capability = "tenants:create"
	TenantsUpdate  Capability = "tenants:update"
	TenantsDisable Capability = "tenants:disable"
	TenantsPurge   Capability = "tenants:purge"

	ClientsRead         Capability = "clients:read"
	ClientsCreate       Capability = "clients:create"
	ClientsUpdate       Capability = "clients:update"
	ClientsDelete       Capability = "clients:delete"
	ClientsRotateSecret Capability = "clients:rotate-secret"

	SessionsRead   Capability = "sessions:read"
	SessionsRevoke Capability = "sessions:revoke"

	KeysRead   Capability = "keys:read"
	KeysRotate Capability = "keys:rotate"
	KeysDelete Capability = "keys:delete"

	SchemasRead  Capability = "schemas:read"
	SchemasWrite Capability = "schemas:write"

	SocialRead   Capability = "social:read"
	SocialWrite  Capability = "social:write"
	SocialDelete Capability = "social:delete"

	DomainsRead   Capability = "domains:read"
	DomainsWrite  Capability = "domains:write"
	DomainsDelete Capability = "domains:delete"
)

// All is every capability the admin API defines. A grant naming anything
// else is a configuration error.
var All = []Capability{
	TenantsRead, TenantsCreate, TenantsUpdate, TenantsDisable, TenantsPurge,
	ClientsRead, ClientsCreate, ClientsUpdate, ClientsDelete, ClientsRotateSecret,
	SessionsRead, SessionsRevoke,
	KeysRead, KeysRotate, KeysDelete,
	SchemasRead, SchemasWrite,
	SocialRead, SocialWrite, SocialDelete,
	DomainsRead, DomainsWrite, DomainsDelete,
}

func known(c Capability) bool {
	for _, k := range All {
		if k == c {
			return true
		}
	}
	return false
}

// Key is one configured admin credential.
type Key struct {
	// Name identifies the key in configuration and in logs. It is not a
	// secret and never authorizes anything by itself.
	Name string `yaml:"name"`
	// Secret is the bearer token presented as `Authorization: Bearer`.
	Secret string `yaml:"key"`
	// Capabilities lists what the key may do: exact capability names,
	// `resource:*` for every action on a resource, or `*` for all of
	// them — which is the root key's grant, and should be spelled as
	// the root key instead.
	Capabilities []string `yaml:"capabilities"`
	// Tenants restricts the key to Tenants whose slug matches one of
	// these patterns; empty means every Tenant. A pattern is an exact
	// slug or a trailing-wildcard prefix (`pilla-*`). Wildcards elsewhere
	// are rejected, so a pattern cannot be read two ways.
	Tenants []string `yaml:"tenants"`
}

// MinSecretLength is the shortest admin key accepted. An admin key is
// the whole of the admin API's authentication, so a guessable one is the
// same as none.
const MinSecretLength = 16

// Validate reports what is wrong with a key, or "" when it is usable.
// Capability typos are rejected here rather than ignored: a key that
// silently grants nothing is a broken deployment discovered at the worst
// possible moment.
func (k Key) Validate() string {
	if k.Name == "" {
		return "name is required"
	}
	if len(k.Secret) < MinSecretLength {
		return fmt.Sprintf("key %q: secret must be at least %d characters", k.Name, MinSecretLength)
	}
	if len(k.Capabilities) == 0 {
		return fmt.Sprintf("key %q: capabilities must list at least one capability", k.Name)
	}
	for _, raw := range k.Capabilities {
		if raw == "*" {
			continue
		}
		if resource, ok := strings.CutSuffix(raw, ":*"); ok {
			if !resourceExists(resource) {
				return fmt.Sprintf("key %q: unknown capability resource %q", k.Name, resource)
			}
			continue
		}
		if !known(Capability(raw)) {
			return fmt.Sprintf("key %q: unknown capability %q", k.Name, raw)
		}
	}
	for _, p := range k.Tenants {
		if strings.Count(p, "*") > 1 || (strings.Contains(p, "*") && !strings.HasSuffix(p, "*")) {
			return fmt.Sprintf("key %q: tenant pattern %q may only end in a wildcard", k.Name, p)
		}
		if p == "" {
			return fmt.Sprintf("key %q: tenant pattern cannot be empty", k.Name)
		}
	}
	return ""
}

func resourceExists(resource string) bool {
	for _, c := range All {
		if strings.HasPrefix(string(c), resource+":") {
			return true
		}
	}
	return false
}

// Grants is what one authenticated caller may do. The zero value grants
// nothing, so a failure to authenticate cannot be mistaken for a grant.
type Grants struct {
	name    string
	root    bool
	caps    []string
	tenants []string
}

// Name identifies the key behind a request, for logs and errors.
func (g Grants) Name() string {
	if g.name == "" {
		return "unauthenticated"
	}
	return g.name
}

// Root reports whether this is the unrestricted operator key.
func (g Grants) Root() bool { return g.root }

// Allows reports whether the caller may perform c against the tenant
// named by slug. An empty slug means the request names no single tenant;
// a tenant-restricted key is refused there, because a scope that cannot
// be checked is not a scope that holds. Callers that can determine the
// tenant themselves — creating one, listing them — ask with the slug
// they resolved.
func (g Grants) Allows(c Capability, slug string) bool {
	if g.root {
		return true
	}
	if !g.hasCapability(c) {
		return false
	}
	return g.coversTenant(slug)
}

// AllowsCapability reports whether the caller holds c, saying nothing
// about which tenants it may use it on. It is for routes that name no
// tenant in their path: they pass this gate and then establish the
// tenant themselves, which is the only place it can be known.
func (g Grants) AllowsCapability(c Capability) bool {
	return g.root || g.hasCapability(c)
}

func (g Grants) hasCapability(c Capability) bool {
	resource, _, _ := strings.Cut(string(c), ":")
	for _, raw := range g.caps {
		if raw == "*" || raw == string(c) || raw == resource+":*" {
			return true
		}
	}
	return false
}

// coversTenant reports whether the key's slug patterns admit this slug.
func (g Grants) coversTenant(slug string) bool {
	if len(g.tenants) == 0 {
		return true
	}
	if slug == "" {
		return false
	}
	for _, p := range g.tenants {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(slug, prefix) {
				return true
			}
			continue
		}
		if p == slug {
			return true
		}
	}
	return false
}

// TenantRestricted reports whether the key is confined to a subset of
// tenants, which is what makes a listing need filtering.
func (g Grants) TenantRestricted() bool { return len(g.tenants) > 0 }

// Keyring resolves a presented bearer secret to the grants behind it.
type Keyring struct {
	root string
	keys []Key
}

// NewKeyring validates the configured keys and returns the ring. An
// empty root secret is allowed as long as some key exists; a ring with
// nothing in it authenticates nobody.
func NewKeyring(root string, keys []Key) (*Keyring, error) {
	seen := map[string]bool{}
	secrets := map[string]string{}
	if root != "" {
		secrets[root] = "root_key"
	}
	for _, k := range keys {
		if msg := k.Validate(); msg != "" {
			return nil, fmt.Errorf("admin.keys: %s", msg)
		}
		if seen[k.Name] {
			return nil, fmt.Errorf("admin.keys: duplicate key name %q", k.Name)
		}
		seen[k.Name] = true
		// Two names for one secret would make the effective grant
		// whichever entry happened to be compared first.
		if other, dup := secrets[k.Secret]; dup {
			return nil, fmt.Errorf("admin.keys: key %q reuses the secret of %s", k.Name, other)
		}
		secrets[k.Secret] = fmt.Sprintf("key %q", k.Name)
	}
	return &Keyring{root: root, keys: keys}, nil
}

// Empty reports whether no credential is configured at all, which is how
// the admin API stays off by default.
func (r *Keyring) Empty() bool { return r.root == "" && len(r.keys) == 0 }

// Lookup resolves a presented secret. Every candidate is compared, in
// constant time and without an early exit, so neither the match nor its
// position leaks through timing.
func (r *Keyring) Lookup(presented string) (Grants, bool) {
	var found Grants
	var ok bool
	if r.root != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(r.root)) == 1 {
		found, ok = Grants{name: "root", root: true}, true
	}
	for _, k := range r.keys {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(k.Secret)) == 1 {
			found, ok = Grants{name: k.Name, caps: k.Capabilities, tenants: k.Tenants}, true
		}
	}
	return found, ok
}
