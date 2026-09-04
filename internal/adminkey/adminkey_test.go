package adminkey

import "testing"

func TestValidateRejectsUnusableKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  Key
		want string // substring of the complaint
	}{
		{"no name", Key{Secret: "0123456789abcdef", Capabilities: []string{"*"}}, "name is required"},
		{"short secret", Key{Name: "k", Secret: "short", Capabilities: []string{"*"}}, "at least"},
		{"no capabilities", Key{Name: "k", Secret: "0123456789abcdef"}, "at least one capability"},
		// The typo that matters: a key granting nothing at all would
		// otherwise be discovered by a provisioner failing in production.
		{"capability typo", Key{Name: "k", Secret: "0123456789abcdef", Capabilities: []string{"tenant:create"}}, "unknown capability"},
		{"unknown resource wildcard", Key{Name: "k", Secret: "0123456789abcdef", Capabilities: []string{"widgets:*"}}, "unknown capability resource"},
		{"wildcard in the middle", Key{Name: "k", Secret: "0123456789abcdef", Capabilities: []string{"*"}, Tenants: []string{"a*b"}}, "may only end in a wildcard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.key.Validate()
			if got == "" {
				t.Fatalf("Validate() accepted %+v", tc.key)
			}
			if !contains(got, tc.want) {
				t.Errorf("Validate() = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

func TestValidateAcceptsUsableKeys(t *testing.T) {
	for _, k := range []Key{
		{Name: "provisioner", Secret: "0123456789abcdef", Capabilities: []string{"tenants:create", "clients:create"}},
		{Name: "wildcarded", Secret: "0123456789abcdef", Capabilities: []string{"clients:*"}},
		{Name: "root-like", Secret: "0123456789abcdef", Capabilities: []string{"*"}},
		{Name: "scoped", Secret: "0123456789abcdef", Capabilities: []string{"*"}, Tenants: []string{"acme", "pilla-*"}},
	} {
		if msg := k.Validate(); msg != "" {
			t.Errorf("Validate() rejected %q: %s", k.Name, msg)
		}
	}
}

func TestNewKeyringRejectsAmbiguity(t *testing.T) {
	valid := func(name, secret string) Key {
		return Key{Name: name, Secret: secret, Capabilities: []string{"tenants:read"}}
	}
	t.Run("duplicate names", func(t *testing.T) {
		_, err := NewKeyring("", []Key{valid("a", "0123456789abcdef"), valid("a", "fedcba9876543210")})
		if err == nil {
			t.Fatal("two keys shared a name and were accepted")
		}
	})
	// Whichever entry compared first would decide the grant, which is
	// not something a reader of the config could predict.
	t.Run("duplicate secrets", func(t *testing.T) {
		_, err := NewKeyring("", []Key{valid("a", "0123456789abcdef"), valid("b", "0123456789abcdef")})
		if err == nil {
			t.Fatal("two keys shared a secret and were accepted")
		}
	})
	t.Run("a key reusing the root secret", func(t *testing.T) {
		_, err := NewKeyring("0123456789abcdef", []Key{valid("a", "0123456789abcdef")})
		if err == nil {
			t.Fatal("a key shadowing the root secret was accepted")
		}
	})
}

func TestGrantsAllows(t *testing.T) {
	ring, err := NewKeyring("root-secret-0123456789", []Key{
		{Name: "prov", Secret: "prov-secret-0123456789", Capabilities: []string{"tenants:create", "clients:*"}},
		{Name: "scoped", Secret: "scoped-secret-0123456789", Capabilities: []string{"*"}, Tenants: []string{"acme", "pilla-*"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	root, ok := ring.Lookup("root-secret-0123456789")
	if !ok || !root.Root() {
		t.Fatal("the root secret did not resolve to the root grant")
	}
	if !root.Allows(KeysDelete, "anything") {
		t.Error("the root key must stay unrestricted")
	}

	prov, _ := ring.Lookup("prov-secret-0123456789")
	for _, c := range []Capability{ClientsCreate, ClientsDelete, ClientsRotateSecret} {
		if !prov.Allows(c, "any-tenant") {
			t.Errorf("clients:* should cover %s", c)
		}
	}
	if prov.Allows(KeysRotate, "any-tenant") {
		t.Error("clients:* leaked into another resource")
	}
	if prov.Allows(TenantsPurge, "any-tenant") {
		t.Error("tenants:create leaked into tenants:purge")
	}

	scoped, _ := ring.Lookup("scoped-secret-0123456789")
	if !scoped.Allows(KeysRotate, "acme") || !scoped.Allows(KeysRotate, "pilla-one") {
		t.Error("the scoped key cannot reach a tenant it names")
	}
	if scoped.Allows(KeysRotate, "acme-evil") {
		t.Error("an exact tenant pattern matched a prefix")
	}
	if scoped.Allows(KeysRotate, "other") {
		t.Error("the scoped key reached a tenant outside its patterns")
	}
	// A scope that cannot be checked is not a scope that holds.
	if scoped.Allows(KeysRotate, "") {
		t.Error("a tenant-restricted key was allowed a request naming no tenant")
	}
	// Except where the handler takes responsibility for the tenant.
	if !scoped.AllowsCapability(TenantsCreate) {
		t.Error("AllowsCapability must ignore the tenant scope")
	}

	if _, ok := ring.Lookup("nothing-like-a-key"); ok {
		t.Error("an unknown secret resolved to a grant")
	}
}

// The zero Grants is what a request that never authenticated carries.
func TestZeroGrantsAllowNothing(t *testing.T) {
	var g Grants
	if g.Allows(TenantsRead, "acme") || g.AllowsCapability(TenantsRead) || g.Root() {
		t.Error("the zero Grants granted something")
	}
}

func TestEmptyRing(t *testing.T) {
	ring, err := NewKeyring("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ring.Empty() {
		t.Error("a ring with no root key and no keys should be empty")
	}
	if _, err := NewKeyring("", []Key{{Name: "a", Secret: "0123456789abcdef", Capabilities: []string{"tenants:read"}}}); err != nil {
		t.Errorf("scoped keys without a root key should be usable: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
