package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katipwork/pratu/internal/adminkey"
)

func randSuffix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d-%d", time.Now().UnixNano()%1_000_000, atomic.AddInt64(&tenantSeq, 1))
}

func uniqueSlug(t *testing.T) string {
	t.Helper()
	return "cap-" + randSuffix(t)
}

// Capability-limited admin keys (#10). The point is a provisioner that
// can make a Tenant and its OAuth2 client and nothing else, so the tests
// are mostly about what a key is refused — and about the root key being
// untouched by any of it.

const (
	provisionerKey = "test-provisioner-key-0123456789"
	readOnlyKey    = "test-read-only-key-0123456789"
	scopedKey      = "test-tenant-scoped-key-0123456789"
	purgerKey      = "test-purger-key-0123456789"
)

// testKeys are the scoped keys every test in this file shares.
func testKeys() []adminkey.Key {
	return []adminkey.Key{
		{
			Name:         "provisioner",
			Secret:       provisionerKey,
			Capabilities: []string{"tenants:create", "clients:create", "clients:rotate-secret"},
		},
		{
			Name:         "read-only",
			Secret:       readOnlyKey,
			Capabilities: []string{"tenants:read", "clients:read"},
		},
		{
			Name:         "tenant-scoped",
			Secret:       scopedKey,
			Capabilities: []string{"*"},
			Tenants:      []string{"scoped-*"},
		},
		{
			Name:         "purger",
			Secret:       purgerKey,
			Capabilities: []string{"tenants:disable", "tenants:purge", "tenants:create"},
		},
	}
}

func TestAdminKeyCapabilities(t *testing.T) {
	h := newHarness(t, false, testKeys()...)

	t.Run("a provisioner can do its job", func(t *testing.T) {
		slug := uniqueSlug(t)
		r := h.adminRequestAs(t, provisionerKey, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": slug, "name": "Provisioned"})
		if r.Status != http.StatusCreated {
			t.Fatalf("create tenant: status %d body %s", r.Status, r.Body)
		}
		r = h.adminRequestAs(t, provisionerKey, http.MethodPost, "/admin/tenants/"+slug+"/clients",
			map[string]any{"name": "App", "redirect_uris": []string{"https://app.example.com/cb"}})
		if r.Status != http.StatusCreated {
			t.Fatalf("create client: status %d body %s", r.Status, r.Body)
		}
		var created struct {
			Client struct {
				ID string `json:"client_id"`
			} `json:"client"`
		}
		r.decode(t, &created)
		// The crash-recovery path from #9 is part of provisioning.
		r = h.adminRequestAs(t, provisionerKey, http.MethodPost,
			"/admin/tenants/"+slug+"/clients/"+created.Client.ID+"/rotate-secret", nil)
		if r.Status != http.StatusOK {
			t.Errorf("rotate secret: status %d body %s", r.Status, r.Body)
		}
	})

	// Everything the provisioner is not: the blast radius the issue is
	// about is every one of these being reachable with the root key.
	t.Run("a provisioner is refused everything else", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		for _, tc := range []struct{ name, method, path string }{
			{"rotate signing keys", http.MethodPost, "/admin/tenants/" + tn.Slug + "/keys/rotate"},
			{"rewrite a schema", http.MethodPut, "/admin/tenants/" + tn.Slug + "/schemas/default"},
			{"revoke sessions", http.MethodDelete, "/admin/tenants/" + tn.Slug + "/identities/x/sessions"},
			{"read tenants", http.MethodGet, "/admin/tenants/" + tn.Slug},
			{"patch a tenant", http.MethodPatch, "/admin/tenants/" + tn.Slug},
			{"disable a tenant", http.MethodDelete, "/admin/tenants/" + tn.Slug},
			{"delete a client", http.MethodDelete, "/admin/tenants/" + tn.Slug + "/clients/pc_x"},
			{"claim a domain", http.MethodPut, "/admin/tenants/" + tn.Slug + "/domains/x.example.net"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := h.adminRequestAs(t, provisionerKey, tc.method, tc.path, nil)
				if r.Status != http.StatusForbidden {
					t.Errorf("status %d body %s, want %d", r.Status, r.Body, http.StatusForbidden)
				}
			})
		}
	})

	t.Run("the refusal names the missing capability", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		r := h.adminRequestAs(t, readOnlyKey, http.MethodPost, "/admin/tenants/"+tn.Slug+"/keys/rotate", nil)
		r.requireStatus(t, http.StatusForbidden)
		if msg := r.errorMessage(t); !strings.Contains(msg, string(adminkey.KeysRotate)) {
			t.Errorf("message = %q, want it to name %q", msg, adminkey.KeysRotate)
		}
	})

	t.Run("a read-only key reads but does not write", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		h.adminRequestAs(t, readOnlyKey, http.MethodGet, "/admin/tenants/"+tn.Slug, nil).
			requireStatus(t, http.StatusOK)
		h.adminRequestAs(t, readOnlyKey, http.MethodGet, "/admin/tenants/"+tn.Slug+"/clients", nil).
			requireStatus(t, http.StatusOK)
		h.adminRequestAs(t, readOnlyKey, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": uniqueSlug(t), "name": "Nope"}).
			requireStatus(t, http.StatusForbidden)
	})

	t.Run("the root key is unrestricted, as before", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		h.adminRequest(t, http.MethodPost, "/admin/tenants/"+tn.Slug+"/keys/rotate", nil).
			requireStatus(t, http.StatusOK)
	})

	t.Run("an unknown key is unauthorized, not forbidden", func(t *testing.T) {
		// 401 and 403 are different answers: one means "who are you",
		// the other "you, but not for this".
		h.adminRequestAs(t, "not-a-configured-key-at-all", http.MethodGet, "/admin/tenants", nil).
			requireStatus(t, http.StatusUnauthorized)
		h.adminRequestAs(t, "", http.MethodGet, "/admin/tenants", nil).
			requireStatus(t, http.StatusUnauthorized)
	})
}

func TestAdminKeyTenantScope(t *testing.T) {
	h := newHarness(t, false, testKeys()...)

	// The scoped key holds "*" capabilities, so only its tenant pattern
	// can be what stops it.
	t.Run("it reaches its own tenants and no others", func(t *testing.T) {
		mine := h.adminRequestAs(t, scopedKey, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": "scoped-" + randSuffix(t), "name": "Mine"})
		if mine.Status != http.StatusCreated {
			t.Fatalf("create in scope: status %d body %s", mine.Status, mine.Body)
		}
		var created struct {
			Slug string `json:"slug"`
		}
		mine.decode(t, &created)
		h.adminRequestAs(t, scopedKey, http.MethodGet, "/admin/tenants/"+created.Slug, nil).
			requireStatus(t, http.StatusOK)

		// A tenant outside the pattern is invisible even to "*".
		theirs := h.createTenant(t, nil)
		h.adminRequestAs(t, scopedKey, http.MethodGet, "/admin/tenants/"+theirs.Slug, nil).
			requireStatus(t, http.StatusForbidden)
		h.adminRequestAs(t, scopedKey, http.MethodPost, "/admin/tenants/"+theirs.Slug+"/keys/rotate", nil).
			requireStatus(t, http.StatusForbidden)
	})

	t.Run("it cannot create a tenant outside its pattern", func(t *testing.T) {
		// Checked against the slug in the body, the only place the
		// tenant is named on this route.
		h.adminRequestAs(t, scopedKey, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": "elsewhere-" + randSuffix(t), "name": "Not mine"}).
			requireStatus(t, http.StatusForbidden)
	})

	t.Run("listing shows only its own tenants", func(t *testing.T) {
		outside := h.createTenant(t, nil)
		inside := "scoped-" + randSuffix(t)
		h.adminRequestAs(t, scopedKey, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": inside, "name": "Mine"}).requireStatus(t, http.StatusCreated)

		r := h.adminRequestAs(t, scopedKey, http.MethodGet, "/admin/tenants", nil)
		r.requireStatus(t, http.StatusOK)
		var listed []struct {
			Slug string `json:"slug"`
		}
		r.decode(t, &listed)

		var sawMine bool
		for _, l := range listed {
			// The slug list is the customer list; a scope that leaks it
			// has given away what it exists to hide.
			if l.Slug == outside.Slug {
				t.Errorf("a scoped key saw tenant %q, outside its pattern", l.Slug)
			}
			if l.Slug == inside {
				sawMine = true
			}
		}
		if !sawMine {
			t.Error("the scoped key cannot see its own tenant")
		}
	})
}

// Disabling and purging share a route but not a permission.
func TestAdminKeyPurgeIsItsOwnCapability(t *testing.T) {
	disabler := adminkey.Key{
		Name:         "disabler",
		Secret:       "test-disabler-key-0123456789",
		Capabilities: []string{"tenants:disable", "tenants:create"},
	}
	h := newHarness(t, false, append(testKeys(), disabler)...)

	slug := "purge-scope-" + randSuffix(t)
	h.adminRequestAs(t, disabler.Secret, http.MethodPost, "/admin/tenants",
		map[string]any{"slug": slug, "name": "Doomed"}).requireStatus(t, http.StatusCreated)

	// Disabling is within reach.
	h.adminRequestAs(t, disabler.Secret, http.MethodDelete, "/admin/tenants/"+slug, nil).
		requireStatus(t, http.StatusOK)

	// Destroying it is not, though it is the same route and method.
	r := h.adminRequestAs(t, disabler.Secret, http.MethodDelete, "/admin/tenants/"+slug+"?purge=true", nil)
	r.requireStatus(t, http.StatusForbidden)
	if msg := r.errorMessage(t); !strings.Contains(msg, string(adminkey.TenantsPurge)) {
		t.Errorf("message = %q, want it to name %q", msg, adminkey.TenantsPurge)
	}

	// The tenant is still there to prove the refusal did nothing.
	h.adminRequest(t, http.MethodGet, "/admin/tenants/"+slug, nil).requireStatus(t, http.StatusOK)

	// A key that holds the capability goes through.
	h.adminRequestAs(t, purgerKey, http.MethodDelete, "/admin/tenants/"+slug+"?purge=true", nil).
		requireStatus(t, http.StatusOK)
}

// The router's two guards are what keep the capability model honest as
// routes are added later: a tenant-scoped route cannot be registered as
// global (which would skip the tenant check), and a route with no slug
// cannot be registered as scoped (where the check would always fail).
func TestAdminRouterRefusesMisregisteredRoutes(t *testing.T) {
	noop := func(http.ResponseWriter, *http.Request) {}

	t.Run("scoped route registered as global", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("registering a {slug} route as global did not panic")
			}
		}()
		adminRouter{mux: http.NewServeMux()}.
			handleGlobal("GET /admin/tenants/{slug}/thing", adminkey.TenantsRead, noop)
	})

	t.Run("global route registered as scoped", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("registering a slugless route as scoped did not panic")
			}
		}()
		adminRouter{mux: http.NewServeMux()}.
			handle("GET /admin/thing", adminkey.TenantsRead, noop)
	})
}
