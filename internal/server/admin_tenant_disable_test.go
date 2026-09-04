package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/storage"
)

// Disabling a Tenant (#8, ADR 0008). The contract has two halves that
// have to hold at once: the public surface closes completely, and the
// admin surface stays open so an operator can see and undo what they
// did. Nothing is destroyed, so enabling brings the Tenant back whole.

func (h *harness) disableTenant(t *testing.T, tn *testTenant) *resp {
	t.Helper()
	return h.adminRequest(t, http.MethodDelete, "/admin/tenants/"+tn.Slug, nil)
}

func (h *harness) enableTenant(t *testing.T, tn *testTenant) *resp {
	t.Helper()
	return h.adminRequest(t, http.MethodPost, "/admin/tenants/"+tn.Slug+"/enable", nil)
}

func (h *harness) purgeTenant(t *testing.T, tn *testTenant) *resp {
	t.Helper()
	return h.adminRequest(t, http.MethodDelete, "/admin/tenants/"+tn.Slug+"?purge=true", nil)
}

// countIdentities reads the tenant's own rows under its RLS context,
// which is the only way to see them at all.
func (h *harness) countIdentities(t *testing.T, tenantID string) int {
	t.Helper()
	var n int
	err := storage.InTenant(context.Background(), h.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM identities`).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (h *harness) countRateLimits(t *testing.T, tenantID string) int {
	t.Helper()
	var n int
	err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM rate_limits WHERE key LIKE '%:' || $1 || ':%'`, tenantID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// disabledAt reads the field the whole feature turns on.
func disabledAt(t *testing.T, r *resp) string {
	t.Helper()
	var body struct {
		DisabledAt string `json:"disabled_at"`
	}
	r.decode(t, &body)
	return body.DisabledAt
}

func TestDisableTenant(t *testing.T) {
	h := newHarness(t, false)

	t.Run("the public surface closes and reopens", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)

		b.getJSON(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)

		r := h.disableTenant(t, tn)
		if r.Status != http.StatusOK {
			t.Fatalf("disable: status %d body %s", r.Status, r.Body)
		}
		if disabledAt(t, r) == "" {
			t.Error("the disabled tenant came back without a disabled_at")
		}

		// The hostname no longer resolves, so every public surface the
		// tenant had is closed — not just the flow endpoints.
		for _, path := range []string{
			"/self-service/login/browser",
			"/.well-known/openid-configuration",
			"/.well-known/jwks.json",
		} {
			if got := b.getJSON(t, path).Status; got != http.StatusNotFound {
				t.Errorf("%s on a disabled tenant: status %d, want %d", path, got, http.StatusNotFound)
			}
		}

		if r := h.enableTenant(t, tn); r.Status != http.StatusOK {
			t.Fatalf("enable: status %d body %s", r.Status, r.Body)
		} else if got := disabledAt(t, r); got != "" {
			t.Errorf("disabled_at = %q after enabling, want it gone", got)
		}
		b.getJSON(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)
	})

	// A custom domain is the other way in (ADR 0003), and it has its own
	// query, so closing the slug route says nothing about it.
	t.Run("a custom domain closes too", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		domain := fmt.Sprintf("custom-%d.example.net", time.Now().UnixNano())
		if r := h.adminRequest(t, http.MethodPut,
			"/admin/tenants/"+tn.Slug+"/domains/"+domain, nil); r.Status != http.StatusOK {
			t.Fatalf("claim domain: status %d body %s", r.Status, r.Body)
		}
		viaDomain := h.browser(t, &testTenant{Slug: tn.Slug, Host: domain, ID: tn.ID})
		viaDomain.getJSON(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)

		h.disableTenant(t, tn)
		if got := viaDomain.getJSON(t, "/self-service/login/browser").Status; got != http.StatusNotFound {
			t.Errorf("custom domain on a disabled tenant: status %d, want %d", got, http.StatusNotFound)
		}

		// The claim survived, so enabling restores that route as well.
		h.enableTenant(t, tn)
		viaDomain.getJSON(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)
	})

	t.Run("a session survives disabling and works again after enabling", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)
		registerIdentityWith(t, b, fmt.Sprintf("disable-%d@example.com", time.Now().UnixNano()))

		b.getJSON(t, "/sessions/whoami").requireStatus(t, http.StatusOK)

		h.disableTenant(t, tn)
		// Inert, because the tenant resolves from nowhere — not revoked.
		if got := b.getJSON(t, "/sessions/whoami").Status; got != http.StatusNotFound {
			t.Errorf("whoami on a disabled tenant: status %d, want %d", got, http.StatusNotFound)
		}

		h.enableTenant(t, tn)
		b.getJSON(t, "/sessions/whoami").requireStatus(t, http.StatusOK)
	})

	t.Run("the admin surface stays open on a disabled tenant", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		h.disableTenant(t, tn)

		// An operator who cannot see what they closed cannot undo it.
		r := h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug, nil)
		if r.Status != http.StatusOK {
			t.Fatalf("get a disabled tenant: status %d body %s", r.Status, r.Body)
		}
		if disabledAt(t, r) == "" {
			t.Error("the admin API hides that the tenant is disabled")
		}

		r = h.adminRequest(t, http.MethodPatch, "/admin/tenants/"+tn.Slug,
			map[string]any{"name": "Repaired while closed"})
		if r.Status != http.StatusOK {
			t.Errorf("patch a disabled tenant: status %d body %s", r.Status, r.Body)
		}
		// Sub-resources too, so the tenant can be repaired before reopening.
		r = h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug+"/clients", nil)
		if r.Status != http.StatusOK {
			t.Errorf("list clients on a disabled tenant: status %d body %s", r.Status, r.Body)
		}
	})

	t.Run("disabling is idempotent and keeps the original timestamp", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})

		first := disabledAt(t, h.disableTenant(t, tn))
		second := h.disableTenant(t, tn)
		if second.Status != http.StatusOK {
			t.Fatalf("disabling twice: status %d body %s, want %d",
				second.Status, second.Body, http.StatusOK)
		}
		if got := disabledAt(t, second); got != first {
			t.Errorf("disabled_at = %q on the second call, want the original %q", got, first)
		}
	})

	t.Run("a tenant that was never there is 404", func(t *testing.T) {
		absent := &testTenant{Slug: "no-such-tenant"}
		if got := h.disableTenant(t, absent).Status; got != http.StatusNotFound {
			t.Errorf("disable: status %d, want %d", got, http.StatusNotFound)
		}
		if got := h.enableTenant(t, absent).Status; got != http.StatusNotFound {
			t.Errorf("enable: status %d, want %d", got, http.StatusNotFound)
		}
	})

	t.Run("the slug stays held, and the refusal says why", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		h.disableTenant(t, tn)

		r := h.adminRequest(t, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": tn.Slug, "name": "Reused"})
		if r.Status != http.StatusConflict {
			t.Fatalf("re-creating a disabled tenant's slug: status %d body %s, want %d",
				r.Status, r.Body, http.StatusConflict)
		}
		// The caller can act on the difference: enable, don't rename.
		if msg := r.errorMessage(t); !strings.Contains(msg, "disabled") {
			t.Errorf("message = %q, want it to say the slug is held by a disabled tenant", msg)
		}
	})

	t.Run("a disabled tenant is still listed", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		h.disableTenant(t, tn)

		r := h.adminRequest(t, http.MethodGet, "/admin/tenants", nil)
		var tenants []struct {
			Slug       string `json:"slug"`
			DisabledAt string `json:"disabled_at"`
		}
		r.decode(t, &tenants)
		for _, listed := range tenants {
			if listed.Slug != tn.Slug {
				continue
			}
			if listed.DisabledAt == "" {
				t.Error("the listed tenant does not show that it is disabled")
			}
			return
		}
		t.Error("a disabled tenant vanished from the tenant list")
	})
}

// Purging is the irreversible half (#8, ADR 0008). It is reachable only
// through the disabled state and only when spelled out, so the tests are
// as much about what it refuses as about what it destroys.
func TestPurgeTenant(t *testing.T) {
	h := newHarness(t, false)

	t.Run("a live tenant is refused, and stays live", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)

		r := h.purgeTenant(t, tn)
		if r.Status != http.StatusConflict {
			t.Fatalf("purge a live tenant: status %d body %s, want %d",
				r.Status, r.Body, http.StatusConflict)
		}
		if msg := r.errorMessage(t); !strings.Contains(msg, "disable") {
			t.Errorf("message = %q, want it to name the step that is missing", msg)
		}
		// Refused means untouched, not half-done.
		b.getJSON(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)
	})

	t.Run("a disabled tenant is destroyed with everything it owns", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)
		registerIdentityWith(t, b, fmt.Sprintf("purge-%d@example.com", time.Now().UnixNano()))

		if got := h.countIdentities(t, tn.ID); got == 0 {
			t.Fatal("no identity to purge; the test proves nothing")
		}
		if got := h.countRateLimits(t, tn.ID); got == 0 {
			t.Fatal("no rate-limit counters to purge; the test proves nothing")
		}

		h.disableTenant(t, tn)
		r := h.purgeTenant(t, tn)
		if r.Status != http.StatusOK {
			t.Fatalf("purge: status %d body %s", r.Status, r.Body)
		}

		// The cascade has to reach through RLS to be worth anything.
		if got := h.countIdentities(t, tn.ID); got != 0 {
			t.Errorf("%d identities survived the purge", got)
		}
		// And the one table no foreign key sweeps up.
		if got := h.countRateLimits(t, tn.ID); got != 0 {
			t.Errorf("%d rate-limit counters survived the purge, keeping the tenant's identifiers", got)
		}
		if got := h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug, nil).Status; got != http.StatusNotFound {
			t.Errorf("the purged tenant is still readable: status %d", got)
		}
	})

	t.Run("purging frees the slug", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		h.disableTenant(t, tn)
		h.purgeTenant(t, tn)

		// This is the whole reason purge exists rather than disable alone.
		r := h.adminRequest(t, http.MethodPost, "/admin/tenants",
			map[string]any{"slug": tn.Slug, "name": "Reprovisioned"})
		if r.Status != http.StatusCreated {
			t.Fatalf("re-creating a purged slug: status %d body %s, want %d",
				r.Status, r.Body, http.StatusCreated)
		}
		// A fresh namespace, not the old one resurrected.
		var recreated struct {
			ID string `json:"id"`
		}
		r.decode(t, &recreated)
		if recreated.ID == tn.ID {
			t.Error("the re-created tenant reused the purged tenant's id")
		}
	})

	t.Run("a purge that cannot be parsed destroys nothing", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)

		r := h.adminRequest(t, http.MethodDelete, "/admin/tenants/"+tn.Slug+"?purge=yes", nil)
		if r.Status != http.StatusBadRequest {
			t.Fatalf("?purge=yes: status %d body %s, want %d",
				r.Status, r.Body, http.StatusBadRequest)
		}
		// Not even disabled: a caller who meant to purge must not be
		// told "done" for something else.
		b.getJSON(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)
	})

	t.Run("purge=false is the soft delete", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		r := h.adminRequest(t, http.MethodDelete, "/admin/tenants/"+tn.Slug+"?purge=false", nil)
		if r.Status != http.StatusOK {
			t.Fatalf("?purge=false: status %d body %s", r.Status, r.Body)
		}
		if disabledAt(t, r) == "" {
			t.Error("?purge=false did not disable the tenant")
		}
		if got := h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug, nil).Status; got != http.StatusOK {
			t.Errorf("the tenant was destroyed by ?purge=false: status %d", got)
		}
	})

	t.Run("a tenant that was never there is 404", func(t *testing.T) {
		got := h.purgeTenant(t, &testTenant{Slug: "no-such-tenant"}).Status
		if got != http.StatusNotFound {
			t.Errorf("status %d, want %d", got, http.StatusNotFound)
		}
	})
}
