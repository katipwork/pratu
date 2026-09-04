package server

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/katipwork/pratu/internal/tenant"
)

// Per-tenant login throttle (#11). The default is strict because it is
// brute-force protection; the point of the knob is that a test tenant,
// whose suite signs the same handful of identities in over and over, can
// be given room without loosening anything for a production tenant.

// loginAttempts fires n failed password logins for one identifier and
// returns the status of each, so a test can see exactly where the
// budget ran out.
func loginAttempts(t *testing.T, b *browser, identifier string, n int) []int {
	t.Helper()
	f := b.createFlow(t, "/self-service/login/browser")
	var out []int
	for i := 0; i < n; i++ {
		r := b.postJSON(t, "/self-service/login?flow="+f.ID, map[string]any{
			"method":     "password",
			"identifier": identifier,
			"password":   "wrong-password-entirely",
			"csrf_token": f.CSRFToken,
		})
		out = append(out, r.Status)
	}
	return out
}

// firstThrottled reports the 1-based attempt that was refused, or 0.
func firstThrottled(statuses []int) int {
	for i, s := range statuses {
		if s == http.StatusTooManyRequests {
			return i + 1
		}
	}
	return 0
}

func TestLoginThrottleConfig(t *testing.T) {
	h := newHarness(t, false)

	t.Run("a tenant with no config gets the strict default", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn).withIP("198.51.100.11")

		got := firstThrottled(loginAttempts(t, b, testEmail(t), tenant.DefaultLoginMaxAttempts+1))
		if want := tenant.DefaultLoginMaxAttempts + 1; got != want {
			t.Errorf("throttled at attempt %d, want %d (the default budget)", got, want)
		}
	})

	t.Run("a relaxed tenant keeps going where the default would stop", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{
			"verification":   "deferred",
			"login_throttle": map[string]any{"max_attempts": 20},
		})
		b := h.browser(t, tn).withIP("198.51.100.12")

		// Exactly the case from the issue: a suite signing in more often
		// than the default allows, failing on the throttle rather than
		// on what it asserts.
		statuses := loginAttempts(t, b, testEmail(t), tenant.DefaultLoginMaxAttempts+3)
		if n := firstThrottled(statuses); n != 0 {
			t.Errorf("throttled at attempt %d, want the relaxed budget to hold", n)
		}
	})

	t.Run("a stricter tenant stops sooner", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{
			"verification":   "deferred",
			"login_throttle": map[string]any{"max_attempts": 2},
		})
		b := h.browser(t, tn).withIP("198.51.100.13")

		if got := firstThrottled(loginAttempts(t, b, testEmail(t), 4)); got != 3 {
			t.Errorf("throttled at attempt %d, want 3", got)
		}
	})

	// The budget is keyed by tenant as well as identifier, so relaxing
	// one tenant cannot spend — or widen — another's.
	t.Run("the budget does not leak between tenants", func(t *testing.T) {
		strict := h.createTenant(t, map[string]any{"verification": "deferred"})
		relaxed := h.createTenant(t, map[string]any{
			"verification":   "deferred",
			"login_throttle": map[string]any{"max_attempts": 50},
		})
		identifier := testEmail(t)

		relaxedBrowser := h.browser(t, relaxed).withIP("198.51.100.14")
		if n := firstThrottled(loginAttempts(t, relaxedBrowser, identifier, 8)); n != 0 {
			t.Fatalf("the relaxed tenant was throttled at attempt %d", n)
		}

		// Same identifier, strict tenant: its own untouched budget.
		strictBrowser := h.browser(t, strict).withIP("198.51.100.15")
		got := firstThrottled(loginAttempts(t, strictBrowser, identifier, tenant.DefaultLoginMaxAttempts+1))
		if want := tenant.DefaultLoginMaxAttempts + 1; got != want {
			t.Errorf("throttled at attempt %d, want %d — the strict tenant kept its own budget", got, want)
		}
	})

	t.Run("the window is what the tenant says it is", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{
			"verification":   "deferred",
			"login_throttle": map[string]any{"max_attempts": 1, "window_seconds": 1},
		})
		b := h.browser(t, tn).withIP("198.51.100.16")
		identifier := testEmail(t)

		if got := firstThrottled(loginAttempts(t, b, identifier, 2)); got != 2 {
			t.Fatalf("throttled at attempt %d, want 2", got)
		}
		// Windows are fixed and aligned, so waiting past the boundary
		// hands the budget back.
		time.Sleep(1100 * time.Millisecond)
		if got := firstThrottled(loginAttempts(t, b, identifier, 1)); got != 0 {
			t.Error("the budget did not come back after the configured window")
		}
	})

	t.Run("the throttle is patchable on a live tenant", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn).withIP("198.51.100.17")

		r := h.adminRequest(t, http.MethodPatch, "/admin/tenants/"+tn.Slug,
			map[string]any{"login_throttle": map[string]any{"max_attempts": 40}})
		if r.Status != http.StatusOK {
			t.Fatalf("patch: status %d body %s", r.Status, r.Body)
		}
		if n := firstThrottled(loginAttempts(t, b, testEmail(t), tenant.DefaultLoginMaxAttempts+3)); n != 0 {
			t.Errorf("throttled at attempt %d after relaxing the tenant", n)
		}
	})

	t.Run("nonsense is refused", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			value map[string]any
		}{
			{"negative attempts", map[string]any{"max_attempts": -1}},
			{"negative window", map[string]any{"window_seconds": -1}},
			// A window meant as 60 seconds, typed as 60000 milliseconds:
			// most of a day's lockout, and plainly not what was meant.
			{"seconds mistaken for milliseconds", map[string]any{"window_seconds": 60000}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// A unique slug, so a validation regression shows up as a
				// 201 rather than as a 409 from an earlier run's leftovers.
				r := h.adminRequest(t, http.MethodPost, "/admin/tenants", map[string]any{
					"slug":           fmt.Sprintf("throttle-invalid-%d", time.Now().UnixNano()),
					"name":           "Invalid",
					"login_throttle": tc.value,
				})
				if r.Status != http.StatusBadRequest {
					t.Errorf("status %d body %s, want %d", r.Status, r.Body, http.StatusBadRequest)
				}
			})
		}
	})
}

// The per-IP login limit is platform-wide on purpose: attackers spread
// across tenants, so it is not a per-tenant knob and relaxing a tenant
// must not touch it.
func TestLoginThrottleLeavesPerIPLimitAlone(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, map[string]any{
		"verification":   "deferred",
		"login_throttle": map[string]any{"max_attempts": 1_000_000},
	})
	b := h.browser(t, tn).withIP("198.51.100.18")

	f := b.createFlow(t, "/self-service/login/browser")
	throttled := false
	// Each attempt uses a fresh identifier, so only the per-IP limit can
	// be what stops it.
	for i := 0; i < limitLoginPerIP+2; i++ {
		r := b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
			"method":     {"password"},
			"identifier": {testEmail(t)},
			"password":   {"wrong-password-entirely"},
			"csrf_token": {f.CSRFToken},
		})
		if r.Status == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Error("a tenant relaxed its own throttle and escaped the platform-wide per-IP limit")
	}
}
