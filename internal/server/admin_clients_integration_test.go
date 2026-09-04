package server

import (
	"net/http"
	"net/url"
	"testing"
)

// Rotating an OAuth2 client secret (#9). The point of the endpoint is
// that the client keeps its identity: a secret that was lost — or
// leaked — is replaced without churning the client_id every consumer is
// configured with. So the assertions are about the id surviving and the
// two secrets swapping places at the token endpoint, which is the only
// place a client secret means anything.

// createClient registers a client through the admin API and returns its
// id and (for confidential clients) the secret shown exactly once.
func (h *harness) createClient(t *testing.T, tn *testTenant, public bool) (id, secret string) {
	t.Helper()
	r := h.adminRequest(t, http.MethodPost, "/admin/tenants/"+tn.Slug+"/clients", map[string]any{
		"name":          "Rotation client",
		"redirect_uris": []string{"https://client.example.com/cb"},
		"public":        public,
	})
	if r.Status != http.StatusCreated {
		t.Fatalf("create client: status %d body %s", r.Status, r.Body)
	}
	var created struct {
		Client struct {
			ID string `json:"client_id"`
		} `json:"client"`
		Secret string `json:"client_secret"`
	}
	r.decode(t, &created)
	return created.Client.ID, created.Secret
}

// tokenAuth presents client credentials at the token endpoint with a code
// that was never issued. fosite authenticates the client before it looks
// at the grant, so the status separates the two failures: 401 means the
// secret was rejected, 400 means it was accepted and only the bogus code
// failed. That makes it a probe for "does this secret authenticate?"
// without driving a whole authorization flow.
func tokenAuth(t *testing.T, h *harness, tn *testTenant, id, secret string) int {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"redirect_uri":  {"https://client.example.com/cb"},
		"client_id":     {id},
		"client_secret": {secret},
	}
	return h.browser(t, tn).postForm(t, "/oauth2/token", form).Status
}

func TestRotateClientSecret(t *testing.T) {
	h := newHarness(t, false)

	t.Run("client_id survives, the new secret replaces the old", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		id, old := h.createClient(t, tn, false)

		if got := tokenAuth(t, h, tn, id, old); got != http.StatusBadRequest {
			t.Fatalf("the original secret should authenticate: status %d, want %d", got, http.StatusBadRequest)
		}

		r := h.adminRequest(t, http.MethodPost,
			"/admin/tenants/"+tn.Slug+"/clients/"+id+"/rotate-secret", nil)
		if r.Status != http.StatusOK {
			t.Fatalf("rotate: status %d body %s", r.Status, r.Body)
		}
		var rotated struct {
			State    string `json:"state"`
			ClientID string `json:"client_id"`
			Secret   string `json:"client_secret"`
		}
		r.decode(t, &rotated)

		if rotated.ClientID != id {
			t.Errorf("client_id = %q, want %q — rotation must not re-identify the client", rotated.ClientID, id)
		}
		if rotated.State != "rotated" {
			t.Errorf("state = %q, want %q", rotated.State, "rotated")
		}
		if rotated.Secret == "" || rotated.Secret == old {
			t.Fatalf("client_secret = %q, want a fresh secret", rotated.Secret)
		}

		if got := tokenAuth(t, h, tn, id, rotated.Secret); got != http.StatusBadRequest {
			t.Errorf("the rotated secret should authenticate: status %d, want %d", got, http.StatusBadRequest)
		}
		if got := tokenAuth(t, h, tn, id, old); got != http.StatusUnauthorized {
			t.Errorf("the old secret should be rejected: status %d, want %d", got, http.StatusUnauthorized)
		}
	})

	t.Run("the secret is never echoed back afterwards", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		id, _ := h.createClient(t, tn, false)
		h.adminRequest(t, http.MethodPost,
			"/admin/tenants/"+tn.Slug+"/clients/"+id+"/rotate-secret", nil)

		r := h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug+"/clients", nil)
		var clients []map[string]any
		r.decode(t, &clients)
		for _, c := range clients {
			if _, ok := c["client_secret"]; ok {
				t.Errorf("listing a client exposed a secret: %v", c)
			}
			if _, ok := c["secret_hash"]; ok {
				t.Errorf("listing a client exposed a secret hash: %v", c)
			}
		}
	})

	t.Run("public clients have no secret to rotate", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		id, secret := h.createClient(t, tn, true)
		if secret != "" {
			t.Fatalf("a public client was given a secret: %q", secret)
		}

		r := h.adminRequest(t, http.MethodPost,
			"/admin/tenants/"+tn.Slug+"/clients/"+id+"/rotate-secret", nil)
		if r.Status != http.StatusConflict {
			t.Fatalf("rotate a public client: status %d body %s, want %d",
				r.Status, r.Body, http.StatusConflict)
		}
	})

	t.Run("unknown client and unknown tenant are 404", func(t *testing.T) {
		tn := h.createTenant(t, nil)
		r := h.adminRequest(t, http.MethodPost,
			"/admin/tenants/"+tn.Slug+"/clients/pc_missing/rotate-secret", nil)
		if r.Status != http.StatusNotFound {
			t.Errorf("unknown client: status %d body %s, want %d", r.Status, r.Body, http.StatusNotFound)
		}

		r = h.adminRequest(t, http.MethodPost,
			"/admin/tenants/no-such-tenant/clients/pc_whatever/rotate-secret", nil)
		if r.Status != http.StatusNotFound {
			t.Errorf("unknown tenant: status %d body %s, want %d", r.Status, r.Body, http.StatusNotFound)
		}
	})

	t.Run("a client of another tenant is invisible", func(t *testing.T) {
		owner := h.createTenant(t, nil)
		other := h.createTenant(t, nil)
		id, _ := h.createClient(t, owner, false)

		r := h.adminRequest(t, http.MethodPost,
			"/admin/tenants/"+other.Slug+"/clients/"+id+"/rotate-secret", nil)
		if r.Status != http.StatusNotFound {
			t.Errorf("cross-tenant rotate: status %d body %s, want %d",
				r.Status, r.Body, http.StatusNotFound)
		}
	})
}
