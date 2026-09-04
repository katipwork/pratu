package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Editing an OAuth2 client (#7). The endpoint exists so that adding a
// scope or a redirect_uri stays a metadata change: before it, the only
// way to alter either was DELETE + re-create, which churned the
// client_id and secret every consumer is configured with. So the tests
// assert two things at once — that the edit reaches the authorization
// endpoint, and that the credentials came through it untouched.

// patchClient edits a client and returns the response as the admin API
// gave it back.
func (h *harness) patchClient(t *testing.T, tn *testTenant, id string, body map[string]any) *resp {
	t.Helper()
	return h.adminRequest(t, http.MethodPatch,
		"/admin/tenants/"+tn.Slug+"/clients/"+id, body)
}

// authorize drives an authorization request as a browser would. A client
// whose registration accepts the redirect_uri and scope is sent on to the
// tenant's login screen; one that does not is refused before that.
func authorize(t *testing.T, h *harness, tn *testTenant, clientID, redirectURI, scope string) *resp {
	t.Helper()
	q := url.Values{
		"client_id":     {clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"scope":         {scope},
		"state":         {"patch-state"},
	}
	return h.browser(t, tn).getHTML(t, "/oauth2/auth?"+q.Encode())
}

func reachedLoginScreen(r *resp) bool {
	return r.Status == http.StatusFound && strings.HasPrefix(r.Location, loginScreen)
}

// patchTenant is a tenant with a login screen of its own, so an accepted
// authorization request has somewhere recognisable to land.
func (h *harness) patchTenant(t *testing.T) *testTenant {
	t.Helper()
	return h.createTenant(t, map[string]any{
		"verification": "deferred",
		"ui":           map[string]any{"login_url": loginScreen},
	})
}

func TestPatchClient(t *testing.T) {
	h := newHarness(t, false)

	t.Run("a new redirect_uri becomes usable, credentials untouched", func(t *testing.T) {
		tn := h.patchTenant(t)
		id, secret := h.createClient(t, tn, false)
		const added = "https://custom.example.com/cb"

		if reachedLoginScreen(authorize(t, h, tn, id, added, "openid")) {
			t.Fatal("an unregistered redirect_uri was accepted before the patch")
		}

		r := h.patchClient(t, tn, id, map[string]any{
			"redirect_uris": []string{"https://client.example.com/cb", added},
		})
		if r.Status != http.StatusOK {
			t.Fatalf("patch: status %d body %s", r.Status, r.Body)
		}
		var patched struct {
			ID           string   `json:"client_id"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		r.decode(t, &patched)
		if patched.ID != id {
			t.Errorf("client_id = %q, want %q — an edit must not re-identify the client", patched.ID, id)
		}
		if len(patched.RedirectURIs) != 2 {
			t.Errorf("redirect_uris = %v, want both", patched.RedirectURIs)
		}

		if !reachedLoginScreen(authorize(t, h, tn, id, added, "openid")) {
			t.Error("the added redirect_uri is still refused by the authorization endpoint")
		}
		if !reachedLoginScreen(authorize(t, h, tn, id, "https://client.example.com/cb", "openid")) {
			t.Error("the original redirect_uri stopped working")
		}
		// The whole point: the secret survives a metadata edit.
		if got := tokenAuth(t, h, tn, id, secret); got != http.StatusBadRequest {
			t.Errorf("the secret stopped authenticating after a patch: status %d, want %d",
				got, http.StatusBadRequest)
		}
	})

	t.Run("a new scope becomes grantable", func(t *testing.T) {
		tn := h.patchTenant(t)
		id, _ := h.createClient(t, tn, false)

		if reachedLoginScreen(authorize(t, h, tn, id, "https://client.example.com/cb", "openid pilla.api")) {
			t.Fatal("an unregistered scope was accepted before the patch")
		}

		r := h.patchClient(t, tn, id, map[string]any{
			"scopes": []string{"openid", "offline_access", "profile", "email", "pilla.api"},
		})
		if r.Status != http.StatusOK {
			t.Fatalf("patch: status %d body %s", r.Status, r.Body)
		}
		if !reachedLoginScreen(authorize(t, h, tn, id, "https://client.example.com/cb", "openid pilla.api")) {
			t.Error("the added scope is still refused by the authorization endpoint")
		}
	})

	t.Run("absent keys are left alone, present keys replace outright", func(t *testing.T) {
		tn := h.patchTenant(t)
		id, _ := h.createClient(t, tn, false)

		r := h.patchClient(t, tn, id, map[string]any{"name": "Renamed"})
		var patched struct {
			Name         string   `json:"name"`
			RedirectURIs []string `json:"redirect_uris"`
			Scopes       []string `json:"scopes"`
		}
		r.decode(t, &patched)
		if patched.Name != "Renamed" {
			t.Errorf("name = %q, want %q", patched.Name, "Renamed")
		}
		if len(patched.RedirectURIs) != 1 || patched.RedirectURIs[0] != "https://client.example.com/cb" {
			t.Errorf("redirect_uris = %v, want the untouched original", patched.RedirectURIs)
		}
		if len(patched.Scopes) != 4 {
			t.Errorf("scopes = %v, want the untouched defaults", patched.Scopes)
		}

		// A present key is a replacement, not a merge.
		r = h.patchClient(t, tn, id, map[string]any{"scopes": []string{"openid"}})
		r.decode(t, &patched)
		if len(patched.Scopes) != 1 || patched.Scopes[0] != "openid" {
			t.Errorf("scopes = %v, want exactly the sent value", patched.Scopes)
		}
		if patched.Name != "Renamed" {
			t.Errorf("name = %q, want the earlier patch to survive", patched.Name)
		}
	})

	// Identity and authentication are refused outright rather than
	// quietly dropped: a caller that thinks it just turned a client
	// public, or set its own secret, is told it did not.
	t.Run("editing identity or authentication is refused, not ignored", func(t *testing.T) {
		tn := h.patchTenant(t)
		id, secret := h.createClient(t, tn, false)

		for _, field := range []struct {
			name string
			body map[string]any
		}{
			{"client_id", map[string]any{"client_id": "pc_hijacked"}},
			{"client_secret", map[string]any{"client_secret": "psec_chosen-by-the-caller"}},
			{"public", map[string]any{"public": true}},
			{"first_party", map[string]any{"first_party": true}},
		} {
			t.Run(field.name, func(t *testing.T) {
				r := h.patchClient(t, tn, id, field.body)
				if r.Status != http.StatusBadRequest {
					t.Errorf("status %d body %s, want %d", r.Status, r.Body, http.StatusBadRequest)
				}
			})
		}

		// And none of those attempts left a mark.
		r := h.patchClient(t, tn, id, map[string]any{"name": "Still confidential"})
		var patched struct {
			ID         string `json:"client_id"`
			Public     bool   `json:"public"`
			FirstParty bool   `json:"first_party"`
		}
		r.decode(t, &patched)
		if patched.ID != id || patched.Public || patched.FirstParty {
			t.Errorf("client = %+v, want id %q, confidential, third-party", patched, id)
		}
		if got := tokenAuth(t, h, tn, id, secret); got != http.StatusBadRequest {
			t.Errorf("the original secret stopped authenticating: status %d, want %d",
				got, http.StatusBadRequest)
		}
		if got := tokenAuth(t, h, tn, id, "psec_chosen-by-the-caller"); got != http.StatusUnauthorized {
			t.Error("a caller-chosen secret was accepted")
		}
	})

	t.Run("a client cannot be patched into a shape it could not be created in", func(t *testing.T) {
		tn := h.patchTenant(t)
		id, _ := h.createClient(t, tn, false)

		for _, tc := range []struct {
			name string
			body map[string]any
		}{
			{"emptied name", map[string]any{"name": ""}},
			{"emptied redirect_uris", map[string]any{"redirect_uris": []string{}}},
			{"relative redirect_uri", map[string]any{"redirect_uris": []string{"/cb"}}},
			{"fragment in redirect_uri", map[string]any{"redirect_uris": []string{"https://a.example.com/cb#x"}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := h.patchClient(t, tn, id, tc.body)
				if r.Status != http.StatusBadRequest {
					t.Errorf("status %d body %s, want %d", r.Status, r.Body, http.StatusBadRequest)
				}
			})
		}
	})

	t.Run("unknown and cross-tenant clients are 404", func(t *testing.T) {
		owner := h.patchTenant(t)
		other := h.patchTenant(t)
		id, _ := h.createClient(t, owner, false)

		r := h.patchClient(t, owner, "pc_missing", map[string]any{"name": "x"})
		if r.Status != http.StatusNotFound {
			t.Errorf("unknown client: status %d body %s, want %d", r.Status, r.Body, http.StatusNotFound)
		}
		r = h.patchClient(t, other, id, map[string]any{"name": "x"})
		if r.Status != http.StatusNotFound {
			t.Errorf("cross-tenant patch: status %d body %s, want %d", r.Status, r.Body, http.StatusNotFound)
		}
	})
}
