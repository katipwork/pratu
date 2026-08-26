package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	oauth2pkg "github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/storage"
)

// The OAuth2/OIDC provider endpoints. Everything is tenant-scoped: the
// issuer is the tenant hostname (ADR 0003), and the Hydra-style handshake
// parks the authorization request in a Login/Consent Challenge until the
// tenant's login UI proves a user and accepts it.

// requireOAuth guards against a deployment without a configured system
// secret (the provider is then disabled).
func (a *publicAPI) requireOAuth(w http.ResponseWriter) bool {
	if a.providers == nil {
		writeError(w, http.StatusServiceUnavailable, "OAuth2 is disabled: no oauth2.system_secret configured")
		return false
	}
	return true
}

func issuerFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (a *publicAPI) oauthDiscovery(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	issuer := issuerFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/auth",
		"token_endpoint":                        issuer + "/oauth2/token",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"scopes_supported":                      []string{"openid", "offline_access", "profile", "email"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

func (a *publicAPI) oauthJWKS(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	var payload any
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		// Ensure the tenant has a key before rendering the set.
		if _, err := storage.ActiveTenantKey(r.Context(), tx, t.ID); err != nil {
			return err
		}
		set, err := oauth2pkg.JWKS(r.Context(), tx)
		payload = set
		return err
	})
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// oauthAuthorize is the authorization endpoint: it validates the request
// via fosite, parks it in a challenge, and redirects the browser to the
// tenant's login UI.
func (a *publicAPI) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	if !a.allow(w, r, "flow:ip:"+clientIP(r), limitFlowCreatePerIP, time.Minute) {
		return
	}
	if t.Config.LoginURL == "" {
		writeError(w, http.StatusBadRequest, "tenant has no login_url configured; OAuth2 flows need a login UI")
		return
	}
	issuer := issuerFromRequest(r)

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		octx := storage.WithOAuthTx(r.Context(), tx, t.ID)
		prov, err := a.providers.For(octx, tx, t.ID, issuer)
		if err != nil {
			return err
		}
		ar, err := prov.NewAuthorizeRequest(octx, r)
		if err != nil {
			prov.WriteAuthorizeError(octx, w, ar, err)
			return nil
		}
		f, err := storage.CreateFlow(octx, tx, t.ID, flow.KindOAuth2, flow.OAuth2Context{
			Query: r.URL.RawQuery,
		}, false)
		if err != nil {
			return err
		}
		sep := "?"
		if strings.Contains(t.Config.LoginURL, "?") {
			sep = "&"
		}
		http.Redirect(w, r, t.Config.LoginURL+sep+"login_challenge="+f.ID, http.StatusFound)
		return nil
	})
	if err != nil {
		internalError(w, err)
	}
}

// oauthChallengeInfo lets the login UI describe the pending request.
func (a *publicAPI) oauthChallengeInfo(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	challenge := r.PathValue("challenge")

	var resp map[string]any
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, challenge, flow.KindOAuth2)
		if err != nil {
			return err
		}
		var fctx flow.OAuth2Context
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		q, err := url.ParseQuery(fctx.Query)
		if err != nil {
			return err
		}
		client, err := storage.FindOAuth2Client(r.Context(), tx, q.Get("client_id"))
		if err != nil {
			return err
		}
		resp = map[string]any{
			"challenge":        f.ID,
			"client_id":        client.ID,
			"client_name":      client.Name,
			"first_party":      client.FirstParty,
			"requested_scopes": strings.Fields(q.Get("scope")),
			"expires_at":       f.ExpiresAt,
		}
		return nil
	})
	if errors.Is(err, storage.ErrFlowNotFound) || errors.Is(err, storage.ErrClientNotFound) {
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// oauthAccept records that the tenant's UI proved a user (session token)
// and — for now — that consent covers the requested scopes. First-party
// clients skip the consent screen by policy; the accept is the same.
func (a *publicAPI) oauthAccept(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	challenge := r.URL.Query().Get("challenge")
	issuer := issuerFromRequest(r)

	var redirectTo string
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		f, err := storage.GetFlow(r.Context(), tx, challenge, flow.KindOAuth2)
		if err != nil {
			return err
		}
		var fctx flow.OAuth2Context
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		identifier, err := storage.IdentifierForIdentity(r.Context(), tx, sess.IdentityID)
		if err != nil {
			return err
		}
		fctx.IdentityID = sess.IdentityID
		fctx.AAL = sess.AAL
		fctx.Granted = true
		if strings.Contains(identifier, "@") {
			fctx.Email = identifier
		}
		if err := storage.UpdateFlowContext(r.Context(), tx, f.ID, fctx); err != nil {
			return err
		}
		redirectTo = issuer + "/oauth2/auth/finish?challenge=" + f.ID
		return nil
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required: log the user in first")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case errors.Is(err, storage.ErrFlowNotFound):
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirectTo})
	}
}

// oauthFinish resumes the parked authorization request and sends the
// browser back to the client with an authorization code.
func (a *publicAPI) oauthFinish(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	challenge := r.URL.Query().Get("challenge")
	issuer := issuerFromRequest(r)

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		octx := storage.WithOAuthTx(r.Context(), tx, t.ID)
		f, err := storage.GetFlow(octx, tx, challenge, flow.KindOAuth2)
		if err != nil {
			return err
		}
		var fctx flow.OAuth2Context
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		if !fctx.Granted {
			return errChallengeNotAccepted
		}
		prov, err := a.providers.For(octx, tx, t.ID, issuer)
		if err != nil {
			return err
		}
		replay, err := http.NewRequestWithContext(octx, http.MethodGet, "/oauth2/auth?"+fctx.Query, nil)
		if err != nil {
			return err
		}
		ar, err := prov.NewAuthorizeRequest(octx, replay)
		if err != nil {
			prov.WriteAuthorizeError(octx, w, ar, err)
			return nil
		}
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
		sess := oauth2pkg.NewSession(issuer, fctx.IdentityID, ar.GetClient().GetID(), t.ID, fctx.AAL, fctx.Email)
		resp, err := prov.NewAuthorizeResponse(octx, ar, sess)
		if err != nil {
			prov.WriteAuthorizeError(octx, w, ar, err)
			return nil
		}
		if err := storage.DeleteFlow(octx, tx, f.ID); err != nil {
			return err
		}
		prov.WriteAuthorizeResponse(octx, w, ar, resp)
		return nil
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
	case errors.Is(err, errChallengeNotAccepted):
		writeError(w, http.StatusBadRequest, "challenge has not been accepted")
	case err != nil:
		internalError(w, err)
	}
}

func (a *publicAPI) oauthToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	issuer := issuerFromRequest(r)

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		octx := storage.WithOAuthTx(r.Context(), tx, t.ID)
		prov, err := a.providers.For(octx, tx, t.ID, issuer)
		if err != nil {
			return err
		}
		accessReq, err := prov.NewAccessRequest(octx, r, oauth2pkg.EmptySession())
		if err != nil {
			prov.WriteAccessError(octx, w, accessReq, err)
			return nil
		}
		resp, err := prov.NewAccessResponse(octx, accessReq)
		if err != nil {
			prov.WriteAccessError(octx, w, accessReq, err)
			return nil
		}
		prov.WriteAccessResponse(octx, w, accessReq, resp)
		return nil
	})
	if err != nil {
		internalError(w, err)
	}
}

func (a *publicAPI) oauthIntrospect(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	issuer := issuerFromRequest(r)

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		octx := storage.WithOAuthTx(r.Context(), tx, t.ID)
		prov, err := a.providers.For(octx, tx, t.ID, issuer)
		if err != nil {
			return err
		}
		ir, err := prov.NewIntrospectionRequest(octx, r, oauth2pkg.EmptySession())
		if err != nil {
			prov.WriteIntrospectionError(octx, w, err)
			return nil
		}
		prov.WriteIntrospectionResponse(octx, w, ir)
		return nil
	})
	if err != nil {
		internalError(w, err)
	}
}

func (a *publicAPI) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.requireOAuth(w) {
		return
	}
	t := requestTenant(r)
	issuer := issuerFromRequest(r)

	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		octx := storage.WithOAuthTx(r.Context(), tx, t.ID)
		prov, err := a.providers.For(octx, tx, t.ID, issuer)
		if err != nil {
			return err
		}
		revErr := prov.NewRevocationRequest(octx, r)
		prov.WriteRevocationResponse(octx, w, revErr)
		return nil
	})
	if err != nil {
		internalError(w, err)
	}
}

var errChallengeNotAccepted = errors.New("challenge not accepted")
