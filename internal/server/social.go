package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/social"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Social sign-in (Q13, v1.1). The ladder at the callback:
//  1. a known social identifier logs its identity in;
//  2. otherwise a provider-verified email that matches a VERIFIED address
//     links the social account to that identity — verified email is the
//     only linking basis;
//  3. otherwise a fresh identity registers from the provider's claims,
//     with no password credential.
// Enrolled second factors still apply: social proves only the first
// factor, so the flow is handed over to a held login flow for TOTP/SMS.

func socialRedirectURI(r *http.Request) string {
	return issuerFromRequest(r) + "/self-service/social/callback"
}

// socialStart begins the round trip: browser navigation that 302s to the
// provider with the flow ID as the OAuth2 state.
func (a *publicAPI) socialStart(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "flow:ip:"+clientIP(r), limitFlowCreatePerIP, time.Minute) {
		return
	}
	providerID := r.PathValue("provider")
	// The CSRF cookie is minted now so a later MFA handover can bind its
	// token to this browser.
	if _, err := ensureCSRFCookie(w, r); err != nil {
		internalError(w, err)
		return
	}

	var authURL string
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		p, err := storage.GetSocialProvider(r.Context(), tx, providerID)
		if err != nil {
			return err
		}
		f, err := storage.CreateFlow(r.Context(), tx, t.ID, flow.KindSocial,
			flow.SocialContext{Provider: p.ID}, true)
		if err != nil {
			return err
		}
		authURL, err = social.AuthURL(r.Context(), p, socialRedirectURI(r), f.ID)
		return err
	})
	switch {
	case errors.Is(err, storage.ErrProviderNotFound):
		writeError(w, http.StatusNotFound, "unknown social provider")
	case err != nil:
		internalError(w, err)
	default:
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// socialCallback finishes the round trip. The state parameter is the
// flow ID (unguessable), which is the CSRF binding for this navigation.
func (a *publicAPI) socialCallback(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	if !a.allow(w, r, "login:ip:"+clientIP(r), limitLoginPerIP, time.Minute) {
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	returnTo := t.Config.EffectiveSocialReturnURL()
	fail := func(reason string) {
		if returnTo == "" {
			writeError(w, http.StatusBadRequest, "social sign-in failed: "+reason)
			return
		}
		a.log.Warn("social sign-in failed", "reason", reason)
		http.Redirect(w, r, withParam(returnTo, "error", reason), http.StatusFound)
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		fail("provider_" + errParam)
		return
	}

	// Load the flow and provider, then leave the transaction before the
	// outbound exchange: network calls must not hold a tenant tx.
	var provider *storage.SocialProvider
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, state, flow.KindSocial)
		if err != nil {
			return err
		}
		var fctx flow.SocialContext
		if err := json.Unmarshal(f.Context, &fctx); err != nil {
			return err
		}
		provider, err = storage.GetSocialProvider(r.Context(), tx, fctx.Provider)
		return err
	})
	if errors.Is(err, storage.ErrFlowNotFound) {
		fail("flow_expired")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}

	claims, err := social.Exchange(r.Context(), provider, socialRedirectURI(r), code)
	if err != nil {
		fail("exchange_failed")
		return
	}

	var (
		sess    *session.Session
		token   string
		mfaFlow string
		methods []string
	)
	err = storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		f, err := storage.GetFlow(r.Context(), tx, state, flow.KindSocial)
		if err != nil {
			return err
		}
		if err := storage.DeleteFlow(r.Context(), tx, f.ID); err != nil {
			return err
		}
		identityID, err := a.resolveSocialIdentity(r, tx, t, provider, claims)
		if err != nil {
			return err
		}
		if !mfaHidden(t) {
			methods, err = enrolledFactors(r.Context(), tx, identityID)
			if err != nil {
				return err
			}
			if len(methods) > 0 {
				lf, err := storage.CreateFlow(r.Context(), tx, t.ID, flow.KindLogin,
					flow.LoginContext{IdentityID: identityID, PasswordOK: true}, f.Browser)
				if err != nil {
					return err
				}
				mfaFlow = lf.ID
				return nil
			}
		}
		sess, token, err = storage.CreateSession(r.Context(), tx, t.ID, identityID, session.AAL1, deviceFrom(r))
		return err
	})
	switch {
	case errors.Is(err, storage.ErrFlowNotFound):
		fail("flow_expired")
	case errors.Is(err, errSocialEmailTaken):
		fail("email_in_use_but_unverified")
	case errors.Is(err, errSocialUnregisterable):
		fail("cannot_auto_register")
	case err != nil:
		internalError(w, err)
	case mfaFlow != "":
		u := withParam(returnTo, "mfa_flow", mfaFlow)
		for _, m := range methods {
			u = withParam(u, "methods", m)
		}
		// The handover login flow is a browser flow; hand its CSRF token
		// to the tenant UI (single-purpose, useless without the cookie).
		if secret := csrfSecret(r); secret != "" {
			u = withParam(u, "mfa_csrf", csrfToken(secret, mfaFlow))
		}
		http.Redirect(w, r, u, http.StatusFound)
	default:
		setSessionCookie(w, r, token, sess.ExpiresAt)
		if returnTo == "" {
			writeJSON(w, http.StatusOK, map[string]any{"state": "active", "session": sess})
			return
		}
		http.Redirect(w, r, returnTo, http.StatusFound)
	}
}

// resolveSocialIdentity walks the login / link / register ladder.
func (a *publicAPI) resolveSocialIdentity(r *http.Request, tx pgx.Tx, t *tenant.Tenant, p *storage.SocialProvider, claims *social.Claims) (string, error) {
	ctx := r.Context()
	socialID := social.Identifier(p.ID, claims.Subject)

	if id, err := storage.FindIdentityByIdentifier(ctx, tx, socialID); err != nil || id != "" {
		return id, err
	}

	// Link by verified email only.
	if claims.Email != "" && claims.EmailVerified {
		id, err := storage.FindVerifiedAddressIdentity(ctx, tx, claims.Email)
		if err != nil {
			return "", err
		}
		if id != "" {
			if err := storage.AddIdentifier(ctx, tx, t.ID, socialID, id); err != nil {
				return "", err
			}
			return id, a.recordSocialCredential(ctx, tx, t, id, p.ID, claims.Subject)
		}
	}

	// Register a fresh identity from the provider's claims.
	schema, err := storage.CurrentSchema(ctx, tx, "default")
	if err != nil {
		return "", err
	}
	traits := map[string]any{}
	for _, field := range schema.Fields() {
		switch field.Name {
		case "email":
			if claims.Email != "" {
				traits["email"] = claims.Email
			}
		case "name":
			if claims.Name != "" {
				traits["name"] = claims.Name
			}
		}
	}
	raw, err := json.Marshal(traits)
	if err != nil {
		return "", err
	}
	if msgs := schema.ValidateTraits(raw); msgs != nil {
		return "", errSocialUnregisterable
	}
	ident, err := storage.CreateIdentity(ctx, tx, t.ID, schema.ID, raw, "", schema.Identifiers(raw))
	if errors.Is(err, storage.ErrIdentifierTaken) {
		// The email exists but is unverified, so linking is off the
		// table and registering would collide.
		return "", errSocialEmailTaken
	}
	if err != nil {
		return "", err
	}
	addrs, err := storage.CreateAddresses(ctx, tx, t.ID, ident.ID, schema.Addresses(raw))
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if addr.Value == claims.Email && claims.EmailVerified {
			if err := storage.MarkAddressVerified(ctx, tx, addr.ID); err != nil {
				return "", err
			}
		}
	}
	if err := storage.AddIdentifier(ctx, tx, t.ID, socialID, ident.ID); err != nil {
		return "", err
	}
	return ident.ID, a.recordSocialCredential(ctx, tx, t, ident.ID, p.ID, claims.Subject)
}

func (a *publicAPI) recordSocialCredential(ctx context.Context, tx pgx.Tx, t *tenant.Tenant, identityID, providerID, subject string) error {
	raw, err := storage.CredentialConfig(ctx, tx, identityID, identity.CredentialSocial)
	if err != nil {
		return err
	}
	cfg := struct {
		Providers map[string]string `json:"providers"`
	}{Providers: map[string]string{}}
	if raw != nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return err
		}
		if cfg.Providers == nil {
			cfg.Providers = map[string]string{}
		}
	}
	cfg.Providers[providerID] = subject
	return storage.SetCredential(ctx, tx, t.ID, identityID, identity.CredentialSocial, cfg)
}

func withParam(base, key, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Add(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

var (
	errSocialEmailTaken     = errors.New("social email belongs to an unverified account")
	errSocialUnregisterable = errors.New("provider claims cannot satisfy the identity schema")
)
