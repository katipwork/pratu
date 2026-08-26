package server

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/social"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Social provider registry management.

func (a *adminAPI) putSocialProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	if len(id) > 63 || !slugPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest,
			"provider id must be lowercase letters, digits, and inner hyphens")
		return
	}
	var body struct {
		Kind         string   `json:"kind"`
		Label        string   `json:"label"`
		Issuer       string   `json:"issuer"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	switch body.Kind {
	case social.KindOIDC:
		if u, err := url.Parse(body.Issuer); err != nil || !u.IsAbs() {
			writeError(w, http.StatusBadRequest, "issuer must be an absolute URL for oidc providers")
			return
		}
		if body.Scopes == nil {
			body.Scopes = []string{"openid", "email", "profile"}
		}
	case social.KindGitHub:
		if body.Scopes == nil {
			body.Scopes = []string{"read:user", "user:email"}
		}
	default:
		writeError(w, http.StatusBadRequest, `kind must be "oidc" or "github"`)
		return
	}
	if body.ClientID == "" || body.ClientSecret == "" {
		writeError(w, http.StatusBadRequest, "client_id and client_secret are required")
		return
	}
	if body.Label == "" {
		body.Label = id
	}

	p := &storage.SocialProvider{
		ID: id, Kind: body.Kind, Label: body.Label, Issuer: body.Issuer,
		ClientID: body.ClientID, ClientSecret: body.ClientSecret, Scopes: body.Scopes,
	}
	err := a.withTenant(w, r, func(t *tenant.Tenant, tx pgx.Tx) error {
		return storage.UpsertSocialProvider(r.Context(), tx, t.ID, p)
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *adminAPI) listSocialProviders(w http.ResponseWriter, r *http.Request) {
	var providers []storage.SocialProvider
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		providers, err = storage.ListSocialProviders(r.Context(), tx)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if providers == nil {
		providers = []storage.SocialProvider{}
	}
	writeJSON(w, http.StatusOK, providers)
}

func (a *adminAPI) deleteSocialProvider(w http.ResponseWriter, r *http.Request) {
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		return storage.DeleteSocialProvider(r.Context(), tx, r.PathValue("provider"))
	})
	switch {
	case errors.Is(err, tenant.ErrNotFound):
	case errors.Is(err, storage.ErrProviderNotFound):
		writeError(w, http.StatusNotFound, "social provider not found")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "deleted"})
	}
}
