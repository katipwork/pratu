package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// OAuth2 client management. Confidential clients get a generated secret,
// returned exactly once; public clients get no secret and must use PKCE.

func (a *adminAPI) withTenant(w http.ResponseWriter, r *http.Request, fn func(t *tenant.Tenant, tx pgx.Tx) error) error {
	t, err := a.tenants.FindBySlug(r.Context(), r.PathValue("slug"))
	if errors.Is(err, tenant.ErrNotFound) {
		writeError(w, http.StatusNotFound, "tenant not found")
		return err
	}
	if err != nil {
		internalError(w, err)
		return err
	}
	return storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		return fn(t, tx)
	})
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (a *adminAPI) createClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		FirstParty   bool     `json:"first_party"`
		Public       bool     `json:"public"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(body.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one redirect_uri is required")
		return
	}
	for _, raw := range body.RedirectURIs {
		if u, err := url.Parse(raw); err != nil || !u.IsAbs() || u.Fragment != "" {
			writeError(w, http.StatusBadRequest, "redirect_uris must be absolute URLs without fragments")
			return
		}
	}
	if body.Scopes == nil {
		body.Scopes = []string{"openid", "offline_access", "profile", "email"}
	}

	id, err := randomHex(16)
	if err != nil {
		internalError(w, err)
		return
	}
	client := &storage.OAuth2Client{
		ID:           "pc_" + id,
		Name:         body.Name,
		Public:       body.Public,
		RedirectURIs: body.RedirectURIs,
		Scopes:       body.Scopes,
		FirstParty:   body.FirstParty,
	}
	var secret string
	if !body.Public {
		raw, err := randomHex(32)
		if err != nil {
			internalError(w, err)
			return
		}
		secret = "psec_" + raw
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
		if err != nil {
			internalError(w, err)
			return
		}
		client.SecretHash = string(hash)
	}

	err = a.withTenant(w, r, func(t *tenant.Tenant, tx pgx.Tx) error {
		return storage.CreateOAuth2Client(r.Context(), tx, t.ID, client)
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return // response already written
	}
	if err != nil {
		internalError(w, err)
		return
	}

	resp := map[string]any{"client": client}
	if secret != "" {
		// The only time the secret exists in plaintext server-side.
		resp["client_secret"] = secret
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (a *adminAPI) listClients(w http.ResponseWriter, r *http.Request) {
	var clients []storage.OAuth2Client
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		clients, err = storage.ListOAuth2Clients(r.Context(), tx)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if clients == nil {
		clients = []storage.OAuth2Client{}
	}
	writeJSON(w, http.StatusOK, clients)
}

func (a *adminAPI) deleteClient(w http.ResponseWriter, r *http.Request) {
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		return storage.DeleteOAuth2Client(r.Context(), tx, r.PathValue("id"))
	})
	switch {
	case errors.Is(err, tenant.ErrNotFound):
	case errors.Is(err, storage.ErrClientNotFound):
		writeError(w, http.StatusNotFound, "client not found")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "deleted"})
	}
}
