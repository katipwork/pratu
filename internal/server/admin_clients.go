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

// withTenant resolves the slug for an admin sub-resource. Disabled
// tenants are included: the admin API stays open on a closed tenant so
// an operator can inspect and repair it before switching it back on
// (ADR 0008).
func (a *adminAPI) withTenant(w http.ResponseWriter, r *http.Request, fn func(t *tenant.Tenant, tx pgx.Tx) error) error {
	t, err := a.tenants.FindBySlugIncludingDisabled(r.Context(), r.PathValue("slug"))
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

// newClientSecret mints a client secret and the hash that is stored in
// its place. The plaintext is handed to the caller for its one trip to
// the operator and never persisted.
func newClientSecret() (secret, hash string, err error) {
	raw, err := randomHex(32)
	if err != nil {
		return "", "", err
	}
	secret = "psec_" + raw
	h, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return "", "", err
	}
	return secret, string(h), nil
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
	if msg := validateRedirectURIs(body.RedirectURIs); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
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
		var hash string
		secret, hash, err = newClientSecret()
		if err != nil {
			internalError(w, err)
			return
		}
		client.SecretHash = hash
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

// validateRedirectURIs rejects what the authorization endpoint could not
// safely honour: a client with nowhere to send an authorization code, or
// a target that is relative or carries a fragment. Shared by creation
// and editing, so a client cannot be patched into a shape it could not
// have been created in.
func validateRedirectURIs(uris []string) string {
	if len(uris) == 0 {
		return "at least one redirect_uri is required"
	}
	for _, raw := range uris {
		if u, err := url.Parse(raw); err != nil || !u.IsAbs() || u.Fragment != "" {
			return "redirect_uris must be absolute URLs without fragments"
		}
	}
	return ""
}

// updateClient edits a client's metadata in place, preserving client_id
// and secret: adding a redirect_uri or a scope is a metadata change, and
// should not force every consumer holding the credentials to be updated
// in lockstep. Absent keys are left alone; a present key replaces its
// value outright — the same PATCH semantics the tenant endpoint has.
func (a *adminAPI) updateClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         *string   `json:"name"`
		RedirectURIs *[]string `json:"redirect_uris"`
		Scopes       *[]string `json:"scopes"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Name != nil && *body.Name == "" {
		writeError(w, http.StatusBadRequest, "name cannot be emptied")
		return
	}
	if body.RedirectURIs != nil {
		if msg := validateRedirectURIs(*body.RedirectURIs); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}

	var client *storage.OAuth2Client
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		client, err = storage.UpdateOAuth2Client(r.Context(), tx, r.PathValue("id"),
			func(c *storage.OAuth2Client) error {
				if body.Name != nil {
					c.Name = *body.Name
				}
				if body.RedirectURIs != nil {
					c.RedirectURIs = *body.RedirectURIs
				}
				if body.Scopes != nil {
					c.Scopes = *body.Scopes
				}
				return nil
			})
		return err
	})
	switch {
	case errors.Is(err, tenant.ErrNotFound):
	case errors.Is(err, storage.ErrClientNotFound):
		writeError(w, http.StatusNotFound, "client not found")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, client)
	}
}

// rotateClientSecret mints a fresh secret for a confidential client,
// preserving its client_id: a secret that was lost (or leaked) is
// recoverable without re-identifying the client everywhere it is
// configured. Like creation, the new secret is returned exactly once.
func (a *adminAPI) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	secret, hash, err := newClientSecret()
	if err != nil {
		internalError(w, err)
		return
	}
	id := r.PathValue("id")
	err = a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		return storage.RotateOAuth2ClientSecret(r.Context(), tx, id, hash)
	})
	switch {
	case errors.Is(err, tenant.ErrNotFound):
	case errors.Is(err, storage.ErrClientNotFound):
		writeError(w, http.StatusNotFound, "client not found")
	case errors.Is(err, storage.ErrClientPublic):
		writeError(w, http.StatusConflict, "public clients have no secret to rotate")
	case err != nil:
		internalError(w, err)
	default:
		// The only time the new secret exists in plaintext server-side.
		writeJSON(w, http.StatusOK, map[string]string{
			"state":         "rotated",
			"client_id":     id,
			"client_secret": secret,
		})
	}
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
