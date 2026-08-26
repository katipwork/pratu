package server

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Signing-key lifecycle (Q17): rotate mints a fresh active key while the
// old one stays in the JWKS verifying already-issued tokens; deleting a
// retired key is the deliberate end of its life.

func (a *adminAPI) rotateKey(w http.ResponseWriter, r *http.Request) {
	var kid string
	var tenantID string
	err := a.withTenant(w, r, func(t *tenant.Tenant, tx pgx.Tx) error {
		tenantID = t.ID
		key, err := storage.RotateTenantKey(r.Context(), tx, t.ID)
		if err != nil {
			return err
		}
		kid = key.KID
		return nil
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	// New tokens must sign with the new key immediately.
	if a.providers != nil {
		a.providers.Invalidate(tenantID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "rotated", "kid": kid})
}

func (a *adminAPI) listKeys(w http.ResponseWriter, r *http.Request) {
	var keys []storage.TenantKeyInfo
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		keys, err = storage.ListTenantKeys(r.Context(), tx)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if keys == nil {
		keys = []storage.TenantKeyInfo{}
	}
	writeJSON(w, http.StatusOK, keys)
}

func (a *adminAPI) deleteKey(w http.ResponseWriter, r *http.Request) {
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		return storage.DeleteTenantKey(r.Context(), tx, r.PathValue("kid"))
	})
	switch {
	case errors.Is(err, tenant.ErrNotFound):
	case errors.Is(err, storage.ErrKeyNotFound):
		writeError(w, http.StatusNotFound, "key not found")
	case errors.Is(err, storage.ErrKeyActive):
		writeError(w, http.StatusConflict, "cannot delete the active key; rotate first")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"state": "deleted"})
	}
}
