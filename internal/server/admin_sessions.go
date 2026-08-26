package server

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Admin session controls: the kill-switch half of Q9.

func (a *adminAPI) listIdentitySessions(w http.ResponseWriter, r *http.Request) {
	identityID := r.PathValue("id")
	if !storage.ValidUUID(identityID) {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	var sessions []session.Session
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		sessions, err = storage.SessionsForIdentity(r.Context(), tx, identityID)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if sessions == nil {
		sessions = []session.Session{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (a *adminAPI) revokeIdentitySessions(w http.ResponseWriter, r *http.Request) {
	identityID := r.PathValue("id")
	if !storage.ValidUUID(identityID) {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	var revoked int64
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		revoked, err = storage.RevokeSessions(r.Context(), tx, identityID)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "revoked", "revoked": revoked})
}
