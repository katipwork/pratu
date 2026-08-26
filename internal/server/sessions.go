package server

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/session"
	"github.com/katipwork/pratu/internal/storage"
)

// Session management (Q9: sessions are listable and revocable). The list
// never exposes tokens — only metadata a person can recognize a device by.

type sessionListEntry struct {
	session.Session
	Current bool `json:"current"`
}

func (a *publicAPI) listSessions(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	var out []sessionListEntry
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, false)
		if err != nil {
			return err
		}
		all, err := storage.SessionsForIdentity(r.Context(), tx, sess.IdentityID)
		if err != nil {
			return err
		}
		for _, s := range all {
			out = append(out, sessionListEntry{Session: s, Current: s.ID == sess.ID})
		}
		return nil
	})
	if errors.Is(err, errNoSession) {
		writeError(w, http.StatusUnauthorized, "session required")
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// revokeSession ends one of the caller's own sessions.
func (a *publicAPI) revokeSession(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	target := r.PathValue("id")
	var found, wasCurrent bool
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		wasCurrent = sess.ID == target
		found, err = storage.DeleteSessionOwned(r.Context(), tx, target, sess.IdentityID)
		return err
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case err != nil:
		internalError(w, err)
	case !found:
		writeError(w, http.StatusNotFound, "session not found")
	default:
		if wasCurrent {
			clearSessionCookie(w, r)
		}
		writeJSON(w, http.StatusOK, map[string]string{"state": "revoked"})
	}
}

// revokeOtherSessions is "log out other devices": every session except
// the current one dies.
func (a *publicAPI) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	t := requestTenant(r)
	var revoked int64
	err := storage.InTenant(r.Context(), a.pool, t.ID, func(tx pgx.Tx) error {
		sess, err := requireSession(r.Context(), tx, r, true)
		if err != nil {
			return err
		}
		revoked, err = storage.DeleteOtherSessions(r.Context(), tx, sess.IdentityID, sess.ID)
		return err
	})
	switch {
	case errors.Is(err, errNoSession):
		writeError(w, http.StatusUnauthorized, "session required")
	case errors.Is(err, errCSRF):
		writeError(w, http.StatusForbidden, "csrf token missing or invalid (X-CSRF-Token)")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"state": "revoked_others", "revoked": revoked})
	}
}
