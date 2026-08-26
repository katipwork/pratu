package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Identity Schema management (Q6): schemas are immutable versions — PUT
// appends a new version of a name (creating the name at version 1), new
// registrations pick up the current version, and existing identities keep
// the version that validated them.

var schemaNamePattern = slugPattern // same shape rules as tenant slugs

func (a *adminAPI) listSchemas(w http.ResponseWriter, r *http.Request) {
	var schemas []storage.SchemaInfo
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		schemas, err = storage.ListSchemas(r.Context(), tx)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	if schemas == nil {
		schemas = []storage.SchemaInfo{}
	}
	writeJSON(w, http.StatusOK, schemas)
}

func (a *adminAPI) getSchema(w http.ResponseWriter, r *http.Request) {
	var info *storage.SchemaInfo
	var raw json.RawMessage
	err := a.withTenant(w, r, func(_ *tenant.Tenant, tx pgx.Tx) error {
		var err error
		info, raw, err = storage.CurrentSchemaRaw(r.Context(), tx, r.PathValue("name"))
		return err
	})
	switch {
	case errors.Is(err, tenant.ErrNotFound):
	case errors.Is(err, storage.ErrSchemaNotFound):
		writeError(w, http.StatusNotFound, "schema not found")
	case err != nil:
		internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"id": info.ID, "name": info.Name, "version": info.Version,
			"created_at": info.CreatedAt, "schema": raw,
		})
	}
}

// putSchema validates and appends a new version. The body is the raw
// JSON Schema itself.
func (a *adminAPI) putSchema(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if len(name) > 63 || !schemaNamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest,
			"schema name must be lowercase letters, digits, and inner hyphens")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	parsed, err := identity.ParseSchema("new", name, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identity schema: "+err.Error())
		return
	}
	if !parsed.HasIdentifier() {
		writeError(w, http.StatusBadRequest,
			`schema must annotate at least one property with "pratu": {"identifier": true}`)
		return
	}

	var info *storage.SchemaInfo
	err = a.withTenant(w, r, func(t *tenant.Tenant, tx pgx.Tx) error {
		info, err = storage.PutSchemaVersion(r.Context(), tx, t.ID, name, raw)
		return err
	})
	if errors.Is(err, tenant.ErrNotFound) {
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}
