package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func logError(err error) {
	slog.Error("request failed", "error", err)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, status int, message string, details ...string) {
	writeJSON(w, status, map[string]apiError{"error": {Message: message, Details: details}})
}

// readJSON decodes a request body, rejecting unknown fields.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}
