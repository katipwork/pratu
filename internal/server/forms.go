package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// A Browser Flow can be driven by a plain HTML form, so submissions
// arrive either as JSON or url-encoded. Form fields carry the same names
// as the JSON ones, and a dotted name builds a nested object, so
// `traits.email=a@b.c` fills the traits object a registration expects.
// Form values are always strings: a trait the Identity Schema types as a
// number or boolean has to come in as JSON.

func isFormSubmission(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// readSubmission decodes a flow submission from either encoding.
func readSubmission(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !isFormSubmission(r) {
		return readJSON(w, r, dst)
	}
	return decodeForm(w, r, dst, false)
}

// readOptionalSubmission is readSubmission for endpoints whose body may
// be absent (resends carry nothing but a csrf_token).
func readOptionalSubmission(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !isFormSubmission(r) {
		return readOptionalJSON(w, r, dst)
	}
	return decodeForm(w, r, dst, true)
}

func decodeForm(w http.ResponseWriter, r *http.Request, dst any, optional bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form body: "+err.Error())
		return false
	}
	if len(r.PostForm) == 0 && optional {
		return true
	}
	nested := map[string]any{}
	for key, values := range r.PostForm {
		if len(values) == 0 {
			continue
		}
		assignPath(nested, strings.Split(key, "."), values[0])
	}
	raw, err := json.Marshal(nested)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid form body")
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form body: "+err.Error())
		return false
	}
	return true
}

// assignPath writes value at a dotted path, creating objects on the way.
func assignPath(m map[string]any, path []string, value string) {
	for i, key := range path {
		if key == "" {
			return
		}
		if i == len(path)-1 {
			m[key] = value
			return
		}
		child, ok := m[key].(map[string]any)
		if !ok {
			child = map[string]any{}
			m[key] = child
		}
		m = child
	}
}
