package password

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHIBPBreachCount(t *testing.T) {
	// SHA-1 of "password1234", split as the range API does.
	sum := fmt.Sprintf("%X", sha1.Sum([]byte("password1234")))
	prefix, suffix := sum[:5], sum[5:]

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprintf(w, "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n%s:2444\r\nFFFFFFF000000000000000000000000000F:0\r\n", suffix)
	}))
	defer srv.Close()

	h := NewHIBP(srv.URL)
	count, err := h.BreachCount(context.Background(), "password1234")
	if err != nil {
		t.Fatalf("BreachCount: %v", err)
	}
	if count != 2444 {
		t.Errorf("count = %d, want 2444", count)
	}
	if gotPath != "/"+prefix {
		t.Errorf("requested path %q, want /%s (k-anonymity: only the 5-char prefix may leave)", gotPath, prefix)
	}

	if count, err := h.BreachCount(context.Background(), "unbreached-password-hopefully"); err != nil || count != 0 {
		t.Errorf("unlisted suffix: count=%d err=%v, want 0, nil", count, err)
	}
}

func TestHIBPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if _, err := NewHIBP(srv.URL).BreachCount(context.Background(), "x"); err == nil {
		t.Error("expected error on non-200 response")
	}

	down := NewHIBP("http://127.0.0.1:1")
	if _, err := down.BreachCount(context.Background(), "x"); err == nil {
		t.Error("expected error when the API is unreachable")
	}
}
