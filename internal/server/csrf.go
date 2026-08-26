package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// Browser requests authenticate with cookies, so state-changing requests
// need CSRF proof. The scheme is a double-submit HMAC: an HTTP-only
// cookie holds a per-browser secret, and each token is
// HMAC(secret, scope) where scope is the flow ID (flow submissions) or
// "session" (session-authenticated endpoints). Cookies are host-only, so
// the browser enforces per-tenant isolation (ADR 0003). Header-token
// requests (X-Session-Token / Authorization) skip CSRF entirely: custom
// headers cannot be sent cross-site.

const (
	sessionCookieName = "pratu_session"
	csrfCookieName    = "pratu_csrf"
	csrfSessionScope  = "session"
)

var errCSRF = errors.New("csrf token missing or invalid")

func secureRequest(r *http.Request) bool {
	return r.TLS != nil
}

// ensureCSRFCookie returns the browser's CSRF secret, minting the cookie
// when absent.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: secret, Path: "/",
		HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteLaxMode,
	})
	return secret, nil
}

func csrfSecret(r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil {
		return c.Value
	}
	return ""
}

func csrfToken(secret, scope string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(scope))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validCSRF(r *http.Request, scope, submitted string) bool {
	secret := csrfSecret(r)
	if secret == "" || submitted == "" {
		return false
	}
	return hmac.Equal([]byte(csrfToken(secret, scope)), []byte(submitted))
}

// flowCSRF guards one browser-flow submission; API flows pass freely.
func flowCSRF(r *http.Request, browser bool, flowID, submitted string) error {
	if !browser {
		return nil
	}
	if !validCSRF(r, flowID, submitted) {
		return errCSRF
	}
	return nil
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteLaxMode,
		Expires: expires,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/",
		HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteLaxMode,
		MaxAge: -1,
	})
}
