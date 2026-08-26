// Package session defines server-side sessions and their opaque bearer
// tokens. Only a SHA-256 hash of a token is ever stored (a leaked database
// must not yield usable tokens).
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"
)

// Lifetime is the default session duration; per-tenant configuration
// arrives with tenant config work.
const Lifetime = 24 * time.Hour

// Authenticator assurance levels: AAL1 = one factor proven (password),
// AAL2 = a second factor (TOTP) proven too.
const (
	AAL1 = "aal1"
	AAL2 = "aal2"
)

type Session struct {
	ID              string    `json:"id"`
	IdentityID      string    `json:"identity_id"`
	AAL             string    `json:"aal"`
	IP              string    `json:"ip,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// NewToken returns a fresh opaque session token and the hash to persist.
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = "pst_" + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken maps a presented token to its storage hash.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ValidToken reports whether a presented token looks like a session token
// at all, cheaply rejecting garbage before a database round trip.
func ValidToken(token string) bool {
	const prefix = "pst_"
	return len(token) > len(prefix) &&
		subtle.ConstantTimeCompare([]byte(token[:len(prefix)]), []byte(prefix)) == 1
}
