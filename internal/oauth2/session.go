// Package oauth2 hosts Pratu's OAuth2/OIDC provider: fosite wired to
// per-tenant issuers, signing keys, and Postgres storage (ADR 0001/0003).
package oauth2

import (
	"encoding/json"
	"time"

	"github.com/ory/fosite"
	foauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
)

// Session carries both the JWT access-token claims and the OIDC ID-token
// claims through fosite.
type Session struct {
	*foauth2.JWTSession
	IDClaims  *jwt.IDTokenClaims `json:"id_claims"`
	IDHeaders *jwt.Headers       `json:"id_headers"`
}

// NewSession builds the session minted when a challenge is accepted.
func NewSession(issuer, subject, clientID, tenantID, aal, email string) *Session {
	now := time.Now().UTC()
	extra := map[string]any{"tid": tenantID, "acr": aal}
	idExtra := map[string]any{"acr": aal}
	if email != "" {
		idExtra["email"] = email
	}
	return &Session{
		JWTSession: &foauth2.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    issuer,
				Subject:   subject,
				Audience:  []string{clientID},
				IssuedAt:  now,
				NotBefore: now,
				Extra:     extra,
			},
			JWTHeader: &jwt.Headers{},
			Subject:   subject,
			ExpiresAt: map[fosite.TokenType]time.Time{},
		},
		IDClaims: &jwt.IDTokenClaims{
			Issuer:      issuer,
			Subject:     subject,
			Audience:    []string{clientID},
			IssuedAt:    now,
			RequestedAt: now,
			AuthTime:    now,
			Extra:       idExtra,
		},
		IDHeaders: &jwt.Headers{},
	}
}

// EmptySession is the prototype fosite unmarshals stored sessions into.
func EmptySession() *Session {
	return &Session{
		JWTSession: &foauth2.JWTSession{
			JWTClaims: &jwt.JWTClaims{},
			JWTHeader: &jwt.Headers{},
			ExpiresAt: map[fosite.TokenType]time.Time{},
		},
		IDClaims:  &jwt.IDTokenClaims{},
		IDHeaders: &jwt.Headers{},
	}
}

func (s *Session) IDTokenClaims() *jwt.IDTokenClaims {
	if s.IDClaims == nil {
		s.IDClaims = &jwt.IDTokenClaims{}
	}
	return s.IDClaims
}

func (s *Session) IDTokenHeaders() *jwt.Headers {
	if s.IDHeaders == nil {
		s.IDHeaders = &jwt.Headers{}
	}
	return s.IDHeaders
}

// Clone deep-copies the session (fosite mutates clones per token type).
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	out := EmptySession()
	if err := json.Unmarshal(raw, out); err != nil {
		panic(err)
	}
	return out
}
