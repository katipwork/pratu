package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/session"
)

var ErrSessionNotFound = errors.New("session not found or expired")

// CreateSession issues a fresh session for an identity and returns the
// session plus its opaque bearer token (the only time the token exists in
// plaintext on the server side).
func CreateSession(ctx context.Context, tx pgx.Tx, tenantID, identityID string) (*session.Session, string, error) {
	token, hash, err := session.NewToken()
	if err != nil {
		return nil, "", err
	}
	s := &session.Session{IdentityID: identityID}
	err = tx.QueryRow(ctx,
		`INSERT INTO sessions (tenant_id, identity_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id::text, authenticated_at, expires_at`,
		tenantID, identityID, hash, time.Now().Add(session.Lifetime),
	).Scan(&s.ID, &s.AuthenticatedAt, &s.ExpiresAt)
	if err != nil {
		return nil, "", err
	}
	return s, token, nil
}

// FindSessionByToken resolves a presented bearer token to a live session.
func FindSessionByToken(ctx context.Context, tx pgx.Tx, token string) (*session.Session, error) {
	if !session.ValidToken(token) {
		return nil, ErrSessionNotFound
	}
	var s session.Session
	err := tx.QueryRow(ctx,
		`SELECT id::text, identity_id::text, authenticated_at, expires_at
		   FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
		session.HashToken(token),
	).Scan(&s.ID, &s.IdentityID, &s.AuthenticatedAt, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
