package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/session"
)

var ErrSessionNotFound = errors.New("session not found or expired")

// CreateSession issues a fresh session for an identity at the given
// assurance level and returns the session plus its opaque bearer token
// (the only time the token exists in plaintext on the server side).
func CreateSession(ctx context.Context, tx pgx.Tx, tenantID, identityID, aal string) (*session.Session, string, error) {
	token, hash, err := session.NewToken()
	if err != nil {
		return nil, "", err
	}
	s := &session.Session{IdentityID: identityID, AAL: aal}
	err = tx.QueryRow(ctx,
		`INSERT INTO sessions (tenant_id, identity_id, token_hash, expires_at, aal)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id::text, authenticated_at, expires_at`,
		tenantID, identityID, hash, time.Now().Add(session.Lifetime), aal,
	).Scan(&s.ID, &s.AuthenticatedAt, &s.ExpiresAt)
	if err != nil {
		return nil, "", err
	}
	return s, token, nil
}

// RaiseSessionAAL records that a session's holder proved a second factor.
func RaiseSessionAAL(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE sessions SET aal = $2 WHERE id = $1`, id, session.AAL2)
	return err
}

// DeleteSession removes one session (logout).
func DeleteSession(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

// RevokeSessions deletes every session belonging to an identity; recovery
// calls this before issuing the fresh one.
func RevokeSessions(ctx context.Context, tx pgx.Tx, identityID string) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE identity_id = $1`, identityID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// FindSessionByToken resolves a presented bearer token to a live session.
func FindSessionByToken(ctx context.Context, tx pgx.Tx, token string) (*session.Session, error) {
	if !session.ValidToken(token) {
		return nil, ErrSessionNotFound
	}
	var s session.Session
	err := tx.QueryRow(ctx,
		`SELECT id::text, identity_id::text, aal, authenticated_at, expires_at
		   FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
		session.HashToken(token),
	).Scan(&s.ID, &s.IdentityID, &s.AAL, &s.AuthenticatedAt, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
