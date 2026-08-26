package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/session"
)

var ErrSessionNotFound = errors.New("session not found or expired")

// Device describes where a session was minted, for "log out other
// devices" listings.
type Device struct {
	IP        string
	UserAgent string
}

// CreateSession issues a fresh session for an identity at the given
// assurance level and returns the session plus its opaque bearer token
// (the only time the token exists in plaintext on the server side).
func CreateSession(ctx context.Context, tx pgx.Tx, tenantID, identityID, aal string, dev Device) (*session.Session, string, error) {
	token, hash, err := session.NewToken()
	if err != nil {
		return nil, "", err
	}
	if len(dev.UserAgent) > 256 {
		dev.UserAgent = dev.UserAgent[:256]
	}
	s := &session.Session{IdentityID: identityID, AAL: aal, IP: dev.IP, UserAgent: dev.UserAgent}
	err = tx.QueryRow(ctx,
		`INSERT INTO sessions (tenant_id, identity_id, token_hash, expires_at, aal, ip, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id::text, authenticated_at, expires_at`,
		tenantID, identityID, hash, time.Now().Add(session.Lifetime), aal, dev.IP, dev.UserAgent,
	).Scan(&s.ID, &s.AuthenticatedAt, &s.ExpiresAt)
	if err != nil {
		return nil, "", err
	}
	return s, token, nil
}

// SessionsForIdentity lists an identity's live sessions, newest first.
func SessionsForIdentity(ctx context.Context, tx pgx.Tx, identityID string) ([]session.Session, error) {
	rows, err := tx.Query(ctx,
		`SELECT id::text, identity_id::text, aal, ip, user_agent, authenticated_at, expires_at
		   FROM sessions WHERE identity_id = $1 AND expires_at > now()
		  ORDER BY authenticated_at DESC`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []session.Session
	for rows.Next() {
		var s session.Session
		if err := rows.Scan(&s.ID, &s.IdentityID, &s.AAL, &s.IP, &s.UserAgent, &s.AuthenticatedAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSessionOwned removes one session only if it belongs to the given
// identity, reporting whether anything was deleted.
func DeleteSessionOwned(ctx context.Context, tx pgx.Tx, id, identityID string) (bool, error) {
	if !uuidPattern.MatchString(id) {
		return false, nil
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM sessions WHERE id = $1 AND identity_id = $2`, id, identityID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteOtherSessions removes every session of an identity except one
// ("log out other devices").
func DeleteOtherSessions(ctx context.Context, tx pgx.Tx, identityID, keepID string) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM sessions WHERE identity_id = $1 AND id <> $2`, identityID, keepID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
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
