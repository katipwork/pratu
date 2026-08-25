package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrNoCode = errors.New("no code for flow")

// OneTimeCode is the stored form of a code: hash, budget, deadline.
type OneTimeCode struct {
	ID        string
	Hash      []byte
	Attempts  int
	ExpiresAt time.Time
}

// ReplaceCode installs a fresh code for a flow, discarding any previous one.
func ReplaceCode(ctx context.Context, tx pgx.Tx, tenantID, flowID string, hash []byte, expiresAt time.Time) error {
	if _, err := tx.Exec(ctx, `DELETE FROM one_time_codes WHERE flow_id = $1`, flowID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO one_time_codes (tenant_id, flow_id, code_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		tenantID, flowID, hash, expiresAt)
	return err
}

// CodeForFlow loads a flow's code, locked for this transaction so the
// attempt counter cannot race.
func CodeForFlow(ctx context.Context, tx pgx.Tx, flowID string) (*OneTimeCode, error) {
	var c OneTimeCode
	err := tx.QueryRow(ctx,
		`SELECT id::text, code_hash, attempts, expires_at
		   FROM one_time_codes WHERE flow_id = $1 FOR UPDATE`,
		flowID,
	).Scan(&c.ID, &c.Hash, &c.Attempts, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoCode
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// IncrementCodeAttempts burns one attempt from the code's budget.
func IncrementCodeAttempts(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE one_time_codes SET attempts = attempts + 1 WHERE id = $1`, id)
	return err
}
