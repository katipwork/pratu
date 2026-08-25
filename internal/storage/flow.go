package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
)

var ErrFlowNotFound = errors.New("flow not found or expired")

// CreateFlow starts a new self-service flow for the current tenant.
func CreateFlow(ctx context.Context, tx pgx.Tx, tenantID string, kind flow.Kind) (*flow.Flow, error) {
	f := &flow.Flow{Kind: kind}
	err := tx.QueryRow(ctx,
		`INSERT INTO flows (tenant_id, kind, expires_at) VALUES ($1, $2, $3)
		 RETURNING id::text, expires_at`,
		tenantID, kind, time.Now().Add(flow.Lifetime),
	).Scan(&f.ID, &f.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// ConsumeFlow atomically claims an unexpired flow of the given kind,
// deleting it so it cannot be submitted twice.
func ConsumeFlow(ctx context.Context, tx pgx.Tx, id string, kind flow.Kind) error {
	tag, err := tx.Exec(ctx,
		`DELETE FROM flows WHERE id = $1 AND kind = $2 AND expires_at > now()`,
		id, kind,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrFlowNotFound
	}
	return nil
}
