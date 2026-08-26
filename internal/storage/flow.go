package storage

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/flow"
)

var ErrFlowNotFound = errors.New("flow not found or expired")

// flow ids arrive as client-supplied query params; a malformed uuid would
// otherwise surface as a database error instead of a clean not-found.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CreateFlow starts a new self-service flow for the current tenant.
// flowContext carries server-side state (nil for flows that need none);
// browser flows carry CSRF protection.
func CreateFlow(ctx context.Context, tx pgx.Tx, tenantID string, kind flow.Kind, flowContext any, browser bool) (*flow.Flow, error) {
	raw := []byte(`{}`)
	if flowContext != nil {
		var err error
		if raw, err = json.Marshal(flowContext); err != nil {
			return nil, err
		}
	}
	f := &flow.Flow{Kind: kind, Context: raw, Browser: browser}
	err := tx.QueryRow(ctx,
		`INSERT INTO flows (tenant_id, kind, expires_at, context, browser) VALUES ($1, $2, $3, $4, $5)
		 RETURNING id::text, expires_at`,
		tenantID, kind, time.Now().Add(flow.Lifetime), raw, browser,
	).Scan(&f.ID, &f.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// GetFlow loads an unexpired flow of the given kind without consuming it,
// locked so concurrent submissions serialize.
func GetFlow(ctx context.Context, tx pgx.Tx, id string, kind flow.Kind) (*flow.Flow, error) {
	if !uuidPattern.MatchString(id) {
		return nil, ErrFlowNotFound
	}
	f := &flow.Flow{Kind: kind}
	err := tx.QueryRow(ctx,
		`SELECT id::text, expires_at, context, browser FROM flows
		  WHERE id = $1 AND kind = $2 AND expires_at > now() FOR UPDATE`,
		id, kind,
	).Scan(&f.ID, &f.ExpiresAt, &f.Context, &f.Browser)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrFlowNotFound
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// UpdateFlowContext replaces a flow's server-side context.
func UpdateFlowContext(ctx context.Context, tx pgx.Tx, id string, flowContext any) error {
	raw, err := json.Marshal(flowContext)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE flows SET context = $2 WHERE id = $1`, id, raw)
	return err
}

// DeleteFlow removes a flow (and, via cascade, its one-time code).
func DeleteFlow(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM flows WHERE id = $1`, id)
	return err
}
