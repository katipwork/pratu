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

// ValidUUID reports whether a client-supplied id is uuid-shaped, so
// handlers can 404 instead of surfacing a database cast error.
func ValidUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// FlowOptions carries what a browser flow needs beyond its context:
// where to land when it completes, which browser owns it, and which step
// it opens on. All fields are optional.
type FlowOptions struct {
	ReturnTo        string
	CSRFFingerprint string
	State           string
}

// CreateFlow starts a new self-service flow for the current tenant.
// flowContext carries server-side state (nil for flows that need none);
// browser flows carry CSRF protection.
func CreateFlow(ctx context.Context, tx pgx.Tx, tenantID string, kind flow.Kind, flowContext any, browser bool) (*flow.Flow, error) {
	return CreateFlowWith(ctx, tx, tenantID, kind, flowContext, browser, FlowOptions{})
}

// CreateFlowWith is CreateFlow with the browser-flow extras filled in.
func CreateFlowWith(ctx context.Context, tx pgx.Tx, tenantID string, kind flow.Kind, flowContext any, browser bool, opts FlowOptions) (*flow.Flow, error) {
	raw := []byte(`{}`)
	if flowContext != nil {
		var err error
		if raw, err = json.Marshal(flowContext); err != nil {
			return nil, err
		}
	}
	f := &flow.Flow{
		Kind: kind, Context: raw, Browser: browser,
		State: opts.State, ReturnTo: opts.ReturnTo, CSRFFingerprint: opts.CSRFFingerprint,
	}
	err := tx.QueryRow(ctx,
		`INSERT INTO flows (tenant_id, kind, expires_at, context, browser, state, return_to, csrf_fp)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id::text, expires_at`,
		tenantID, kind, time.Now().Add(flow.Lifetime), raw, browser,
		opts.State, opts.ReturnTo, opts.CSRFFingerprint,
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
	var msgs []byte
	err := tx.QueryRow(ctx,
		`SELECT id::text, expires_at, context, browser, state, ui_messages, return_to, csrf_fp FROM flows
		  WHERE id = $1 AND kind = $2 AND expires_at > now() FOR UPDATE`,
		id, kind,
	).Scan(&f.ID, &f.ExpiresAt, &f.Context, &f.Browser, &f.State, &msgs, &f.ReturnTo, &f.CSRFFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrFlowNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(msgs, &f.Messages); err != nil {
		return nil, err
	}
	return f, nil
}

// FlowByID loads an unexpired flow of any kind without locking it: the
// read-only view a UI renders after landing on its screen.
func FlowByID(ctx context.Context, tx pgx.Tx, id string) (*flow.Flow, error) {
	if !uuidPattern.MatchString(id) {
		return nil, ErrFlowNotFound
	}
	f := &flow.Flow{}
	var msgs []byte
	err := tx.QueryRow(ctx,
		`SELECT id::text, kind, expires_at, context, browser, state, ui_messages, return_to, csrf_fp FROM flows
		  WHERE id = $1 AND expires_at > now()`,
		id,
	).Scan(&f.ID, &f.Kind, &f.ExpiresAt, &f.Context, &f.Browser, &f.State, &msgs, &f.ReturnTo, &f.CSRFFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrFlowNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(msgs, &f.Messages); err != nil {
		return nil, err
	}
	return f, nil
}

// SetFlowUI records the step a flow waits on and the messages its UI
// should show. A failed submission rolls its own transaction back, so
// this runs in a transaction of its own — otherwise the messages would
// vanish with the failure that produced them.
func SetFlowUI(ctx context.Context, tx pgx.Tx, id, state string, msgs []flow.Message) error {
	if msgs == nil {
		msgs = []flow.Message{}
	}
	raw, err := json.Marshal(msgs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE flows SET state = $2, ui_messages = $3 WHERE id = $1`, id, state, raw)
	return err
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
