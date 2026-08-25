package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/identity"
)

// CreateAddresses persists an identity's verifiable addresses, unverified.
func CreateAddresses(ctx context.Context, tx pgx.Tx, tenantID, identityID string, specs []identity.AddressSpec) ([]identity.Address, error) {
	out := make([]identity.Address, 0, len(specs))
	for _, spec := range specs {
		a := identity.Address{Channel: spec.Channel, Value: spec.Value}
		err := tx.QueryRow(ctx,
			`INSERT INTO identity_addresses (tenant_id, identity_id, channel, value)
			 VALUES ($1, $2, $3, $4) RETURNING id::text`,
			tenantID, identityID, spec.Channel, spec.Value,
		).Scan(&a.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// AddressesForIdentity lists an identity's addresses.
func AddressesForIdentity(ctx context.Context, tx pgx.Tx, identityID string) ([]identity.Address, error) {
	rows, err := tx.Query(ctx,
		`SELECT id::text, channel, value, verified, verified_at
		   FROM identity_addresses WHERE identity_id = $1 ORDER BY channel, value`,
		identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []identity.Address
	for rows.Next() {
		var a identity.Address
		if err := rows.Scan(&a.ID, &a.Channel, &a.Value, &a.Verified, &a.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// FindAddress loads one address by id.
func FindAddress(ctx context.Context, tx pgx.Tx, id string) (*identity.Address, error) {
	var a identity.Address
	err := tx.QueryRow(ctx,
		`SELECT id::text, channel, value, verified, verified_at
		   FROM identity_addresses WHERE id = $1`, id,
	).Scan(&a.ID, &a.Channel, &a.Value, &a.Verified, &a.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("address not found")
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// MarkAddressVerified records a successful verification.
func MarkAddressVerified(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx,
		`UPDATE identity_addresses SET verified = true, verified_at = now() WHERE id = $1`, id)
	return err
}
