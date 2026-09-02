package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/katipwork/pratu/internal/identity"
)

// CreateAddresses persists an identity's schema-declared addresses,
// unverified.
func CreateAddresses(ctx context.Context, tx pgx.Tx, tenantID, identityID string, specs []identity.AddressSpec) ([]identity.Address, error) {
	out := make([]identity.Address, 0, len(specs))
	for _, spec := range specs {
		a := identity.Address{
			Channel:         spec.Channel,
			Value:           spec.Value,
			ForVerification: spec.Verification,
			ForRecovery:     spec.Recovery,
		}
		err := tx.QueryRow(ctx,
			`INSERT INTO identity_addresses (tenant_id, identity_id, channel, value, for_verification, for_recovery)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
			tenantID, identityID, spec.Channel, spec.Value, spec.Verification, spec.Recovery,
		).Scan(&a.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

const addressColumns = `id::text, channel, value, verified, verified_at, for_verification, for_recovery`

func scanAddress(row pgx.Row) (*identity.Address, error) {
	var a identity.Address
	err := row.Scan(&a.ID, &a.Channel, &a.Value, &a.Verified, &a.VerifiedAt, &a.ForVerification, &a.ForRecovery)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AddressesForIdentity lists an identity's addresses.
func AddressesForIdentity(ctx context.Context, tx pgx.Tx, identityID string) ([]identity.Address, error) {
	rows, err := tx.Query(ctx,
		`SELECT `+addressColumns+`
		   FROM identity_addresses WHERE identity_id = $1 ORDER BY channel, value`,
		identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []identity.Address
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// FindAddress loads one address by id.
func FindAddress(ctx context.Context, tx pgx.Tx, id string) (*identity.Address, error) {
	a, err := scanAddress(tx.QueryRow(ctx,
		`SELECT `+addressColumns+` FROM identity_addresses WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("address not found")
	}
	return a, err
}

// FindRecoveryAddress resolves a submitted address value to a
// recovery-capable address and its identity. Absence is normal (recovery
// must not reveal it); callers get ErrNoCredential.
func FindRecoveryAddress(ctx context.Context, tx pgx.Tx, value string) (*identity.Address, string, error) {
	var identityID string
	var a identity.Address
	err := tx.QueryRow(ctx,
		`SELECT `+addressColumns+`, identity_id::text
		   FROM identity_addresses
		  WHERE value = $1 AND for_recovery
		  ORDER BY created_at DESC LIMIT 1`, value,
	).Scan(&a.ID, &a.Channel, &a.Value, &a.Verified, &a.VerifiedAt, &a.ForVerification, &a.ForRecovery, &identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNoCredential
	}
	if err != nil {
		return nil, "", err
	}
	return &a, identityID, nil
}

// FindLoginCodeAddress resolves a submitted login identifier to the
// verification-capable address that *is* that identifier, plus its
// identity — the target of a first-factor One-Time Code (ADR 0007).
// Requiring the address to equal the identifier keeps the code going
// where the person just typed, never to some other address they own.
// Absence is normal (the send step must not reveal it); callers get
// ErrNoCredential.
func FindLoginCodeAddress(ctx context.Context, tx pgx.Tx, identifier string) (*identity.Address, string, error) {
	var identityID string
	var a identity.Address
	err := tx.QueryRow(ctx,
		`SELECT a.id::text, a.channel, a.value, a.verified, a.verified_at,
		        a.for_verification, a.for_recovery, a.identity_id::text
		   FROM identity_addresses a
		   JOIN identity_identifiers ii ON ii.identity_id = a.identity_id
		  WHERE ii.identifier = $1 AND a.value = $1 AND a.for_verification
		  ORDER BY a.created_at DESC LIMIT 1`, identifier,
	).Scan(&a.ID, &a.Channel, &a.Value, &a.Verified, &a.VerifiedAt, &a.ForVerification, &a.ForRecovery, &identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNoCredential
	}
	if err != nil {
		return nil, "", err
	}
	return &a, identityID, nil
}

// MarkAddressVerified records a successful verification.
func MarkAddressVerified(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx,
		`UPDATE identity_addresses SET verified = true, verified_at = now() WHERE id = $1`, id)
	return err
}
