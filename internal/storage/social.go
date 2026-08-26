package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SocialProvider is one entry in a tenant's social login registry.
type SocialProvider struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"` // 'oidc' | 'github'
	Label        string   `json:"label"`
	Issuer       string   `json:"issuer,omitempty"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"`
	Scopes       []string `json:"scopes"`
}

var ErrProviderNotFound = errors.New("social provider not found")

// UpsertSocialProvider creates or replaces a provider; the client secret
// is sealed at rest.
func UpsertSocialProvider(ctx context.Context, tx pgx.Tx, tenantID string, p *SocialProvider) error {
	scopes, err := json.Marshal(p.Scopes)
	if err != nil {
		return err
	}
	sealed, err := cipher.Encrypt(p.ClientSecret)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO social_providers (tenant_id, id, kind, label, issuer, client_id, client_secret, scopes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, id) DO UPDATE SET
		   kind = EXCLUDED.kind, label = EXCLUDED.label, issuer = EXCLUDED.issuer,
		   client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret,
		   scopes = EXCLUDED.scopes`,
		tenantID, p.ID, p.Kind, p.Label, p.Issuer, p.ClientID, sealed, scopes)
	return err
}

// GetSocialProvider loads one provider with its secret opened.
func GetSocialProvider(ctx context.Context, tx pgx.Tx, id string) (*SocialProvider, error) {
	var p SocialProvider
	var scopes []byte
	var sealed string
	err := tx.QueryRow(ctx,
		`SELECT id, kind, label, issuer, client_id, client_secret, scopes
		   FROM social_providers WHERE id = $1`, id,
	).Scan(&p.ID, &p.Kind, &p.Label, &p.Issuer, &p.ClientID, &sealed, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProviderNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.ClientSecret, err = cipher.Decrypt(sealed); err != nil {
		return nil, fmt.Errorf("social provider %s: %w", id, err)
	}
	return &p, json.Unmarshal(scopes, &p.Scopes)
}

// ListSocialProviders lists a tenant's providers (no secrets).
func ListSocialProviders(ctx context.Context, tx pgx.Tx) ([]SocialProvider, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, kind, label, issuer, client_id, scopes FROM social_providers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SocialProvider
	for rows.Next() {
		var p SocialProvider
		var scopes []byte
		if err := rows.Scan(&p.ID, &p.Kind, &p.Label, &p.Issuer, &p.ClientID, &scopes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(scopes, &p.Scopes); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func DeleteSocialProvider(ctx context.Context, tx pgx.Tx, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM social_providers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// FindIdentityByIdentifier resolves any identifier (login or social) to
// its identity, or "" when unknown.
func FindIdentityByIdentifier(ctx context.Context, tx pgx.Tx, identifier string) (string, error) {
	var id string
	err := tx.QueryRow(ctx,
		`SELECT identity_id::text FROM identity_identifiers WHERE identifier = $1`, identifier,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// FindVerifiedAddressIdentity resolves a verified address value to its
// identity, or "" — the only basis on which social accounts auto-link.
func FindVerifiedAddressIdentity(ctx context.Context, tx pgx.Tx, value string) (string, error) {
	var id string
	err := tx.QueryRow(ctx,
		`SELECT identity_id::text FROM identity_addresses
		  WHERE value = $1 AND verified ORDER BY created_at LIMIT 1`, value,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// AddIdentifier registers one more identifier for an identity.
func AddIdentifier(ctx context.Context, tx pgx.Tx, tenantID, identifier, identityID string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identity_identifiers (tenant_id, identifier, identity_id) VALUES ($1, $2, $3)`,
		tenantID, identifier, identityID)
	if isUniqueViolation(err) {
		return ErrIdentifierTaken
	}
	return err
}
