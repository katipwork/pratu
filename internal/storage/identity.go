package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/secrets"
)

// ErrIdentifierTaken reports a registration whose identifier already
// belongs to another identity in the tenant.
var ErrIdentifierTaken = errors.New("identifier already in use")

// ErrNoCredential reports a login identifier with no matching identity or
// credential.
var ErrNoCredential = errors.New("no matching credential")

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateIdentitySchema stores a raw Identity Schema for the current tenant.
func CreateIdentitySchema(ctx context.Context, tx pgx.Tx, tenantID, name string, raw json.RawMessage) (string, error) {
	var id string
	err := tx.QueryRow(ctx,
		`INSERT INTO identity_schemas (tenant_id, name, schema) VALUES ($1, $2, $3) RETURNING id::text`,
		tenantID, name, raw,
	).Scan(&id)
	return id, err
}

// DefaultIdentitySchema loads and compiles the tenant's "default" schema.
func DefaultIdentitySchema(ctx context.Context, tx pgx.Tx) (*identity.Schema, error) {
	var id string
	var raw json.RawMessage
	err := tx.QueryRow(ctx,
		`SELECT id::text, schema FROM identity_schemas WHERE name = 'default'`,
	).Scan(&id, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("tenant has no default identity schema")
	}
	if err != nil {
		return nil, err
	}
	return identity.ParseSchema(id, "default", raw)
}

// CreateIdentity inserts an identity with a password credential and its
// login identifiers, atomically within the caller's tenant transaction.
func CreateIdentity(ctx context.Context, tx pgx.Tx, tenantID, schemaID string, traits json.RawMessage, passwordHash string, identifiers []string) (*identity.Identity, error) {
	var ident identity.Identity
	ident.SchemaID = schemaID
	ident.Traits = traits
	err := tx.QueryRow(ctx,
		`INSERT INTO identities (tenant_id, schema_id, traits) VALUES ($1, $2, $3)
		 RETURNING id::text, created_at`,
		tenantID, schemaID, traits,
	).Scan(&ident.ID, &ident.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert identity: %w", err)
	}

	config, err := json.Marshal(map[string]string{"hash": passwordHash})
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO identity_credentials (tenant_id, identity_id, kind, config) VALUES ($1, $2, $3, $4)`,
		tenantID, ident.ID, identity.CredentialPassword, config,
	)
	if err != nil {
		return nil, fmt.Errorf("insert credential: %w", err)
	}

	for _, idf := range identifiers {
		_, err := tx.Exec(ctx,
			`INSERT INTO identity_identifiers (tenant_id, identifier, identity_id) VALUES ($1, $2, $3)`,
			tenantID, idf, ident.ID,
		)
		if isUniqueViolation(err) {
			return nil, ErrIdentifierTaken
		}
		if err != nil {
			return nil, fmt.Errorf("insert identifier: %w", err)
		}
	}
	return &ident, nil
}

// encryptedCredentialKinds are stored sealed: their configs contain
// impersonation-grade secrets (TOTP secret, second-factor phone).
var encryptedCredentialKinds = map[string]bool{
	identity.CredentialTOTP: true,
	identity.CredentialSMS:  true,
}

// CredentialConfig loads one credential's config for an identity, or nil
// when the identity has no credential of that kind. Encrypted configs
// (stored as a JSON string "enc:v1:...") are opened transparently.
func CredentialConfig(ctx context.Context, tx pgx.Tx, identityID, kind string) (json.RawMessage, error) {
	var config json.RawMessage
	err := tx.QueryRow(ctx,
		`SELECT config FROM identity_credentials WHERE identity_id = $1 AND kind = $2`,
		identityID, kind,
	).Scan(&config)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(config) > 0 && config[0] == '"' {
		var sealed string
		if err := json.Unmarshal(config, &sealed); err != nil {
			return nil, err
		}
		plain, err := cipher.Decrypt(sealed)
		if err != nil {
			return nil, fmt.Errorf("credential %s: %w", kind, err)
		}
		return json.RawMessage(plain), nil
	}
	return config, nil
}

// SetCredential creates or replaces a credential of one kind, sealing the
// config for second-factor kinds.
func SetCredential(ctx context.Context, tx pgx.Tx, tenantID, identityID, kind string, config any) error {
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if encryptedCredentialKinds[kind] {
		sealed, err := cipher.Encrypt(string(raw))
		if err != nil {
			return err
		}
		if secrets.Encrypted(sealed) {
			if raw, err = json.Marshal(sealed); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO identity_credentials (tenant_id, identity_id, kind, config) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (identity_id, kind) DO UPDATE SET config = EXCLUDED.config`,
		tenantID, identityID, kind, raw)
	return err
}

// DeleteCredential removes a credential of one kind.
func DeleteCredential(ctx context.Context, tx pgx.Tx, identityID, kind string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM identity_credentials WHERE identity_id = $1 AND kind = $2`, identityID, kind)
	return err
}

// IdentifierForIdentity returns one of the identity's login identifiers,
// for labeling (e.g. the authenticator-app account name).
func IdentifierForIdentity(ctx context.Context, tx pgx.Tx, identityID string) (string, error) {
	var identifier string
	err := tx.QueryRow(ctx,
		`SELECT identifier FROM identity_identifiers WHERE identity_id = $1 ORDER BY identifier LIMIT 1`,
		identityID,
	).Scan(&identifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return identityID, nil
	}
	return identifier, err
}

// SetPasswordCredential replaces (or creates) an identity's password hash.
func SetPasswordCredential(ctx context.Context, tx pgx.Tx, tenantID, identityID, passwordHash string) error {
	config, err := json.Marshal(map[string]string{"hash": passwordHash})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO identity_credentials (tenant_id, identity_id, kind, config) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (identity_id, kind) DO UPDATE SET config = EXCLUDED.config`,
		tenantID, identityID, identity.CredentialPassword, config)
	return err
}

// PasswordCredential resolves a normalized identifier to its identity and
// stored password hash.
func PasswordCredential(ctx context.Context, tx pgx.Tx, identifier string) (identityID, hash string, err error) {
	err = tx.QueryRow(ctx,
		`SELECT i.id::text, c.config->>'hash'
		   FROM identity_identifiers ii
		   JOIN identities i ON i.id = ii.identity_id
		   JOIN identity_credentials c ON c.identity_id = i.id AND c.kind = $2
		  WHERE ii.identifier = $1`,
		identifier, identity.CredentialPassword,
	).Scan(&identityID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNoCredential
	}
	return identityID, hash, err
}

// FindIdentity loads one identity by id.
func FindIdentity(ctx context.Context, tx pgx.Tx, id string) (*identity.Identity, error) {
	var ident identity.Identity
	err := tx.QueryRow(ctx,
		`SELECT id::text, schema_id::text, traits, created_at FROM identities WHERE id = $1`, id,
	).Scan(&ident.ID, &ident.SchemaID, &ident.Traits, &ident.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ident, nil
}
