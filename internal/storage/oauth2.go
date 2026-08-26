package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- context plumbing -------------------------------------------------
//
// fosite's storage interfaces receive only a context, but every query
// here must run inside the caller's tenant transaction (RLS). Handlers
// stash the pair before invoking fosite.

type oauthCtxKey int

const oauthTxKey oauthCtxKey = 0

type oauthTx struct {
	tx       pgx.Tx
	tenantID string
}

// WithOAuthTx binds a tenant transaction into ctx for the fosite storage
// adapter.
func WithOAuthTx(ctx context.Context, tx pgx.Tx, tenantID string) context.Context {
	return context.WithValue(ctx, oauthTxKey, oauthTx{tx: tx, tenantID: tenantID})
}

// OAuthTx recovers the bound transaction; fosite storage calls fail
// loudly when a handler forgot to bind it.
func OAuthTx(ctx context.Context) (pgx.Tx, string, error) {
	v, ok := ctx.Value(oauthTxKey).(oauthTx)
	if !ok {
		return nil, "", errors.New("oauth2 storage used outside a tenant transaction")
	}
	return v.tx, v.tenantID, nil
}

// --- signing keys -----------------------------------------------------

type TenantKey struct {
	KID string
	Key *rsa.PrivateKey
}

// ActiveTenantKey returns the tenant's active signing key, generating one
// on first use.
func ActiveTenantKey(ctx context.Context, tx pgx.Tx, tenantID string) (*TenantKey, error) {
	var kid, pemStr string
	err := tx.QueryRow(ctx,
		`SELECT kid, private_pem FROM tenant_keys WHERE active ORDER BY created_at DESC LIMIT 1`,
	).Scan(&kid, &pemStr)
	if errors.Is(err, pgx.ErrNoRows) {
		return generateTenantKey(ctx, tx, tenantID)
	}
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(pemStr)
	if err != nil {
		return nil, err
	}
	return &TenantKey{KID: kid, Key: key}, nil
}

func parseKeyPEM(stored string) (*rsa.PrivateKey, error) {
	pemStr, err := cipher.Decrypt(stored)
	if err != nil {
		return nil, fmt.Errorf("tenant key: %w", err)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("tenant key: invalid PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tenant key: %w", err)
	}
	return key, nil
}

// VerificationKeys returns every key (active and retired) for the JWKS.
func VerificationKeys(ctx context.Context, tx pgx.Tx) ([]TenantKey, error) {
	rows, err := tx.Query(ctx, `SELECT kid, private_pem FROM tenant_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantKey
	for rows.Next() {
		var kid, pemStr string
		if err := rows.Scan(&kid, &pemStr); err != nil {
			return nil, err
		}
		key, err := parseKeyPEM(pemStr)
		if err != nil {
			return nil, err
		}
		out = append(out, TenantKey{KID: kid, Key: key})
	}
	return out, rows.Err()
}

// RotateTenantKey retires the current active key (it stays verifiable in
// the JWKS) and mints a fresh active one.
func RotateTenantKey(ctx context.Context, tx pgx.Tx, tenantID string) (*TenantKey, error) {
	if _, err := tx.Exec(ctx, `UPDATE tenant_keys SET active = false WHERE active`); err != nil {
		return nil, err
	}
	return generateTenantKey(ctx, tx, tenantID)
}

// TenantKeyInfo is the public shape of a signing key: no private material.
type TenantKeyInfo struct {
	KID       string    `json:"kid"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// ListTenantKeys describes the tenant's keys, newest first.
func ListTenantKeys(ctx context.Context, tx pgx.Tx) ([]TenantKeyInfo, error) {
	rows, err := tx.Query(ctx,
		`SELECT kid, active, created_at FROM tenant_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantKeyInfo
	for rows.Next() {
		var k TenantKeyInfo
		if err := rows.Scan(&k.KID, &k.Active, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrKeyActive   = errors.New("key is active")
)

// DeleteTenantKey drops a retired key: tokens signed with it stop
// verifying, so this is the deliberate end of the rotation lifecycle.
// The active key is refused.
func DeleteTenantKey(ctx context.Context, tx pgx.Tx, kid string) error {
	var active bool
	err := tx.QueryRow(ctx, `SELECT active FROM tenant_keys WHERE kid = $1`, kid).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrKeyNotFound
	}
	if err != nil {
		return err
	}
	if active {
		return ErrKeyActive
	}
	_, err = tx.Exec(ctx, `DELETE FROM tenant_keys WHERE kid = $1`, kid)
	return err
}

func generateTenantKey(ctx context.Context, tx pgx.Tx, tenantID string) (*TenantKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	stored, err := cipher.Encrypt(pemStr)
	if err != nil {
		return nil, err
	}
	var kid string
	err = tx.QueryRow(ctx,
		`INSERT INTO tenant_keys (tenant_id, kid, private_pem)
		 VALUES ($1, gen_random_uuid()::text, $2) RETURNING kid`,
		tenantID, stored,
	).Scan(&kid)
	if err != nil {
		return nil, err
	}
	return &TenantKey{KID: kid, Key: key}, nil
}

// --- clients ----------------------------------------------------------

type OAuth2Client struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"name"`
	SecretHash   string   `json:"-"`
	Public       bool     `json:"public"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	FirstParty   bool     `json:"first_party"`
}

func CreateOAuth2Client(ctx context.Context, tx pgx.Tx, tenantID string, c *OAuth2Client) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	scopes, err := json.Marshal(c.Scopes)
	if err != nil {
		return err
	}
	var secret *string
	if !c.Public {
		secret = &c.SecretHash
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO oauth2_clients (id, tenant_id, name, secret_hash, redirect_uris, scopes, first_party)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ID, tenantID, c.Name, secret, uris, scopes, c.FirstParty)
	return err
}

var ErrClientNotFound = errors.New("oauth2 client not found")

func FindOAuth2Client(ctx context.Context, tx pgx.Tx, id string) (*OAuth2Client, error) {
	var c OAuth2Client
	var secret *string
	var uris, scopes []byte
	err := tx.QueryRow(ctx,
		`SELECT id, name, secret_hash, redirect_uris, scopes, first_party
		   FROM oauth2_clients WHERE id = $1`, id,
	).Scan(&c.ID, &c.Name, &secret, &uris, &scopes, &c.FirstParty)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}
	if secret != nil {
		c.SecretHash = *secret
	} else {
		c.Public = true
	}
	if err := json.Unmarshal(uris, &c.RedirectURIs); err != nil {
		return nil, err
	}
	return &c, json.Unmarshal(scopes, &c.Scopes)
}

func ListOAuth2Clients(ctx context.Context, tx pgx.Tx) ([]OAuth2Client, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, name, secret_hash IS NULL, redirect_uris, scopes, first_party
		   FROM oauth2_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OAuth2Client
	for rows.Next() {
		var c OAuth2Client
		var uris, scopes []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.Public, &uris, &scopes, &c.FirstParty); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(uris, &c.RedirectURIs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(scopes, &c.Scopes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func DeleteOAuth2Client(ctx context.Context, tx pgx.Tx, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM oauth2_clients WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// --- protocol session rows -------------------------------------------

var ErrOAuthSessionNotFound = errors.New("oauth2 session not found")

type OAuthSessionRow struct {
	RequestID     string
	ClientID      string
	RequestedAt   time.Time
	Scopes        []string
	GrantedScopes []string
	Form          string
	Session       json.RawMessage
	Subject       string
	Active        bool
}

func CreateOAuthSession(ctx context.Context, tx pgx.Tx, tenantID, kind, signature string, row *OAuthSessionRow, accessSignature *string) error {
	scopes, err := json.Marshal(row.Scopes)
	if err != nil {
		return err
	}
	granted, err := json.Marshal(row.GrantedScopes)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO oauth2_sessions
		   (kind, signature, tenant_id, request_id, client_id, requested_at,
		    scopes, granted_scopes, form, session, subject, access_signature)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (kind, signature) DO UPDATE SET
		   request_id = EXCLUDED.request_id, session = EXCLUDED.session,
		   granted_scopes = EXCLUDED.granted_scopes, active = true`,
		kind, signature, tenantID, row.RequestID, row.ClientID, row.RequestedAt,
		scopes, granted, row.Form, row.Session, row.Subject, accessSignature)
	return err
}

func GetOAuthSession(ctx context.Context, tx pgx.Tx, kind, signature string) (*OAuthSessionRow, error) {
	var row OAuthSessionRow
	var scopes, granted []byte
	err := tx.QueryRow(ctx,
		`SELECT request_id, client_id, requested_at, scopes, granted_scopes, form, session, subject, active
		   FROM oauth2_sessions WHERE kind = $1 AND signature = $2`,
		kind, signature,
	).Scan(&row.RequestID, &row.ClientID, &row.RequestedAt, &scopes, &granted,
		&row.Form, &row.Session, &row.Subject, &row.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOAuthSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopes, &row.Scopes); err != nil {
		return nil, err
	}
	return &row, json.Unmarshal(granted, &row.GrantedScopes)
}

func DeleteOAuthSession(ctx context.Context, tx pgx.Tx, kind, signature string) error {
	_, err := tx.Exec(ctx, `DELETE FROM oauth2_sessions WHERE kind = $1 AND signature = $2`, kind, signature)
	return err
}

func DeactivateOAuthSession(ctx context.Context, tx pgx.Tx, kind, signature string) error {
	_, err := tx.Exec(ctx, `UPDATE oauth2_sessions SET active = false WHERE kind = $1 AND signature = $2`, kind, signature)
	return err
}

// DeactivateOAuthSessionsByRequest flips every row of one kind belonging
// to a request (refresh-token reuse detection revokes the whole chain).
func DeactivateOAuthSessionsByRequest(ctx context.Context, tx pgx.Tx, kind, requestID string) error {
	_, err := tx.Exec(ctx, `UPDATE oauth2_sessions SET active = false WHERE kind = $1 AND request_id = $2`, kind, requestID)
	return err
}

func DeleteOAuthSessionsByRequest(ctx context.Context, tx pgx.Tx, kind, requestID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM oauth2_sessions WHERE kind = $1 AND request_id = $2`, kind, requestID)
	return err
}
