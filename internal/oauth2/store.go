package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"time"

	"github.com/ory/fosite"

	"github.com/katipwork/pratu/internal/storage"
)

// Store adapts fosite's storage interfaces onto the tenant-scoped
// Postgres tables. Every method expects storage.WithOAuthTx on the ctx.
type Store struct{}

const (
	kindCode    = "code"
	kindAccess  = "access"
	kindRefresh = "refresh"
	kindPKCE    = "pkce"
	kindOIDC    = "oidc"
)

// sig hashes fosite's signatures/keys so raw token material never lands
// in the table.
func sig(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// --- ClientManager ----------------------------------------------------

func (Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return nil, err
	}
	c, err := storage.FindOAuth2Client(ctx, tx, id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	return clientFor(c), nil
}

func clientFor(c *storage.OAuth2Client) *fosite.DefaultClient {
	return &fosite.DefaultClient{
		ID:            c.ID,
		Secret:        []byte(c.SecretHash),
		RedirectURIs:  c.RedirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        c.Scopes,
		Public:        c.Public,
	}
}

func (Store) ClientAssertionJWTValid(ctx context.Context, jti string) error { return nil }

func (Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

// --- request (de)hydration -------------------------------------------

func rowFor(requester fosite.Requester) (*storage.OAuthSessionRow, error) {
	sessJSON, err := json.Marshal(requester.GetSession())
	if err != nil {
		return nil, err
	}
	return &storage.OAuthSessionRow{
		RequestID:     requester.GetID(),
		ClientID:      requester.GetClient().GetID(),
		RequestedAt:   requester.GetRequestedAt(),
		Scopes:        requester.GetRequestedScopes(),
		GrantedScopes: requester.GetGrantedScopes(),
		Form:          requester.GetRequestForm().Encode(),
		Session:       sessJSON,
		Subject:       requester.GetSession().GetSubject(),
	}, nil
}

func (s Store) requesterFor(ctx context.Context, row *storage.OAuthSessionRow, session fosite.Session) (fosite.Requester, error) {
	client, err := s.GetClient(ctx, row.ClientID)
	if err != nil {
		return nil, err
	}
	if session != nil && len(row.Session) > 0 {
		if err := json.Unmarshal(row.Session, session); err != nil {
			return nil, err
		}
	}
	form, err := url.ParseQuery(row.Form)
	if err != nil {
		return nil, err
	}
	req := fosite.NewRequest()
	req.ID = row.RequestID
	req.RequestedAt = row.RequestedAt
	req.Client = client
	req.RequestedScope = row.Scopes
	req.GrantedScope = row.GrantedScopes
	req.Form = form
	req.Session = session
	return req, nil
}

func (s Store) create(ctx context.Context, kind, signature string, requester fosite.Requester, accessSig *string) error {
	tx, tenantID, err := storage.OAuthTx(ctx)
	if err != nil {
		return err
	}
	row, err := rowFor(requester)
	if err != nil {
		return err
	}
	return storage.CreateOAuthSession(ctx, tx, tenantID, kind, sig(signature), row, accessSig)
}

func (s Store) get(ctx context.Context, kind, signature string, session fosite.Session) (fosite.Requester, *storage.OAuthSessionRow, error) {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return nil, nil, err
	}
	row, err := storage.GetOAuthSession(ctx, tx, kind, sig(signature))
	if err != nil {
		return nil, nil, fosite.ErrNotFound
	}
	requester, err := s.requesterFor(ctx, row, session)
	return requester, row, err
}

func (s Store) delete(ctx context.Context, kind, signature string) error {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return err
	}
	return storage.DeleteOAuthSession(ctx, tx, kind, sig(signature))
}

// --- AuthorizeCodeStorage --------------------------------------------

func (s Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.create(ctx, kindCode, code, request, nil)
}

func (s Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	requester, row, err := s.get(ctx, kindCode, code, session)
	if err != nil {
		return nil, err
	}
	if !row.Active {
		return requester, fosite.ErrInvalidatedAuthorizeCode
	}
	return requester, nil
}

func (s Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return err
	}
	return storage.DeactivateOAuthSession(ctx, tx, kindCode, sig(code))
}

// --- AccessTokenStorage ----------------------------------------------

func (s Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.create(ctx, kindAccess, signature, request, nil)
}

func (s Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	requester, row, err := s.get(ctx, kindAccess, signature, session)
	if err != nil {
		return nil, err
	}
	if !row.Active {
		return requester, fosite.ErrInactiveToken
	}
	return requester, nil
}

func (s Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, kindAccess, signature)
}

// --- RefreshTokenStorage ---------------------------------------------

func (s Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	accessSig := sig(accessSignature)
	return s.create(ctx, kindRefresh, signature, request, &accessSig)
}

func (s Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	requester, row, err := s.get(ctx, kindRefresh, signature, session)
	if err != nil {
		return nil, err
	}
	if !row.Active {
		// Reuse of a rotated refresh token: fosite revokes the chain.
		return requester, fosite.ErrInactiveToken
	}
	return requester, nil
}

func (s Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, kindRefresh, signature)
}

// RotateRefreshToken retires the used refresh token and the access tokens
// minted alongside it.
func (s Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return err
	}
	if err := storage.DeactivateOAuthSession(ctx, tx, kindRefresh, sig(refreshTokenSignature)); err != nil {
		return err
	}
	return storage.DeleteOAuthSessionsByRequest(ctx, tx, kindAccess, requestID)
}

// --- TokenRevocationStorage ------------------------------------------

func (s Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return err
	}
	return storage.DeactivateOAuthSessionsByRequest(ctx, tx, kindRefresh, requestID)
}

func (s Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	tx, _, err := storage.OAuthTx(ctx)
	if err != nil {
		return err
	}
	return storage.DeleteOAuthSessionsByRequest(ctx, tx, kindAccess, requestID)
}

// --- PKCERequestStorage ----------------------------------------------

func (s Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.create(ctx, kindPKCE, signature, requester, nil)
}

func (s Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	requester, _, err := s.get(ctx, kindPKCE, signature, session)
	return requester, err
}

func (s Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.delete(ctx, kindPKCE, signature)
}

// --- OpenIDConnectRequestStorage -------------------------------------

func (s Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	return s.create(ctx, kindOIDC, authorizeCode, requester, nil)
}

func (s Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	found, _, err := s.get(ctx, kindOIDC, authorizeCode, requester.GetSession())
	return found, err
}

func (s Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.delete(ctx, kindOIDC, authorizeCode)
}
