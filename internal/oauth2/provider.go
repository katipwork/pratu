package oauth2

import (
	"context"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"

	"github.com/katipwork/pratu/internal/storage"
)

// Token lifetimes (Q18): short JWT access tokens, rotating refresh
// tokens. Per-tenant overrides arrive with tenant config work.
const (
	AccessTokenLifespan   = 15 * time.Minute
	RefreshTokenLifespan  = 30 * 24 * time.Hour
	AuthorizeCodeLifespan = 10 * time.Minute
)

// Providers hands out one fosite provider per tenant issuer: issuers and
// signing keys are per-tenant (ADR 0003, Q17), and fosite configs are
// static, so each (tenant, issuer) pair gets its own composed instance.
type Providers struct {
	secret []byte
	mu     sync.Mutex
	cache  map[string]fosite.OAuth2Provider
}

func NewProviders(systemSecret []byte) *Providers {
	return &Providers{secret: systemSecret, cache: map[string]fosite.OAuth2Provider{}}
}

// For returns the provider for a tenant issuer, loading (or minting) the
// tenant's active signing key on first use.
func (p *Providers) For(ctx context.Context, tx pgx.Tx, tenantID, issuer string) (fosite.OAuth2Provider, error) {
	cacheKey := tenantID + "|" + issuer

	p.mu.Lock()
	if prov, ok := p.cache[cacheKey]; ok {
		p.mu.Unlock()
		return prov, nil
	}
	p.mu.Unlock()

	key, err := storage.ActiveTenantKey(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	webKey := &jose.JSONWebKey{Key: key.Key, KeyID: key.KID, Algorithm: "RS256", Use: "sig"}
	keyGetter := func(context.Context) (interface{}, error) { return webKey, nil }

	config := &fosite.Config{
		AccessTokenIssuer:           issuer,
		IDTokenIssuer:               issuer,
		GlobalSecret:                p.secret,
		AccessTokenLifespan:         AccessTokenLifespan,
		RefreshTokenLifespan:        RefreshTokenLifespan,
		AuthorizeCodeLifespan:       AuthorizeCodeLifespan,
		IDTokenLifespan:             time.Hour,
		ScopeStrategy:               fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:    fosite.DefaultAudienceMatchingStrategy,
		RefreshTokenScopes:          []string{"offline_access"},
		EnforcePKCEForPublicClients: true,
	}

	store := Store{}
	hmacStrategy := compose.NewOAuth2HMACStrategy(config)
	strategy := compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, config),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}

	prov := compose.Compose(config, store, strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
	)

	p.mu.Lock()
	p.cache[cacheKey] = prov
	p.mu.Unlock()
	return prov, nil
}

// Invalidate drops a tenant's cached providers so the next request
// rebuilds them against the current active key (called after rotation).
func (p *Providers) Invalidate(tenantID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.cache {
		if strings.HasPrefix(key, tenantID+"|") {
			delete(p.cache, key)
		}
	}
}

// JWKS renders every tenant key (active and retired) as a public key set.
func JWKS(ctx context.Context, tx pgx.Tx) (*jose.JSONWebKeySet, error) {
	keys, err := storage.VerificationKeys(ctx, tx)
	if err != nil {
		return nil, err
	}
	set := &jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key: k.Key.Public(), KeyID: k.KID, Algorithm: "RS256", Use: "sig",
		})
	}
	return set, nil
}
