// Package social speaks the client side of social sign-in: generic OIDC
// providers (Google, Microsoft, another Pratu, …) via discovery and
// verified ID tokens, plus GitHub's plain-OAuth2 dialect.
package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/storage"
)

const (
	KindOIDC   = "oidc"
	KindGitHub = "github"
)

// Claims is what a provider asserted about the person.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Identifier is the per-tenant unique identifier a social account maps to.
func Identifier(providerID, subject string) string {
	return "social:" + providerID + ":" + subject
}

var githubEndpoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

func timeoutCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 15*time.Second)
}

// AuthURL builds the provider's authorization redirect.
func AuthURL(ctx context.Context, p *storage.SocialProvider, redirectURI, state string) (string, error) {
	cfg, _, err := oauthConfig(ctx, p, redirectURI)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state), nil
}

func oauthConfig(ctx context.Context, p *storage.SocialProvider, redirectURI string) (*oauth2.Config, *oidc.Provider, error) {
	switch p.Kind {
	case KindGitHub:
		return &oauth2.Config{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret,
			Endpoint: githubEndpoint, RedirectURL: redirectURI,
			Scopes: p.Scopes,
		}, nil, nil
	case KindOIDC:
		tctx, cancel := timeoutCtx(ctx)
		defer cancel()
		provider, err := oidc.NewProvider(tctx, p.Issuer)
		if err != nil {
			return nil, nil, fmt.Errorf("provider %s discovery: %w", p.ID, err)
		}
		return &oauth2.Config{
			ClientID: p.ClientID, ClientSecret: p.ClientSecret,
			Endpoint: provider.Endpoint(), RedirectURL: redirectURI,
			Scopes: p.Scopes,
		}, provider, nil
	default:
		return nil, nil, fmt.Errorf("unknown social provider kind %q", p.Kind)
	}
}

// Exchange redeems the callback code and returns the provider's verified
// claims about the person.
func Exchange(ctx context.Context, p *storage.SocialProvider, redirectURI, code string) (*Claims, error) {
	tctx, cancel := timeoutCtx(ctx)
	defer cancel()
	cfg, provider, err := oauthConfig(tctx, p, redirectURI)
	if err != nil {
		return nil, err
	}
	token, err := cfg.Exchange(tctx, code)
	if err != nil {
		return nil, fmt.Errorf("provider %s code exchange: %w", p.ID, err)
	}
	if p.Kind == KindGitHub {
		return githubClaims(tctx, cfg, token)
	}
	return oidcClaims(tctx, p, provider, token)
}

func oidcClaims(ctx context.Context, p *storage.SocialProvider, provider *oidc.Provider, token *oauth2.Token) (*Claims, error) {
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, errors.New("provider returned no id_token")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("provider %s id_token: %w", p.ID, err)
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&c); err != nil {
		return nil, err
	}
	email := identity.Normalize(c.Email)
	return &Claims{
		Subject:       idToken.Subject,
		Email:         email,
		EmailVerified: c.EmailVerified,
		Name:          c.Name,
	}, nil
}

func githubClaims(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (*Claims, error) {
	client := cfg.Client(ctx, token)

	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := getJSON(ctx, client, "https://api.github.com/user", &user); err != nil {
		return nil, err
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, client, "https://api.github.com/user/emails", &emails); err != nil {
		return nil, err
	}
	claims := &Claims{Subject: fmt.Sprintf("%d", user.ID), Name: user.Name}
	if claims.Name == "" {
		claims.Name = user.Login
	}
	for _, e := range emails {
		if e.Primary {
			claims.Email = identity.Normalize(e.Email)
			claims.EmailVerified = e.Verified
			break
		}
	}
	return claims, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
