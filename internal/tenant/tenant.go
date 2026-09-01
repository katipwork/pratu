// Package tenant defines the Tenant — a fully isolated identity namespace —
// and the Resolver that maps request hostnames to tenants.
package tenant

import (
	"context"
	"errors"
	"net"
	"strings"
)

var (
	ErrNotFound  = errors.New("tenant not found")
	ErrSlugTaken = errors.New("tenant slug already in use")
)

type Tenant struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Config Config `json:"config"`
}

// Verification policy values.
const (
	VerificationRequired = "required" // no session until an address is verified (default)
	VerificationDeferred = "deferred" // session immediately, verification nags later
)

// MFA policy values.
const (
	MFAOff      = "off"      // second factors hidden entirely
	MFAOptional = "optional" // users may enrol; login asks only if enrolled (default)
	MFARequired = "required" // every login must end at aal2; unenrolled users are told to enrol
)

// Config is the tenant's policy configuration, stored as JSON on the
// tenant row. Zero values mean defaults.
type Config struct {
	Verification string         `json:"verification,omitempty"`
	Password     PasswordConfig `json:"password,omitempty"`
	// SMSDailyCap bounds total SMS sends per day across the whole tenant
	// (pumping protection); 0 means the default.
	SMSDailyCap int `json:"sms_daily_cap,omitempty"`
	// MFA is the second-factor policy: off, optional (default), required.
	MFA string `json:"mfa,omitempty"`
	// UI names the tenant's own screens; Browser Flows drive HTML
	// clients there by redirect (ADR 0006).
	UI UIConfig `json:"ui,omitempty"`
	// LoginURL is the tenant's own login UI; OAuth2 authorization
	// requests redirect there with a login_challenge (Hydra-style).
	//
	// Deprecated: superseded by UI.LoginURL, still read as a fallback.
	LoginURL string `json:"login_url,omitempty"`
	// SocialReturnURL is where the browser lands after a social sign-in
	// round trip (falls back to LoginURL).
	//
	// Deprecated: superseded by UI.DefaultReturnURL, still read as a
	// fallback.
	SocialReturnURL string `json:"social_return_url,omitempty"`
}

// UIConfig points at the tenant's screens. Each Self-Service Flow kind
// has its own screen, plus one screen for failures that have no flow to
// return to and one landing place for completed flows.
type UIConfig struct {
	LoginURL         string `json:"login_url,omitempty"`
	RegistrationURL  string `json:"registration_url,omitempty"`
	RecoveryURL      string `json:"recovery_url,omitempty"`
	VerificationURL  string `json:"verification_url,omitempty"`
	ErrorURL         string `json:"error_url,omitempty"`
	DefaultReturnURL string `json:"default_return_url,omitempty"`
	// AllowedReturnURLs widens the return_to allow-list beyond the
	// origins of the screens above (for apps served from another origin).
	AllowedReturnURLs []string `json:"allowed_return_urls,omitempty"`
}

// EffectiveLoginUIURL is the login screen: the new block first, then the
// deprecated top-level field.
func (c Config) EffectiveLoginUIURL() string {
	if c.UI.LoginURL != "" {
		return c.UI.LoginURL
	}
	return c.LoginURL
}

func (c Config) EffectiveRegistrationUIURL() string { return c.UI.RegistrationURL }
func (c Config) EffectiveRecoveryUIURL() string     { return c.UI.RecoveryURL }
func (c Config) EffectiveVerificationUIURL() string { return c.UI.VerificationURL }
func (c Config) EffectiveErrorUIURL() string        { return c.UI.ErrorURL }

// EffectiveDefaultReturnURL is where a completed Browser Flow lands when
// the flow carries no return_to.
func (c Config) EffectiveDefaultReturnURL() string {
	if c.UI.DefaultReturnURL != "" {
		return c.UI.DefaultReturnURL
	}
	return c.SocialReturnURL
}

// EffectiveSocialReturnURL is where a social sign-in round trip lands.
func (c Config) EffectiveSocialReturnURL() string {
	if u := c.EffectiveDefaultReturnURL(); u != "" {
		return u
	}
	return c.EffectiveLoginUIURL()
}

// UIScreenURLs are every configured screen, the origins of which are
// implicitly allowed as return_to targets.
func (c Config) UIScreenURLs() []string {
	candidates := []string{
		c.EffectiveLoginUIURL(),
		c.UI.RegistrationURL,
		c.UI.RecoveryURL,
		c.UI.VerificationURL,
		c.UI.ErrorURL,
		c.EffectiveDefaultReturnURL(),
	}
	var out []string
	for _, u := range candidates {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

func (c Config) EffectiveMFA() string {
	if c.MFA == "" {
		return MFAOptional
	}
	return c.MFA
}

// DefaultSMSDailyCap applies when a tenant configures no cap.
const DefaultSMSDailyCap = 1000

func (c Config) EffectiveSMSDailyCap() int {
	if c.SMSDailyCap > 0 {
		return c.SMSDailyCap
	}
	return DefaultSMSDailyCap
}

func (c Config) VerificationRequired() bool {
	return c.Verification != VerificationDeferred
}

// PasswordConfig is the tenant's password policy: NIST-style, so minimum
// length and breach checking are the only knobs — composition rules are
// deliberately not offered (ADR 0005).
type PasswordConfig struct {
	MinLength   int   `json:"min_length,omitempty"`   // 0 means the default (10)
	BreachCheck *bool `json:"breach_check,omitempty"` // nil means enabled
}

func (p PasswordConfig) BreachCheckEnabled() bool {
	return p.BreachCheck == nil || *p.BreachCheck
}

// Store loads tenants from persistent storage.
type Store interface {
	FindBySlug(ctx context.Context, slug string) (*Tenant, error)
	FindByDomain(ctx context.Context, domain string) (*Tenant, error)
}

// Resolver maps a request's Host header to a Tenant. It is the only
// component in the codebase allowed to interpret hostnames (ADR 0003):
// {slug}.{baseDomain} resolves by slug, anything else by the custom
// domain table.
type Resolver struct {
	baseDomain string
	store      Store
}

func NewResolver(baseDomain string, store Store) *Resolver {
	return &Resolver{baseDomain: strings.ToLower(baseDomain), store: store}
}

func (r *Resolver) Resolve(ctx context.Context, host string) (*Tenant, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	slug, ok := strings.CutSuffix(host, "."+r.baseDomain)
	if !ok {
		return r.store.FindByDomain(ctx, host)
	}
	if slug == "" || strings.Contains(slug, ".") {
		return nil, ErrNotFound
	}
	return r.store.FindBySlug(ctx, slug)
}
