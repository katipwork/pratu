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
	// LoginURL is the tenant's own login UI; OAuth2 authorization
	// requests redirect there with a login_challenge (Hydra-style).
	LoginURL string `json:"login_url,omitempty"`
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
}

// Resolver maps a request's Host header to a Tenant. It is the only
// component in the codebase allowed to interpret hostnames (ADR 0003).
// v1 resolves {slug}.{baseDomain}; tenant-owned custom domains become an
// additional lookup here later.
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
	if !ok || slug == "" || strings.Contains(slug, ".") {
		return nil, ErrNotFound
	}
	return r.store.FindBySlug(ctx, slug)
}
