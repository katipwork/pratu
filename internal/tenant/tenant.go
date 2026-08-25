// Package tenant defines the Tenant — a fully isolated identity namespace —
// and the Resolver that maps request hostnames to tenants.
package tenant

import (
	"context"
	"errors"
	"net"
	"strings"
)

var ErrNotFound = errors.New("tenant not found")

type Tenant struct {
	ID   string
	Slug string
	Name string
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
