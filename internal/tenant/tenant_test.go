package tenant

import (
	"context"
	"errors"
	"testing"
)

type fakeStore map[string]*Tenant

func (s fakeStore) FindBySlug(_ context.Context, slug string) (*Tenant, error) {
	if t, ok := s[slug]; ok {
		return t, nil
	}
	return nil, ErrNotFound
}

func TestResolver(t *testing.T) {
	store := fakeStore{"acme": {ID: "1", Slug: "acme", Name: "Acme"}}
	r := NewResolver("pratu.localhost", store)

	cases := []struct {
		host string
		slug string
		err  error
	}{
		{"acme.pratu.localhost", "acme", nil},
		{"acme.pratu.localhost:4433", "acme", nil},
		{"ACME.PRATU.LOCALHOST", "acme", nil},
		{"unknown.pratu.localhost", "", ErrNotFound},
		{"pratu.localhost", "", ErrNotFound},
		{"deep.acme.pratu.localhost", "", ErrNotFound},
		{"acme.evil.example.com", "", ErrNotFound},
		{"evilpratu.localhost", "", ErrNotFound},
	}
	for _, c := range cases {
		got, err := r.Resolve(context.Background(), c.host)
		if !errors.Is(err, c.err) {
			t.Errorf("Resolve(%q) error = %v, want %v", c.host, err, c.err)
			continue
		}
		if err == nil && got.Slug != c.slug {
			t.Errorf("Resolve(%q) slug = %q, want %q", c.host, got.Slug, c.slug)
		}
	}
}
