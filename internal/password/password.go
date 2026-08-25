// Package password enforces the NIST 800-63B-style password policy:
// a per-tenant minimum length and a breach-corpus check — deliberately no
// composition rules and no rotation (see ADR 0005).
package password

import (
	"context"
	"fmt"
	"unicode/utf8"
)

// MaxLength bounds hashing cost; NIST requires accepting at least 64
// characters.
const MaxLength = 128

// DefaultMinLength applies when a tenant configures nothing.
const DefaultMinLength = 10

type Policy struct {
	MinLength   int
	BreachCheck bool
}

// BreachChecker reports how many times a password appears in a known
// breach corpus.
type BreachChecker interface {
	BreachCount(ctx context.Context, password string) (int, error)
}

// Validate checks a candidate password against the policy. It returns the
// policy violations, plus any breach-checker failure separately: the
// checker being unreachable must not block signups (fail-open), but the
// caller should log it.
func Validate(ctx context.Context, candidate string, pol Policy, checker BreachChecker) (violations []string, checkErr error) {
	min := pol.MinLength
	if min <= 0 {
		min = DefaultMinLength
	}
	runes := utf8.RuneCountInString(candidate)
	if runes < min {
		return []string{fmt.Sprintf("password must be at least %d characters", min)}, nil
	}
	if runes > MaxLength {
		return []string{fmt.Sprintf("password must be at most %d characters", MaxLength)}, nil
	}
	if pol.BreachCheck && checker != nil {
		count, err := checker.BreachCount(ctx, candidate)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			return []string{fmt.Sprintf(
				"this password has appeared in %d known data breaches; choose a different one", count)}, nil
		}
	}
	return nil, nil
}
