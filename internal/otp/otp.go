// Package otp generates and checks One-Time Codes: short-lived numeric
// codes proving control of an address. Codes are stored hashed and guarded
// by an attempt counter — six digits are only safe because guessing is
// bounded.
package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"
	"time"
)

const (
	Lifetime    = 15 * time.Minute
	MaxAttempts = 5
)

// Generate returns a 6-digit code.
func Generate() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n), nil
}

// Hash maps a code to its storage form.
func Hash(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

// Matches compares a submitted code against a stored hash in constant time.
func Matches(hash []byte, code string) bool {
	return subtle.ConstantTimeCompare(hash, Hash(code)) == 1
}
