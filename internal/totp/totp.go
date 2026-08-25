// Package totp wraps the TOTP primitives (RFC 6238 via pquerna/otp) used
// for the second factor: standard 6-digit, 30-second codes that any
// authenticator app accepts.
package totp

import (
	"github.com/pquerna/otp/totp"
)

// Generate creates a fresh secret for enrolment. issuer and account label
// the entry in the authenticator app (tenant name / user identifier); uri
// is the otpauth:// URL clients render as a QR code.
func Generate(issuer, account string) (secret, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Validate checks a submitted code against the secret (±1 period skew).
func Validate(code, secret string) bool {
	return totp.Validate(code, secret)
}
