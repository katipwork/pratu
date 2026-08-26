package identity

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

type Identity struct {
	ID        string          `json:"id"`
	SchemaID  string          `json:"schema_id"`
	Traits    json.RawMessage `json:"traits"`
	Addresses []Address       `json:"addresses,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// Credential kinds. Password is the only first factor in v1; TOTP and SMS
// are second factors (TOTP preferred when both are enrolled).
const (
	CredentialPassword = "password"
	CredentialTOTP     = "totp"
	CredentialSMS      = "sms"
	CredentialSocial   = "social"
)

var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

// NormalizePhone canonicalizes a phone number to E.164-ish form, reporting
// whether it is plausible.
func NormalizePhone(s string) (string, bool) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '(' || r == ')' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	return s, phonePattern.MatchString(s)
}

// Address channels.
const (
	ChannelEmail = "email"
	ChannelSMS   = "sms"
)

// Address is an email or phone number belonging to an identity. The For*
// flags mirror the Identity Schema's annotations: which purposes this
// address serves.
type Address struct {
	ID              string     `json:"id"`
	Channel         string     `json:"channel"`
	Value           string     `json:"value"`
	Verified        bool       `json:"verified"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	ForVerification bool       `json:"for_verification"`
	ForRecovery     bool       `json:"for_recovery"`
}

// AddressSpec is an address extracted from traits, before persistence.
type AddressSpec struct {
	Channel      string
	Value        string
	Verification bool
	Recovery     bool
}
