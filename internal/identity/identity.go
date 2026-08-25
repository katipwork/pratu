package identity

import (
	"encoding/json"
	"time"
)

type Identity struct {
	ID        string          `json:"id"`
	SchemaID  string          `json:"schema_id"`
	Traits    json.RawMessage `json:"traits"`
	Addresses []Address       `json:"addresses,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// Credential kinds. Password is the only first factor in v1; TOTP is a
// second factor.
const (
	CredentialPassword = "password"
	CredentialTOTP     = "totp"
)

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
