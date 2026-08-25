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

// Credential kinds. Password is the only first factor in v1.
const CredentialPassword = "password"

// Address channels.
const (
	ChannelEmail = "email"
	ChannelSMS   = "sms"
)

// Address is an email or phone number belonging to an identity, usable
// for verification (and later recovery / SMS second factor).
type Address struct {
	ID         string     `json:"id"`
	Channel    string     `json:"channel"`
	Value      string     `json:"value"`
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// AddressSpec is an address extracted from traits, before persistence.
type AddressSpec struct {
	Channel string
	Value   string
}
