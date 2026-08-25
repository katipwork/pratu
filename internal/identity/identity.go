package identity

import (
	"encoding/json"
	"time"
)

type Identity struct {
	ID        string          `json:"id"`
	SchemaID  string          `json:"schema_id"`
	Traits    json.RawMessage `json:"traits"`
	CreatedAt time.Time       `json:"created_at"`
}

// Credential kinds. Password is the only first factor in v1.
const CredentialPassword = "password"
