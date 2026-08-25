// Package flow defines Self-Service Flows: stateful, server-driven
// interactions (registration, login, …) that clients render from JSON.
package flow

import "time"

type Kind string

const (
	KindRegistration Kind = "registration"
	KindLogin        Kind = "login"
)

// Lifetime is how long a flow may sit unsubmitted.
const Lifetime = 30 * time.Minute

type Flow struct {
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	ExpiresAt time.Time `json:"expires_at"`
}
