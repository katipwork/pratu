// Package flow defines Self-Service Flows: stateful, server-driven
// interactions (registration, login, …) that clients render from JSON.
package flow

import (
	"encoding/json"
	"time"
)

type Kind string

const (
	KindRegistration Kind = "registration"
	KindLogin        Kind = "login"
	KindVerification Kind = "verification"
	KindRecovery     Kind = "recovery"
	KindTOTPEnroll   Kind = "totp_enroll"
)

// Lifetime is how long a flow may sit unsubmitted.
const Lifetime = 30 * time.Minute

type Flow struct {
	ID        string          `json:"id"`
	Kind      Kind            `json:"kind"`
	ExpiresAt time.Time       `json:"expires_at"`
	Context   json.RawMessage `json:"-"`
}

// VerificationContext is the server-side state of a verification flow:
// which address is being proven, for whom, and whether success should
// issue a session (registration/login held one back).
type VerificationContext struct {
	IdentityID   string `json:"identity_id"`
	AddressID    string `json:"address_id"`
	IssueSession bool   `json:"issue_session"`
}

// RecoveryContext tracks a recovery flow's progress. Empty until an
// existing address is submitted (indistinguishable from a miss, by
// design); CodeOK gates the TOTP step (when enrolled — recovery does not
// bypass a second factor) and TOTPOK/CodeOK gate the final set-password
// step.
type RecoveryContext struct {
	IdentityID   string `json:"identity_id,omitempty"`
	AddressID    string `json:"address_id,omitempty"`
	CodeOK       bool   `json:"code_ok,omitempty"`
	TOTPOK       bool   `json:"totp_ok,omitempty"`
	TOTPAttempts int    `json:"totp_attempts,omitempty"`
}

// LoginContext appears on a login flow once the password is proven but a
// second factor is still owed.
type LoginContext struct {
	IdentityID   string `json:"identity_id"`
	PasswordOK   bool   `json:"password_ok"`
	TOTPAttempts int    `json:"totp_attempts,omitempty"`
}

// TOTPEnrollContext holds a pending TOTP secret: it becomes a credential
// only once the holder proves a code from it, so a mis-scanned QR cannot
// lock anyone out.
type TOTPEnrollContext struct {
	IdentityID string `json:"identity_id"`
	SessionID  string `json:"session_id"`
	Secret     string `json:"secret"`
	Attempts   int    `json:"attempts,omitempty"`
}
