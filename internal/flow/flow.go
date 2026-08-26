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
	KindSMSEnroll    Kind = "sms_enroll"
	KindOAuth2       Kind = "oauth2"
)

// Lifetime is how long a flow may sit unsubmitted.
const Lifetime = 30 * time.Minute

type Flow struct {
	ID        string          `json:"id"`
	Kind      Kind            `json:"kind"`
	ExpiresAt time.Time       `json:"expires_at"`
	Browser   bool            `json:"-"`
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
// design); CodeOK gates the second-factor step (when one is enrolled —
// recovery does not bypass it) and SecondFactorOK/CodeOK gate the final
// set-password step.
type RecoveryContext struct {
	IdentityID     string `json:"identity_id,omitempty"`
	AddressID      string `json:"address_id,omitempty"`
	CodeOK         bool   `json:"code_ok,omitempty"`
	SecondFactorOK bool   `json:"second_factor_ok,omitempty"`
	FactorAttempts int    `json:"factor_attempts,omitempty"`
}

// LoginContext appears on a login flow once the password is proven but a
// second factor is still owed.
type LoginContext struct {
	IdentityID     string `json:"identity_id"`
	PasswordOK     bool   `json:"password_ok"`
	FactorAttempts int    `json:"factor_attempts,omitempty"`
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

// SMSEnrollContext holds a pending second-factor phone number: it becomes
// a credential only once its holder proves a delivered code.
type SMSEnrollContext struct {
	IdentityID string `json:"identity_id"`
	SessionID  string `json:"session_id"`
	Phone      string `json:"phone"`
}

// OAuth2Context is a Login/Consent Challenge: the parked authorization
// request, waiting for the tenant's login UI to prove a user and accept.
type OAuth2Context struct {
	Query      string `json:"query"` // the original /oauth2/auth query string
	IdentityID string `json:"identity_id,omitempty"`
	AAL        string `json:"aal,omitempty"`
	Email      string `json:"email,omitempty"`
	Granted    bool   `json:"granted,omitempty"`
}
