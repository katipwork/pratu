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
	KindSocial       Kind = "social"
)

// Lifetime is how long a flow may sit unsubmitted.
const Lifetime = 30 * time.Minute

// State names the step a flow is waiting on, so a UI that re-reads the
// flow after a redirect knows which screen to render.
const (
	StateChooseMethod         = "choose_method"          // the flow's opening step
	StateMFARequired          = "mfa_required"           // password proven, second factor owed
	StateCodeRequired         = "code_required"          // a One-Time Code is outstanding
	StateSecondFactorRequired = "second_factor_required" // recovery code proven, second factor owed
	StatePasswordRequired     = "password_required"      // recovery proven, new password owed
)

// MessageType classifies a UI message.
const (
	MessageError   = "error"
	MessageInfo    = "info"
	MessageSuccess = "success"
)

// Message is one thing to tell the person driving the flow. Messages are
// persisted on the flow so a redirected browser can read back why its
// submission failed.
type Message struct {
	Type    string   `json:"type"`
	Text    string   `json:"text"`
	Details []string `json:"details,omitempty"`
}

type Flow struct {
	ID        string          `json:"id"`
	Kind      Kind            `json:"kind"`
	ExpiresAt time.Time       `json:"expires_at"`
	State     string          `json:"state,omitempty"`
	Messages  []Message       `json:"messages,omitempty"`
	Browser   bool            `json:"-"`
	Context   json.RawMessage `json:"-"`
	// ReturnTo is where a completed browser flow sends the browser;
	// validated against the tenant's allow-list when the flow is created.
	ReturnTo string `json:"-"`
	// CSRFFingerprint binds the flow to the browser that created it, so
	// only that browser can read the flow back.
	CSRFFingerprint string `json:"-"`
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

// SocialContext tracks a social sign-in round trip; the flow ID doubles
// as the OAuth2 state parameter.
type SocialContext struct {
	Provider string `json:"provider"`
}

// RegistrationContext pins the schema version chosen when the flow was
// created, so a schema update mid-flow cannot shift validation.
type RegistrationContext struct {
	SchemaID string `json:"schema_id,omitempty"`
}

// OAuth2Context is a Login/Consent Challenge: the parked authorization
// request, waiting for the tenant's login UI to prove a user and accept
// (with per-scope consent) or reject it.
type OAuth2Context struct {
	Query         string   `json:"query"` // the original /oauth2/auth query string
	IdentityID    string   `json:"identity_id,omitempty"`
	AAL           string   `json:"aal,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Granted       bool     `json:"granted,omitempty"`
	GrantedScopes []string `json:"granted_scopes,omitempty"`
	Rejected      bool     `json:"rejected,omitempty"`
}
