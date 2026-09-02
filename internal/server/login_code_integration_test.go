package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// The passwordless first factor, end to end (ADR 0007): a Tenant that
// opts into first_factor "code" lets an Identity sign in by proving a
// verification-annotated Address with a One-Time Code, with no password
// credential anywhere.

// codeTenant is a phone-first Tenant: One-Time Codes are its only first
// factor, and a session waits on nothing but the phone.
func codeTenant() map[string]any {
	return map[string]any{
		"first_factor": []string{"code"},
		"ui":           screens(),
	}
}

var phoneSeq int64

// testPhone is a unique mobile number in the international format a
// phone-first product identifies people by.
func testPhone(t *testing.T) string {
	t.Helper()
	n := atomic.AddInt64(&phoneSeq, 1)
	return fmt.Sprintf("+6681%03d%04d", n%1000, time.Now().UnixNano()%10000)
}

// putPhoneSchema replaces the tenant's default Identity Schema with the
// phone-only one from the issue: no email anywhere, the phone is both the
// login identifier and the SMS address.
func putPhoneSchema(t *testing.T, h *harness, tn *testTenant) {
	t.Helper()
	r := h.adminRequest(t, http.MethodPut, "/admin/tenants/"+tn.Slug+"/schemas/default", map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"required":             []string{"phone"},
		"additionalProperties": false,
		"properties": map[string]any{
			"phone": map[string]any{
				"type":  "string",
				"title": "Mobile number",
				"pratu": map[string]any{
					"identifier":   true,
					"verification": map[string]any{"via": "sms"},
					"recovery":     map[string]any{"via": "sms"},
				},
			},
		},
	})
	if r.Status != http.StatusOK && r.Status != http.StatusCreated {
		t.Fatalf("put phone schema: status %d body %s", r.Status, r.Body)
	}
}

// registerByCode drives a passwordless registration to a live session:
// traits only, then the One-Time Code that proves the Address.
func registerByCode(t *testing.T, h *harness, b *browser, phone string) {
	t.Helper()
	f := b.createFlow(t, "/self-service/registration/browser")
	for _, field := range f.UI.Fields {
		if field.Name == "password" {
			t.Fatalf("a code-only tenant must not ask for a password: fields %+v", f.UI.Fields)
		}
	}

	r := b.postJSON(t, "/self-service/registration?flow="+f.ID, map[string]any{
		"method":     "code",
		"traits":     map[string]any{"phone": phone},
		"csrf_token": f.CSRFToken,
	})
	r.requireStatus(t, http.StatusOK)
	var reg struct {
		State        string `json:"state"`
		Verification struct {
			FlowID    string `json:"flow_id"`
			CSRFToken string `json:"csrf_token"`
		} `json:"verification"`
	}
	r.decode(t, &reg)
	if reg.State != "verification_required" {
		t.Fatalf("state = %q, want verification_required", reg.State)
	}

	done := b.postJSON(t, "/self-service/verification?flow="+reg.Verification.FlowID, map[string]any{
		"code":       h.latestCode(t, phone),
		"csrf_token": reg.Verification.CSRFToken,
	})
	done.requireStatus(t, http.StatusOK)
	// The verification code has spent this address's delivery budget; a
	// login code is not what the cooldown is guarding.
	h.clearSendCooldown(t, h.tenantIDOf(b), phone)
}

// tenantIDOf is the tenant a browser drives.
func (h *harness) tenantIDOf(b *browser) string { return b.tenant.ID }

// countMessages is how many Courier messages an address has been sent —
// the assertion behind "nothing was delivered".
func (h *harness) countMessages(t *testing.T, recipient string) int {
	t.Helper()
	var n int
	err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM courier_messages WHERE recipient = $1`, recipient).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// hasPasswordCredential reports whether an identifier has a password at
// all — a passwordless Identity must have none. Credentials are behind
// RLS, so the read runs in the tenant the app would run it in.
func (h *harness) hasPasswordCredential(t *testing.T, tenantID, identifier string) bool {
	t.Helper()
	var n int
	err := storage.InTenant(context.Background(), h.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT count(*)
			   FROM identity_identifiers ii
			   JOIN identity_credentials c ON c.identity_id = ii.identity_id AND c.kind = $2
			  WHERE ii.identifier = $1`,
			identifier, identity.CredentialPassword).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// loginByCode signs in with a One-Time Code and returns the send and
// submit responses.
func loginByCode(t *testing.T, h *harness, b *browser, phone string) *resp {
	t.Helper()
	f := b.createFlow(t, "/self-service/login/browser")
	sent := b.postForm(t, "/self-service/login/code/send?flow="+f.ID, url.Values{
		"identifier": {phone},
		"csrf_token": {f.CSRFToken},
	})
	sent.requireRedirectToFlow(t, loginScreen)

	step := b.readFlow(t, f.ID)
	if step.State != flow.StateCodeRequired {
		t.Fatalf("state = %q, want %q", step.State, flow.StateCodeRequired)
	}
	return b.postForm(t, "/self-service/login/code?flow="+f.ID, url.Values{
		"code":       {h.latestCode(t, phone)},
		"csrf_token": {step.CSRFToken},
	})
}

// TestPasswordTenantUntouched: a Tenant that never configured
// first_factor behaves exactly as it did before ADR 0007.
func TestPasswordTenantUntouched(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	b := h.browser(t, tn)

	f := b.createFlow(t, "/self-service/login/browser")
	if len(f.UI.Methods) != 0 {
		t.Errorf("ui.methods = %v, want nothing advertised for a password-only tenant", f.UI.Methods)
	}
	var names []string
	for _, field := range f.UI.Fields {
		names = append(names, field.Name+":"+field.Title)
	}
	if strings.Join(names, ",") != "identifier:Email,password:Password" {
		t.Errorf("login fields = %v, want the unchanged identifier/password pair", names)
	}

	t.Run("the code endpoints refuse the method", func(t *testing.T) {
		r := b.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
			"identifier": "someone@example.test",
			"csrf_token": f.CSRFToken,
		})
		r.requireStatus(t, http.StatusBadRequest)
		if msg := r.errorMessage(t); msg != `unsupported method; use "password"` {
			t.Errorf("message = %q, want the unsupported-method refusal", msg)
		}
		if h.countMessages(t, "someone@example.test") != 0 {
			t.Error("a refused method must deliver nothing")
		}
	})

	t.Run("registration still requires a password", func(t *testing.T) {
		reg := b.createFlow(t, "/self-service/registration/browser")
		r := b.postJSON(t, "/self-service/registration?flow="+reg.ID, map[string]any{
			"method":     "code",
			"traits":     map[string]any{"email": testEmail(t)},
			"csrf_token": reg.CSRFToken,
		})
		r.requireStatus(t, http.StatusBadRequest)
	})
}

// TestPasswordlessRegistrationAndLogin is the journey the issue asked
// for: a phone-only Identity Schema, no password at any point, and a
// session at the end of it.
func TestPasswordlessRegistrationAndLogin(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, codeTenant())
	putPhoneSchema(t, h, tn)
	phone := testPhone(t)

	registerByCode(t, h, h.browser(t, tn), phone)
	if h.hasPasswordCredential(t, tn.ID, phone) {
		t.Fatal("a code registration must write no password credential")
	}

	// A fresh browser signs in from nothing but the phone.
	b := h.browser(t, tn)
	done := loginByCode(t, h, b, phone)
	done.requireRedirect(t, defaultReturn)
	if done.cookie(sessionCookieName) == nil {
		t.Fatal("proving the code should issue the session")
	}

	t.Run("an API flow gets a session token, never a cookie", func(t *testing.T) {
		h.clearSendCooldown(t, tn.ID, phone)
		api := h.browser(t, tn).withIP(nextTestIP())
		start := api.do(t, http.MethodPost, "/self-service/login/api", acceptJSON, "", nil, nil)
		start.requireStatus(t, http.StatusOK)
		var f flowResponse
		start.decode(t, &f)
		if f.CSRFToken != "" {
			t.Error("an API flow carries no CSRF token")
		}

		api.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
			"identifier": phone,
		}).requireStatus(t, http.StatusOK)

		done := api.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
			"code": h.latestCode(t, phone),
		})
		done.requireStatus(t, http.StatusOK)
		var body struct {
			State        string `json:"state"`
			SessionToken string `json:"session_token"`
		}
		done.decode(t, &body)
		if body.State != "active" || body.SessionToken == "" {
			t.Fatalf("api login = %+v, want an active session with a token", body)
		}
		if done.cookie(sessionCookieName) != nil {
			t.Error("an API flow must not set the session cookie")
		}
	})

	t.Run("the session is aal1 and its identity has the address verified", func(t *testing.T) {
		who := b.getJSON(t, "/sessions/whoami")
		who.requireStatus(t, http.StatusOK)
		var body struct {
			Session struct {
				AAL string `json:"aal"`
			} `json:"session"`
			Identity struct {
				Addresses []identity.Address `json:"addresses"`
			} `json:"identity"`
		}
		who.decode(t, &body)
		if body.Session.AAL != "aal1" {
			t.Errorf("aal = %q, want aal1: one factor is one factor", body.Session.AAL)
		}
		if len(body.Identity.Addresses) != 1 || !body.Identity.Addresses[0].Verified {
			t.Errorf("addresses = %+v, want the proven address marked verified", body.Identity.Addresses)
		}
	})
}

// TestLoginCodeSendIsIndistinguishable: the send step is the whole
// interaction, so it must be an oracle for nothing.
func TestLoginCodeSendIsIndistinguishable(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, codeTenant())
	putPhoneSchema(t, h, tn)
	known := testPhone(t)
	registerByCode(t, h, h.browser(t, tn), known)
	stranger := testPhone(t)

	send := func(t *testing.T, b *browser, identifier string) (flowResponse, string) {
		t.Helper()
		f := b.createFlow(t, "/self-service/login/browser")
		r := b.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
			"identifier": identifier,
			"csrf_token": f.CSRFToken,
		})
		r.requireStatus(t, http.StatusOK)
		var body struct {
			State   string `json:"state"`
			Message string `json:"message"`
		}
		r.decode(t, &body)
		// The screen the browser lands on is part of the answer, so read
		// the flow back the way that screen would.
		return b.readFlow(t, f.ID), body.State + "|" + body.Message
	}

	knownBrowser := h.browser(t, tn)
	strangerBrowser := h.browser(t, tn).withIP(nextTestIP())
	knownFlow, knownAnswer := send(t, knownBrowser, known)
	strangerFlow, strangerAnswer := send(t, strangerBrowser, stranger)
	if knownAnswer != strangerAnswer {
		t.Errorf("answers differ: known %q, unknown %q", knownAnswer, strangerAnswer)
	}
	if !strings.Contains(strangerAnswer, "code_sent") {
		t.Errorf("answer = %q, want the uniform code_sent", strangerAnswer)
	}
	if n := h.countMessages(t, stranger); n != 0 {
		t.Errorf("%d messages delivered to an unknown identifier, want 0", n)
	}

	t.Run("both screens render the same step and message", func(t *testing.T) {
		if knownFlow.State != flow.StateCodeRequired || strangerFlow.State != flow.StateCodeRequired {
			t.Errorf("states = %q and %q, want both %q",
				knownFlow.State, strangerFlow.State, flow.StateCodeRequired)
		}
		if got, want := firstMessage(t, strangerFlow), firstMessage(t, knownFlow); got != want {
			t.Errorf("unknown identifier renders %q, known renders %q", got, want)
		}
		if len(strangerFlow.UI.Fields) != 1 || strangerFlow.UI.Fields[0].Name != "code" {
			t.Errorf("fields = %+v, want just the code", strangerFlow.UI.Fields)
		}
	})

	t.Run("a code submitted against the unknown flow is just wrong", func(t *testing.T) {
		b := h.browser(t, tn).withIP(nextTestIP())
		f := b.createFlow(t, "/self-service/login/browser")
		b.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
			"identifier": testPhone(t),
			"csrf_token": f.CSRFToken,
		}).requireStatus(t, http.StatusOK)

		r := b.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
			"code":       "000000",
			"csrf_token": f.CSRFToken,
		})
		r.requireStatus(t, http.StatusUnauthorized)
		if msg := r.errorMessage(t); msg != "incorrect code" {
			t.Errorf("message = %q, want %q", msg, "incorrect code")
		}
	})
}

// TestLoginCodeSuppressedBySendCap: an address over its delivery budget
// must look exactly like an address that does not exist — never a 429,
// which would say "this number is registered".
func TestLoginCodeSuppressedBySendCap(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, codeTenant())
	putPhoneSchema(t, h, tn)
	phone := testPhone(t)
	registerByCode(t, h, h.browser(t, tn), phone)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/login/browser")
	first := b.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
		"identifier": phone,
		"csrf_token": f.CSRFToken,
	})
	first.requireStatus(t, http.StatusOK)
	delivered := h.countMessages(t, phone)

	// Straight back for another: inside the one-per-minute cooldown.
	again := h.browser(t, tn).withIP(nextTestIP())
	f2 := again.createFlow(t, "/self-service/login/browser")
	second := again.postJSON(t, "/self-service/login/code/send?flow="+f2.ID, map[string]any{
		"identifier": phone,
		"csrf_token": f2.CSRFToken,
	})
	second.requireStatus(t, http.StatusOK)
	if string(second.Body) != string(first.Body) {
		t.Errorf("a capped send answered %s, want the same as %s", second.Body, first.Body)
	}
	if n := h.countMessages(t, phone); n != delivered {
		t.Errorf("messages = %d, want %d: the capped send must deliver nothing", n, delivered)
	}
}

// TestLoginCodeAttemptBudget: wrong codes burn the code's attempts, not
// the send budget — mistyping must not lock a person out of signing in.
func TestLoginCodeAttemptBudget(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, codeTenant())
	putPhoneSchema(t, h, tn)
	phone := testPhone(t)
	registerByCode(t, h, h.browser(t, tn), phone)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/login/browser")
	b.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
		"identifier": phone,
		"csrf_token": f.CSRFToken,
	}).requireStatus(t, http.StatusOK)

	// Four wrong guesses stay recoverable: the real code still works.
	for i := range 4 {
		r := b.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
			"code":       "00000" + fmt.Sprint(i),
			"csrf_token": f.CSRFToken,
		})
		r.requireStatus(t, http.StatusUnauthorized)
	}
	done := b.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
		"code":       h.latestCode(t, phone),
		"csrf_token": f.CSRFToken,
	})
	done.requireStatus(t, http.StatusOK)

	t.Run("a sixth guess exhausts the budget", func(t *testing.T) {
		other := h.browser(t, tn).withIP(nextTestIP())
		phone2 := testPhone(t)
		registerByCode(t, h, h.browser(t, tn), phone2)
		f := other.createFlow(t, "/self-service/login/browser")
		other.postJSON(t, "/self-service/login/code/send?flow="+f.ID, map[string]any{
			"identifier": phone2,
			"csrf_token": f.CSRFToken,
		}).requireStatus(t, http.StatusOK)

		var last *resp
		for range 6 {
			last = other.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
				"code":       "000000",
				"csrf_token": f.CSRFToken,
			})
		}
		last.requireStatus(t, http.StatusBadRequest)
		if msg := last.errorMessage(t); !strings.Contains(msg, "too many attempts") {
			t.Errorf("message = %q, want the exhausted-budget refusal", msg)
		}
	})
}

// TestBothFirstFactors: a Tenant may accept passwords and codes at once,
// and says so.
func TestBothFirstFactors(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, map[string]any{
		"first_factor": []string{"password", "code"},
		"verification": "deferred",
		"ui":           screens(),
	})
	email := testEmail(t)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/login/browser")
	if strings.Join(f.UI.Methods, ",") != "password,code" {
		t.Errorf("ui.methods = %v, want both first factors advertised", f.UI.Methods)
	}

	// Password registration and login still work untouched.
	registerIdentityWith(t, h.browser(t, tn), email)
	if !h.hasPasswordCredential(t, tn.ID, email) {
		t.Fatal("a password registration must write a password credential")
	}
	r := b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
		"method":     {"password"},
		"identifier": {email},
		"password":   {testPassword},
		"csrf_token": {f.CSRFToken},
	})
	r.requireRedirect(t, defaultReturn)

	t.Run("the same identity can also sign in with a code", func(t *testing.T) {
		h.clearSendCooldown(t, tn.ID, email)
		codeBrowser := h.browser(t, tn).withIP(nextTestIP())
		done := loginByCode(t, h, codeBrowser, email)
		done.requireRedirect(t, defaultReturn)
		if done.cookie(sessionCookieName) == nil {
			t.Error("a code login should issue a session for a password identity too")
		}
	})
}

// TestCodeLoginStillOwesSecondFactor: a code is one factor, so an
// enrolled second factor is still owed on top of it.
func TestCodeLoginStillOwesSecondFactor(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, codeTenant())
	putPhoneSchema(t, h, tn)
	phone := testPhone(t)

	enrolled := h.browser(t, tn)
	registerByCode(t, h, enrolled, phone)
	secret := enrollTOTP(t, enrolled)

	b := h.browser(t, tn).withIP(nextTestIP())
	f := b.createFlow(t, "/self-service/login/browser")
	b.postForm(t, "/self-service/login/code/send?flow="+f.ID, url.Values{
		"identifier": {phone},
		"csrf_token": {f.CSRFToken},
	}).requireRedirectToFlow(t, loginScreen)

	step := b.readFlow(t, f.ID)
	held := b.postForm(t, "/self-service/login/code?flow="+f.ID, url.Values{
		"code":       {h.latestCode(t, phone)},
		"csrf_token": {step.CSRFToken},
	})
	if got := held.requireRedirectToFlow(t, loginScreen); got != f.ID {
		t.Fatalf("the second factor is owed on flow %s, but the browser went to %s", f.ID, got)
	}
	if held.cookie(sessionCookieName) != nil {
		t.Fatal("no session may be issued while a second factor is owed")
	}
	mfa := b.readFlow(t, f.ID)
	if mfa.State != flow.StateMFARequired {
		t.Fatalf("state = %q, want %q", mfa.State, flow.StateMFARequired)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	done := b.postForm(t, "/self-service/login/totp?flow="+f.ID, url.Values{
		"code":       {code},
		"csrf_token": {mfa.CSRFToken},
	})
	done.requireRedirect(t, defaultReturn)
	if done.cookie(sessionCookieName) == nil {
		t.Error("proving the second factor should issue the session")
	}
}

// TestCodeRegistrationHoldsSessionUnderDeferred: "deferred" may not skip
// the code, because for a passwordless Identity an unproven Address is
// no credential at all.
func TestCodeRegistrationHoldsSessionUnderDeferred(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, map[string]any{
		"first_factor": []string{"code"},
		"verification": "deferred",
		"ui":           screens(),
	})
	putPhoneSchema(t, h, tn)
	phone := testPhone(t)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/registration/browser")
	r := b.postForm(t, "/self-service/registration?flow="+f.ID, url.Values{
		"method":       {"code"},
		"traits.phone": {phone},
		"csrf_token":   {f.CSRFToken},
	})
	r.requireRedirectToFlow(t, verificationScreen)
	if r.cookie(sessionCookieName) != nil {
		t.Error("a passwordless registration may not hand out a session before the address is proven")
	}
}

// TestLoginCodeFatalFailures: the new endpoints follow ADR 0006 like
// every other submit step.
func TestLoginCodeFatalFailures(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, codeTenant())
	putPhoneSchema(t, h, tn)
	phone := testPhone(t)
	registerByCode(t, h, h.browser(t, tn), phone)
	b := h.browser(t, tn)

	t.Run("a bad CSRF token is fatal", func(t *testing.T) {
		f := b.createFlow(t, "/self-service/login/browser")
		r := b.postForm(t, "/self-service/login/code/send?flow="+f.ID, url.Values{
			"identifier": {phone},
			"csrf_token": {"forged"},
		})
		r.requireRedirect(t, errorScreen+"?code="+errCodeCSRF)
	})

	t.Run("an expired or unknown flow goes to the error screen", func(t *testing.T) {
		const unknown = "?flow=00000000-0000-0000-0000-000000000000"
		for path, form := range map[string]url.Values{
			"/self-service/login/code/send": {"identifier": {phone}},
			"/self-service/login/code":      {"code": {"000000"}},
		} {
			b.postForm(t, path+unknown, form).
				requireRedirect(t, errorScreen+"?code="+errCodeFlowExpired)
		}
	})

	t.Run("a JSON client gets JSON, not a redirect", func(t *testing.T) {
		f := b.createFlow(t, "/self-service/login/browser")
		r := b.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
			"code":       "000000",
			"csrf_token": f.CSRFToken,
		})
		r.requireStatus(t, http.StatusUnauthorized)
	})
}

// TestSecondFactorCodeCannotOpenASession is the guard on the shared
// One-Time Code slot: a login flow held at its second factor carries a
// code too, and feeding that code to the first-factor endpoint would
// skip the factor it was sent for.
func TestSecondFactorCodeCannotOpenASession(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, map[string]any{
		"first_factor": []string{"password", "code"},
		"verification": "deferred",
		"ui":           screens(),
	})
	email := testEmail(t)

	enrolled := h.browser(t, tn)
	registerIdentityWith(t, enrolled, email)
	enrollSMSFactor(t, h, enrolled, testPhone(t))

	b := h.browser(t, tn).withIP(nextTestIP())
	f := b.createFlow(t, "/self-service/login/browser")
	b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
		"method":     {"password"},
		"identifier": {email},
		"password":   {testPassword},
		"csrf_token": {f.CSRFToken},
	}).requireRedirectToFlow(t, loginScreen)

	step := b.readFlow(t, f.ID)
	b.postForm(t, "/self-service/login/sms/send?flow="+f.ID, url.Values{
		"csrf_token": {step.CSRFToken},
	}).requireRedirectToFlow(t, loginScreen)

	// The second-factor code is live on this flow. Spend it on the
	// first-factor endpoint instead.
	r := b.postJSON(t, "/self-service/login/code?flow="+f.ID, map[string]any{
		"code":       h.latestCode(t, smsFactorPhone(t, h, tn.ID, email)),
		"csrf_token": step.CSRFToken,
	})
	if r.cookie(sessionCookieName) != nil || r.Status == http.StatusOK {
		t.Fatalf("a second-factor code opened a session through the first-factor endpoint: %d %s",
			r.Status, r.Body)
	}
}

// TestAdminUpdatesTenantPolicy: an operator can turn the passwordless
// first factor on for a tenant that already exists, without resending
// (or losing) the rest of its policy.
func TestAdminUpdatesTenantPolicy(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())

	type tenantBody struct {
		Name   string        `json:"name"`
		Config tenant.Config `json:"config"`
	}
	read := func(t *testing.T) tenantBody {
		t.Helper()
		r := h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug, nil)
		r.requireStatus(t, http.StatusOK)
		var got tenantBody
		r.decode(t, &got)
		return got
	}
	before := read(t)
	// testEmail builds from t.Name(), which is too long for an address
	// once nested in a subtest.
	email := testEmail(t)

	patch := h.adminRequest(t, http.MethodPatch, "/admin/tenants/"+tn.Slug, map[string]any{
		"first_factor": []string{"password", "code"},
	})
	patch.requireStatus(t, http.StatusOK)

	after := read(t)
	if strings.Join(after.Config.FirstFactor, ",") != "password,code" {
		t.Fatalf("first_factor = %v, want the patched pair", after.Config.FirstFactor)
	}
	if after.Config.UI.LoginURL != before.Config.UI.LoginURL || after.Name != before.Name {
		t.Errorf("the patch disturbed untouched policy: %+v became %+v", before, after)
	}
	if after.Config.Verification != before.Config.Verification {
		t.Errorf("verification = %q, want the untouched %q",
			after.Config.Verification, before.Config.Verification)
	}

	t.Run("the change reaches live traffic", func(t *testing.T) {
		registerIdentityWith(t, h.browser(t, tn), email)
		h.clearSendCooldown(t, tn.ID, email)

		b := h.browser(t, tn).withIP(nextTestIP())
		f := b.createFlow(t, "/self-service/login/browser")
		if strings.Join(f.UI.Methods, ",") != "password,code" {
			t.Fatalf("ui.methods = %v, want the patched first factors", f.UI.Methods)
		}
		done := loginByCode(t, h, b, email)
		done.requireRedirect(t, defaultReturn)
	})

	t.Run("a rejected patch changes nothing", func(t *testing.T) {
		r := h.adminRequest(t, http.MethodPatch, "/admin/tenants/"+tn.Slug, map[string]any{
			"first_factor": []string{"password", "magic-link"},
		})
		r.requireStatus(t, http.StatusBadRequest)
		if got := read(t).Config.FirstFactor; strings.Join(got, ",") != "password,code" {
			t.Errorf("first_factor = %v, want the patch to have been refused whole", got)
		}
	})

	t.Run("an unknown tenant is a 404", func(t *testing.T) {
		h.adminRequest(t, http.MethodPatch, "/admin/tenants/no-such-tenant", map[string]any{
			"mfa": "required",
		}).requireStatus(t, http.StatusNotFound)
	})

	t.Run("an empty patch is a no-op, not a wipe", func(t *testing.T) {
		h.adminRequest(t, http.MethodPatch, "/admin/tenants/"+tn.Slug,
			map[string]any{}).requireStatus(t, http.StatusOK)
		if got := read(t); got.Config.UI.LoginURL != before.Config.UI.LoginURL ||
			strings.Join(got.Config.FirstFactor, ",") != "password,code" {
			t.Errorf("an empty patch changed the policy: %+v", got.Config)
		}
	})
}

// enrollSMSFactor takes a signed-in browser through SMS second-factor
// enrolment.
func enrollSMSFactor(t *testing.T, h *harness, b *browser, phone string) {
	t.Helper()
	who := b.getJSON(t, "/sessions/whoami")
	who.requireStatus(t, http.StatusOK)
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	who.decode(t, &session)
	csrfHeader := map[string]string{"X-CSRF-Token": session.CSRFToken}

	start := b.postJSON(t, "/self-service/mfa/sms/enroll", map[string]any{"phone": phone}, csrfHeader)
	start.requireStatus(t, http.StatusOK)
	var enrolment struct {
		FlowID    string `json:"flow_id"`
		CSRFToken string `json:"csrf_token"`
	}
	start.decode(t, &enrolment)

	confirm := b.postJSON(t, "/self-service/mfa/sms/confirm?flow="+enrolment.FlowID, map[string]any{
		"code":       h.latestCode(t, phone),
		"csrf_token": enrolment.CSRFToken,
	}, csrfHeader)
	confirm.requireStatus(t, http.StatusOK)
	h.clearSendCooldown(t, b.tenant.ID, phone)
}

// smsFactorPhone reads back the phone an identity enrolled, which is
// where its second-factor codes go.
func smsFactorPhone(t *testing.T, h *harness, tenantID, identifier string) string {
	t.Helper()
	var phone string
	err := h.pool.QueryRow(context.Background(),
		`SELECT recipient FROM courier_messages
		  WHERE tenant_id = $1 AND template = 'mfa_code'
		  ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&phone)
	if err != nil {
		t.Fatalf("no second-factor code was delivered for %s: %v", identifier, err)
	}
	return phone
}
