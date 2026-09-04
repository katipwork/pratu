package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/tenant"
)

// The Browser Flow contract, end to end (ADR 0006): HTML clients are
// driven by redirects to the tenant's screens, JSON clients keep the
// unchanged contract, and API flows never redirect.

// screens is the ui config block a test tenant gets when it has screens
// of its own.
func screens() map[string]any {
	return map[string]any{
		"login_url":          "https://app.example.com/login",
		"registration_url":   "https://app.example.com/signup",
		"recovery_url":       "https://app.example.com/recover",
		"verification_url":   "https://app.example.com/verify",
		"error_url":          "https://app.example.com/oops",
		"default_return_url": "https://app.example.com/home",
	}
}

const (
	loginScreen        = "https://app.example.com/login"
	registrationScreen = "https://app.example.com/signup"
	recoveryScreen     = "https://app.example.com/recover"
	verificationScreen = "https://app.example.com/verify"
	errorScreen        = "https://app.example.com/oops"
	defaultReturn      = "https://app.example.com/home"
)

// deferredVerification lets a test reach a session without proving an
// address first.
func deferredTenant() map[string]any {
	return map[string]any{"verification": "deferred", "ui": screens()}
}

func testEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d@example.test", strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name())), time.Now().UnixNano())
}

// TestBrowserFlowNegotiation: the same endpoint answers a browser with a
// screen and a JSON client with a flow.
func TestBrowserFlowNegotiation(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	b := h.browser(t, tn)

	t.Run("HTML client lands on the tenant's screen", func(t *testing.T) {
		r := b.getHTML(t, "/self-service/login/browser")
		r.requireRedirectToFlow(t, loginScreen)
		if r.cookie(csrfCookieName) == nil {
			t.Error("the redirect should still set the CSRF cookie the flow is bound to")
		}
	})

	t.Run("JSON client gets the flow", func(t *testing.T) {
		r := b.getJSON(t, "/self-service/login/browser")
		r.requireStatus(t, http.StatusOK)
		var f flowResponse
		r.decode(t, &f)
		if f.ID == "" || f.CSRFToken == "" {
			t.Errorf("expected a flow with a CSRF token, got %+v", f)
		}
	})

	t.Run("fetch default (*/*) keeps JSON", func(t *testing.T) {
		r := b.do(t, http.MethodGet, "/self-service/login/browser", acceptAny, "", nil, nil)
		r.requireStatus(t, http.StatusOK)
	})

	t.Run("API flows never redirect", func(t *testing.T) {
		r := b.do(t, http.MethodPost, "/self-service/login/api", acceptHTML, "", nil, nil)
		r.requireStatus(t, http.StatusOK)
	})
}

// TestFormPostJourney: a plain HTML form drives registration and login
// from end to end, landing on the tenant's return URL with a session.
func TestFormPostJourney(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	email := testEmail(t)

	reg := h.browser(t, tn)
	regFlow := reg.createFlow(t, "/self-service/registration/browser")
	r := reg.postForm(t, "/self-service/registration?flow="+regFlow.ID, url.Values{
		"method":       {"password"},
		"traits.email": {email},
		"password":     {testPassword},
		"csrf_token":   {regFlow.CSRFToken},
	})
	r.requireRedirect(t, defaultReturn)
	if r.cookie(sessionCookieName) == nil {
		t.Fatal("registration should set the session cookie")
	}

	login := h.browser(t, tn)
	loginFlow := login.createFlow(t, "/self-service/login/browser")
	r = login.postForm(t, "/self-service/login?flow="+loginFlow.ID, url.Values{
		"method":     {"password"},
		"identifier": {email},
		"password":   {testPassword},
		"csrf_token": {loginFlow.CSRFToken},
	})
	r.requireRedirect(t, defaultReturn)
	if r.cookie(sessionCookieName) == nil {
		t.Fatal("login should set the session cookie")
	}
}

// TestSubmissionErrorPersistsOnFlow is the regression test for the write
// that has to outlive its own rollback: a failed submission rolls its
// transaction back, so the message it left behind must be written in a
// transaction of its own — otherwise the screen has nothing to render.
func TestSubmissionErrorPersistsOnFlow(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	email := testEmail(t)
	registerIdentity(t, h, tn, email)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/login/browser")

	r := b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
		"method":     {"password"},
		"identifier": {email},
		"password":   {"wrong-" + testPassword},
		"csrf_token": {f.CSRFToken},
	})
	if got := r.requireRedirectToFlow(t, loginScreen); got != f.ID {
		t.Fatalf("failure returned to flow %s, want the same flow %s", got, f.ID)
	}

	reread := b.readFlow(t, f.ID)
	if msg := firstMessage(t, reread); msg != "invalid credentials" {
		t.Errorf("flow message = %q, want %q", msg, "invalid credentials")
	}
	if reread.State != flow.StateChooseMethod {
		t.Errorf("state = %q, want the flow to stay on %q", reread.State, flow.StateChooseMethod)
	}

	// The flow survives its failure: the same one completes with the
	// right password.
	r = b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
		"method":     {"password"},
		"identifier": {email},
		"password":   {testPassword},
		"csrf_token": {reread.CSRFToken},
	})
	r.requireRedirect(t, defaultReturn)
}

// TestJSONClientContractUnchanged: the same failure a browser is
// redirected for still answers a JSON client with its status and body.
func TestJSONClientContractUnchanged(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	email := testEmail(t)
	registerIdentity(t, h, tn, email)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/login/browser")
	r := b.postJSON(t, "/self-service/login?flow="+f.ID, map[string]any{
		"method":     "password",
		"identifier": email,
		"password":   "wrong-" + testPassword,
		"csrf_token": f.CSRFToken,
	})
	r.requireStatus(t, http.StatusUnauthorized)
	if msg := r.errorMessage(t); msg != "invalid credentials" {
		t.Errorf("error message = %q, want %q", msg, "invalid credentials")
	}
}

// TestFlowReadRequiresCreatingBrowser: a flow id travels in URLs and
// logs, so holding one must not be enough to read the flow.
func TestFlowReadRequiresCreatingBrowser(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())

	owner := h.browser(t, tn)
	f := owner.createFlow(t, "/self-service/login/browser")

	if got := owner.readFlow(t, f.ID); got.ID != f.ID {
		t.Fatalf("the creating browser should read its own flow, got %+v", got)
	}

	stranger := h.browser(t, tn) // its own cookie jar: a different browser
	stranger.getJSON(t, "/self-service/flows/"+f.ID).requireStatus(t, http.StatusNotFound)

	// API flows hold their state client-side and prove nothing with a
	// cookie; they are not exposed here at all.
	var apiFlow flowResponse
	r := owner.do(t, http.MethodPost, "/self-service/login/api", acceptJSON, "", nil, nil)
	r.decode(t, &apiFlow)
	owner.getJSON(t, "/self-service/flows/"+apiFlow.ID).requireStatus(t, http.StatusNotFound)
}

// TestReturnToAllowList: return_to decides where a completed flow sends
// the browser, so it is an open redirect unless it is checked.
func TestReturnToAllowList(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	b := h.browser(t, tn)

	rejected := []string{
		"https://evil.example.com/",
		"//evil.example.com",
		"javascript:alert(1)",
	}
	for _, raw := range rejected {
		t.Run("rejects "+raw, func(t *testing.T) {
			r := b.getJSON(t, "/self-service/login/browser?return_to="+url.QueryEscape(raw))
			r.requireStatus(t, http.StatusBadRequest)
		})
	}

	accepted := []string{
		"/dashboard",                      // same origin as the tenant
		"https://app.example.com/welcome", // origin of a configured screen
	}
	for _, raw := range accepted {
		t.Run("accepts "+raw, func(t *testing.T) {
			r := b.getJSON(t, "/self-service/login/browser?return_to="+url.QueryEscape(raw))
			r.requireStatus(t, http.StatusOK)
		})
	}

	t.Run("honoured on success", func(t *testing.T) {
		email := testEmail(t)
		registerIdentity(t, h, tn, email)
		lb := h.browser(t, tn)
		f := lb.createFlow(t, "/self-service/login/browser?return_to=%2Fdashboard")
		r := lb.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
			"method":     {"password"},
			"identifier": {email},
			"password":   {testPassword},
			"csrf_token": {f.CSRFToken},
		})
		r.requireRedirect(t, "/dashboard")
	})
}

// TestFatalFailuresGoToErrorScreen: failures with no flow left to return
// to name themselves on the error screen instead of dead-ending.
func TestFatalFailuresGoToErrorScreen(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	b := h.browser(t, tn)

	t.Run("expired or unknown flow", func(t *testing.T) {
		r := b.postForm(t, "/self-service/login?flow=00000000-0000-0000-0000-000000000000", url.Values{
			"method":     {"password"},
			"identifier": {"nobody@example.test"},
			"password":   {testPassword},
		})
		r.requireRedirect(t, errorScreen+"?code="+errCodeFlowExpired)
	})

	t.Run("csrf violation", func(t *testing.T) {
		f := b.createFlow(t, "/self-service/login/browser")
		r := b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
			"method":     {"password"},
			"identifier": {"nobody@example.test"},
			"password":   {testPassword},
			"csrf_token": {"not-the-token"},
		})
		r.requireRedirect(t, errorScreen+"?code="+errCodeCSRF)
	})

	t.Run("JSON clients keep their statuses", func(t *testing.T) {
		r := b.postJSON(t, "/self-service/login?flow=00000000-0000-0000-0000-000000000000", map[string]any{
			"method": "password", "identifier": "nobody@example.test", "password": testPassword,
		})
		r.requireStatus(t, http.StatusBadRequest)

		f := b.createFlow(t, "/self-service/login/browser")
		r = b.postJSON(t, "/self-service/login?flow="+f.ID, map[string]any{
			"method": "password", "identifier": "nobody@example.test",
			"password": testPassword, "csrf_token": "not-the-token",
		})
		r.requireStatus(t, http.StatusForbidden)
	})
}

// TestRateLimitedRedirect: a blocked request has no flow to go back to
// either, so a browser is told so on the error screen.
func TestRateLimitedRedirect(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	// Its own IP: this test deliberately spends a whole budget.
	b := h.browser(t, tn).withIP(nextTestIP())
	identifier := testEmail(t)

	f := b.createFlow(t, "/self-service/login/browser")
	submit := func() *resp {
		return b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
			"method":     {"password"},
			"identifier": {identifier},
			"password":   {testPassword},
			"csrf_token": {f.CSRFToken},
		})
	}

	// The tenant configures no throttle, so the default budget applies:
	// that many attempts pass (each a plain failure), the next is refused
	// outright.
	for i := 0; i < tenant.DefaultLoginMaxAttempts; i++ {
		if r := submit(); r.Location == errorScreen+"?code="+errCodeRateLimited {
			t.Fatalf("attempt %d was rate limited before the budget was spent", i+1)
		}
	}
	submit().requireRedirect(t, errorScreen+"?code="+errCodeRateLimited)

	// A JSON client over the same budget still gets 429 and Retry-After.
	r := b.postJSON(t, "/self-service/login?flow="+f.ID, map[string]any{
		"method": "password", "identifier": identifier,
		"password": testPassword, "csrf_token": f.CSRFToken,
	})
	r.requireStatus(t, http.StatusTooManyRequests)
	if r.Header.Get("Retry-After") == "" {
		t.Error("a rate-limited JSON response should say when to retry")
	}
}

// TestVerificationHeldState: registration under the default policy hands
// the browser to the verification screen, and the flow there knows which
// step it waits on.
func TestVerificationHeldState(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, map[string]any{"ui": screens()}) // verification required by default
	email := testEmail(t)
	b := h.browser(t, tn)

	regFlow := b.createFlow(t, "/self-service/registration/browser")
	r := b.postForm(t, "/self-service/registration?flow="+regFlow.ID, url.Values{
		"method":       {"password"},
		"traits.email": {email},
		"password":     {testPassword},
		"csrf_token":   {regFlow.CSRFToken},
	})
	verifyID := r.requireRedirectToFlow(t, verificationScreen)
	if r.cookie(sessionCookieName) != nil {
		t.Error("no session may be issued before the address is proven")
	}

	held := b.readFlow(t, verifyID)
	if held.Kind != flow.KindVerification || held.State != flow.StateCodeRequired {
		t.Fatalf("flow = %s/%s, want verification/%s", held.Kind, held.State, flow.StateCodeRequired)
	}

	wrong := b.postForm(t, "/self-service/verification?flow="+verifyID, url.Values{
		"code":       {"000000"},
		"csrf_token": {held.CSRFToken},
	})
	wrong.requireRedirectToFlow(t, verificationScreen)
	if msg := firstMessage(t, b.readFlow(t, verifyID)); msg != "incorrect code" {
		t.Errorf("flow message = %q, want %q", msg, "incorrect code")
	}

	code := h.latestCode(t, email)
	done := b.postForm(t, "/self-service/verification?flow="+verifyID, url.Values{
		"code":       {code},
		"csrf_token": {b.readFlow(t, verifyID).CSRFToken},
	})
	done.requireRedirect(t, defaultReturn)
	if done.cookie(sessionCookieName) == nil {
		t.Error("proving the address should issue the session it held back")
	}
}

// TestMFAHeldState: a login that still owes a second factor stays on its
// own flow, and the login screen reads the step back off it.
func TestMFAHeldState(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	email := testEmail(t)

	// Enrol a TOTP factor through the API an authenticated identity uses.
	enrolled := h.browser(t, tn)
	registerIdentityWith(t, enrolled, email)
	secret := enrollTOTP(t, enrolled)

	// A fresh browser signs in from scratch.
	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/login/browser")
	r := b.postForm(t, "/self-service/login?flow="+f.ID, url.Values{
		"method":     {"password"},
		"identifier": {email},
		"password":   {testPassword},
		"csrf_token": {f.CSRFToken},
	})
	if got := r.requireRedirectToFlow(t, loginScreen); got != f.ID {
		t.Fatalf("the second factor is owed on flow %s, but the browser went to %s", f.ID, got)
	}
	if r.cookie(sessionCookieName) != nil {
		t.Error("no session may be issued while a second factor is owed")
	}

	held := b.readFlow(t, f.ID)
	if held.State != flow.StateMFARequired {
		t.Fatalf("state = %q, want %q", held.State, flow.StateMFARequired)
	}
	if len(held.UI.Methods) != 1 || held.UI.Methods[0] != "totp" {
		t.Fatalf("methods = %v, want [totp]", held.UI.Methods)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	done := b.postForm(t, "/self-service/login/totp?flow="+f.ID, url.Values{
		"code":       {code},
		"csrf_token": {held.CSRFToken},
	})
	done.requireRedirect(t, defaultReturn)
	if done.cookie(sessionCookieName) == nil {
		t.Error("proving the second factor should issue the session")
	}
}

// TestRecoveryChain: every step of Recovery moves the flow forward and
// returns the browser to the recovery screen, which renders the step.
func TestRecoveryChain(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	email := testEmail(t)
	registerIdentity(t, h, tn, email)
	// Registration already spent this address's delivery budget on its
	// verification code; recovery is not what the cooldown is guarding.
	h.clearSendCooldown(t, tn.ID, email)

	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/recovery/browser")

	r := b.postForm(t, "/self-service/recovery?flow="+f.ID, url.Values{
		"address":    {email},
		"csrf_token": {f.CSRFToken},
	})
	r.requireRedirectToFlow(t, recoveryScreen)
	step := b.readFlow(t, f.ID)
	if step.State != flow.StateCodeRequired {
		t.Fatalf("state = %q, want %q", step.State, flow.StateCodeRequired)
	}

	code := h.latestCode(t, email)
	r = b.postForm(t, "/self-service/recovery/code?flow="+f.ID, url.Values{
		"code":       {code},
		"csrf_token": {step.CSRFToken},
	})
	r.requireRedirectToFlow(t, recoveryScreen)
	step = b.readFlow(t, f.ID)
	if step.State != flow.StatePasswordRequired {
		t.Fatalf("state = %q, want %q", step.State, flow.StatePasswordRequired)
	}

	newPassword := "recovered-" + testPassword
	r = b.postForm(t, "/self-service/recovery/password?flow="+f.ID, url.Values{
		"password":   {newPassword},
		"csrf_token": {step.CSRFToken},
	})
	r.requireRedirect(t, defaultReturn)
	if r.cookie(sessionCookieName) == nil {
		t.Error("a completed recovery should issue a session")
	}
}

// TestRecoveryIsIndistinguishable: an address that does not exist must
// move the flow exactly as far as one that does.
func TestRecoveryIsIndistinguishable(t *testing.T) {
	h := newHarness(t, false)
	tn := h.createTenant(t, deferredTenant())
	b := h.browser(t, tn)
	f := b.createFlow(t, "/self-service/recovery/browser")

	r := b.postForm(t, "/self-service/recovery?flow="+f.ID, url.Values{
		"address":    {"stranger-" + testEmail(t)},
		"csrf_token": {f.CSRFToken},
	})
	r.requireRedirectToFlow(t, recoveryScreen)
	step := b.readFlow(t, f.ID)
	if step.State != flow.StateCodeRequired {
		t.Errorf("state = %q, want %q even for an unknown address", step.State, flow.StateCodeRequired)
	}
	if msg := firstMessage(t, step); !strings.Contains(msg, "if the address exists") {
		t.Errorf("message = %q, want the same answer a known address gets", msg)
	}
}

// TestLegacyScreenConfig: tenants configured before the ui block keep
// working, and OAuth2 challenges follow the same screen resolution.
func TestLegacyScreenConfig(t *testing.T) {
	h := newHarness(t, false)
	const legacyScreen = "https://legacy.example.com/signin"
	tn := h.createTenant(t, map[string]any{
		"verification": "deferred",
		"login_url":    legacyScreen,
	})
	b := h.browser(t, tn)

	t.Run("browser flows use the deprecated login_url", func(t *testing.T) {
		r := b.getHTML(t, "/self-service/login/browser")
		r.requireRedirectToFlow(t, legacyScreen)
	})

	t.Run("OAuth2 challenges use it too", func(t *testing.T) {
		challengeRedirect(t, h, tn, b, legacyScreen)
	})

	t.Run("the ui block wins when both are set", func(t *testing.T) {
		both := h.createTenant(t, map[string]any{
			"verification": "deferred",
			"login_url":    legacyScreen,
			"ui":           map[string]any{"login_url": loginScreen},
		})
		bb := h.browser(t, both)
		bb.getHTML(t, "/self-service/login/browser").requireRedirectToFlow(t, loginScreen)
		challengeRedirect(t, h, both, bb, loginScreen)
	})
}

// challengeRedirect drives an authorization request and asserts which
// screen the Login Challenge was handed to.
func challengeRedirect(t *testing.T, h *harness, tn *testTenant, b *browser, screen string) {
	t.Helper()
	r := h.adminRequest(t, http.MethodPost, "/admin/tenants/"+tn.Slug+"/clients", map[string]any{
		"name":          "Test client",
		"redirect_uris": []string{"https://client.example.com/cb"},
		"public":        true,
	})
	if r.Status != http.StatusCreated {
		t.Fatalf("create client: status %d body %s", r.Status, r.Body)
	}
	var created struct {
		Client struct {
			ID string `json:"client_id"`
		} `json:"client"`
	}
	r.decode(t, &created)

	q := url.Values{
		"client_id":     {created.Client.ID},
		"response_type": {"code"},
		"redirect_uri":  {"https://client.example.com/cb"},
		"scope":         {"openid"},
		"state":         {"integration-state"},
	}
	auth := b.getHTML(t, "/oauth2/auth?"+q.Encode())
	if auth.Status != http.StatusFound {
		t.Fatalf("authorize: status %d body %s", auth.Status, auth.Body)
	}
	u, err := url.Parse(auth.Location)
	if err != nil {
		t.Fatal(err)
	}
	if got := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String(); got != screen {
		t.Errorf("challenge went to %q, want %q", got, screen)
	}
	if u.Query().Get("login_challenge") == "" {
		t.Errorf("challenge redirect %q carries no login_challenge", auth.Location)
	}
}

// TestReferenceUIFallback: a tenant with no screens of its own still gets
// redirect-driven flows when the server serves the reference UI, and
// keeps the old JSON behaviour when it does not.
func TestReferenceUIFallback(t *testing.T) {
	t.Run("reference UI served", func(t *testing.T) {
		h := newHarness(t, true)
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)
		r := b.getHTML(t, "/self-service/login/browser")
		r.requireRedirectToFlow(t, referenceUIScreen)
		b.getHTML(t, referenceUIScreen).requireStatus(t, http.StatusOK)
	})

	t.Run("headless server", func(t *testing.T) {
		h := newHarness(t, false)
		tn := h.createTenant(t, map[string]any{"verification": "deferred"})
		b := h.browser(t, tn)
		// Nowhere to send the browser: the JSON flow is still the answer.
		b.getHTML(t, "/self-service/login/browser").requireStatus(t, http.StatusOK)
	})
}

// TestAdminUIConfig: the screens are configured through the admin API, so
// it validates them.
func TestAdminUIConfig(t *testing.T) {
	h := newHarness(t, false)

	t.Run("relative screen URLs are refused", func(t *testing.T) {
		r := h.adminRequest(t, http.MethodPost, "/admin/tenants", map[string]any{
			"slug": fmt.Sprintf("it-bad-%d", time.Now().UnixNano()%1_000_000),
			"name": "Bad screens",
			"ui":   map[string]any{"login_url": "/login"},
		})
		r.requireStatus(t, http.StatusBadRequest)
	})

	t.Run("the block round-trips", func(t *testing.T) {
		tn := h.createTenant(t, map[string]any{
			"ui": map[string]any{
				"login_url":           loginScreen,
				"allowed_return_urls": []string{"https://dash.example.com/app"},
			},
		})
		r := h.adminRequest(t, http.MethodGet, "/admin/tenants/"+tn.Slug, nil)
		r.requireStatus(t, http.StatusOK)
		var got struct {
			Config struct {
				UI struct {
					LoginURL          string   `json:"login_url"`
					AllowedReturnURLs []string `json:"allowed_return_urls"`
				} `json:"ui"`
			} `json:"config"`
		}
		r.decode(t, &got)
		if got.Config.UI.LoginURL != loginScreen {
			t.Errorf("login_url = %q, want %q", got.Config.UI.LoginURL, loginScreen)
		}
		if len(got.Config.UI.AllowedReturnURLs) != 1 {
			t.Errorf("allowed_return_urls = %v, want one entry", got.Config.UI.AllowedReturnURLs)
		}
	})
}

// --- fixtures ---------------------------------------------------------

// registerIdentity creates an Identity with a session-issuing tenant
// (verification deferred), using its own browser so the caller's cookie
// jar stays anonymous.
func registerIdentity(t *testing.T, h *harness, tn *testTenant, email string) {
	t.Helper()
	registerIdentityWith(t, h.browser(t, tn), email)
}

func registerIdentityWith(t *testing.T, b *browser, email string) {
	t.Helper()
	f := b.createFlow(t, "/self-service/registration/browser")
	r := b.postJSON(t, "/self-service/registration?flow="+f.ID, map[string]any{
		"method":     "password",
		"traits":     map[string]any{"email": email},
		"password":   testPassword,
		"csrf_token": f.CSRFToken,
	})
	if r.Status != http.StatusOK {
		t.Fatalf("register %s: status %d body %s", email, r.Status, r.Body)
	}
}

// enrollTOTP takes a signed-in browser through second-factor enrolment
// and returns the secret, so the test can produce codes from it.
func enrollTOTP(t *testing.T, b *browser) string {
	t.Helper()
	who := b.getJSON(t, "/sessions/whoami")
	who.requireStatus(t, http.StatusOK)
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	who.decode(t, &session)
	csrfHeader := map[string]string{"X-CSRF-Token": session.CSRFToken}

	start := b.postJSON(t, "/self-service/mfa/totp/enroll", map[string]any{}, csrfHeader)
	start.requireStatus(t, http.StatusOK)
	var enrolment struct {
		FlowID    string `json:"flow_id"`
		Secret    string `json:"secret"`
		CSRFToken string `json:"csrf_token"`
	}
	start.decode(t, &enrolment)

	code, err := totp.GenerateCode(enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirm := b.postJSON(t, "/self-service/mfa/totp/confirm?flow="+enrolment.FlowID, map[string]any{
		"code":       code,
		"csrf_token": enrolment.CSRFToken,
	}, csrfHeader)
	confirm.requireStatus(t, http.StatusOK)
	return enrolment.Secret
}
