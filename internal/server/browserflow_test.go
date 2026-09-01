package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/tenant"
)

func acceptReq(accept, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/self-service/login?flow=x", strings.NewReader(""))
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestWantsHTML(t *testing.T) {
	cases := []struct {
		name        string
		accept      string
		contentType string
		want        bool
	}{
		{"browser navigation", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "", true},
		{"fetch default", "*/*", "", false},
		{"explicit json", "application/json", "", false},
		{"no accept header", "", "", false},
		{"form post without accept", "", "application/x-www-form-urlencoded", true},
		{"form post with charset", "", "application/x-www-form-urlencoded; charset=utf-8", true},
		{"json body", "*/*", "application/json", false},
		{"html outranked by json", "text/html;q=0.5,application/json;q=0.9", "", false},
		{"html ranked above json", "application/json;q=0.5,text/html;q=0.9", "", true},
		{"html and json equal", "text/html,application/json", "", true},
	}
	for _, c := range cases {
		if got := wantsHTML(acceptReq(c.accept, c.contentType)); got != c.want {
			t.Errorf("%s: wantsHTML = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidateReturnTo(t *testing.T) {
	tn := &tenant.Tenant{Config: tenant.Config{UI: tenant.UIConfig{
		LoginURL:          "https://app.example.com/login",
		AllowedReturnURLs: []string{"https://dash.example.com/app"},
	}}}
	r := httptest.NewRequest(http.MethodGet, "/self-service/login/browser", nil)
	r.Host = "acme.pratu.test"

	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty is fine", "", true},
		{"root-relative path", "/dashboard", true},
		{"protocol-relative is an open redirect", "//evil.example.com", false},
		{"same origin as the request", "https://acme.pratu.test/done", true},
		{"origin of a configured screen", "https://app.example.com/welcome", true},
		{"allow-listed prefix", "https://dash.example.com/app/home", true},
		{"allow-listed host, other path", "https://dash.example.com/elsewhere", false},
		{"unrelated origin", "https://evil.example.com/", false},
		{"lookalike host", "https://app.example.com.evil.com/", false},
		{"javascript scheme", "javascript:alert(1)", false},
	}
	for _, c := range cases {
		got, ok := validateReturnTo(tn, r, c.raw)
		if ok != c.want {
			t.Errorf("%s: validateReturnTo(%q) ok = %v, want %v", c.name, c.raw, ok, c.want)
		}
		if ok && c.raw != "" && got != c.raw {
			t.Errorf("%s: validateReturnTo(%q) = %q, want it unchanged", c.name, c.raw, got)
		}
	}
}

func TestScreenURLFallbacks(t *testing.T) {
	legacy := &tenant.Tenant{Config: tenant.Config{
		LoginURL:        "https://legacy.example.com/login",
		SocialReturnURL: "https://legacy.example.com/after",
	}}
	if got := legacy.Config.EffectiveLoginUIURL(); got != "https://legacy.example.com/login" {
		t.Errorf("deprecated login_url should still resolve, got %q", got)
	}
	if got := legacy.Config.EffectiveDefaultReturnURL(); got != "https://legacy.example.com/after" {
		t.Errorf("deprecated social_return_url should back the default return, got %q", got)
	}

	both := &tenant.Tenant{Config: tenant.Config{
		LoginURL: "https://legacy.example.com/login",
		UI:       tenant.UIConfig{LoginURL: "https://new.example.com/login"},
	}}
	if got := both.Config.EffectiveLoginUIURL(); got != "https://new.example.com/login" {
		t.Errorf("ui.login_url should win over the deprecated field, got %q", got)
	}

	// A tenant with no screens of its own falls back to the reference UI
	// only when the server serves it.
	bare := &tenant.Tenant{}
	withUI := &publicAPI{referenceUI: true}
	headless := &publicAPI{}
	if got := withUI.screenURL(bare, flow.KindLogin); got != referenceUIScreen {
		t.Errorf("reference UI should back an unconfigured tenant, got %q", got)
	}
	if got := headless.screenURL(bare, flow.KindLogin); got != "" {
		t.Errorf("headless server has no screen to offer, got %q", got)
	}

	// An error screen keeps the browser inside the tenant's own UI.
	ownUI := &tenant.Tenant{Config: tenant.Config{UI: tenant.UIConfig{LoginURL: "https://app.example.com/login"}}}
	if got := withUI.errorScreenURL(ownUI); got != "https://app.example.com/login" {
		t.Errorf("error screen should fall back to the tenant's login screen, got %q", got)
	}
}

func TestRedirectsOnlyForHTMLClients(t *testing.T) {
	api := &publicAPI{referenceUI: true}
	tn := &tenant.Tenant{Config: tenant.Config{UI: tenant.UIConfig{
		LoginURL: "https://app.example.com/login",
	}}}

	w := httptest.NewRecorder()
	if !api.redirectToScreen(w, acceptReq("text/html", ""), tn, flow.KindLogin, "abc") {
		t.Fatal("an HTML client should be redirected")
	}
	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "https://app.example.com/login?flow=abc" {
		t.Errorf("Location = %q, want the screen carrying the flow", loc)
	}

	w = httptest.NewRecorder()
	if api.redirectToScreen(w, acceptReq("application/json", ""), tn, flow.KindLogin, "abc") {
		t.Error("a JSON client must keep its JSON response")
	}
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Error("nothing should have been written for a JSON client")
	}
}

func TestReadFormSubmission(t *testing.T) {
	body := "method=password&password=hunter2&csrf_token=tok&traits.email=a%40b.c&traits.name.first=Ada"
	r := httptest.NewRequest(http.MethodPost, "/self-service/registration?flow=x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var got struct {
		Method    string `json:"method"`
		Password  string `json:"password"`
		CSRFToken string `json:"csrf_token"`
		Traits    struct {
			Email string `json:"email"`
			Name  struct {
				First string `json:"first"`
			} `json:"name"`
		} `json:"traits"`
	}
	if !readSubmission(httptest.NewRecorder(), r, &got) {
		t.Fatal("a form submission should decode")
	}
	if got.Method != "password" || got.Password != "hunter2" || got.CSRFToken != "tok" {
		t.Errorf("scalar fields decoded wrong: %+v", got)
	}
	if got.Traits.Email != "a@b.c" || got.Traits.Name.First != "Ada" {
		t.Errorf("dotted names should nest into traits: %+v", got.Traits)
	}
}

func TestReadJSONSubmissionUnchanged(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/self-service/login?flow=x",
		strings.NewReader(`{"method":"password","identifier":"a@b.c"}`))
	r.Header.Set("Content-Type", "application/json")

	var got struct {
		Method     string `json:"method"`
		Identifier string `json:"identifier"`
	}
	if !readSubmission(httptest.NewRecorder(), r, &got) {
		t.Fatal("a JSON submission should decode")
	}
	if got.Method != "password" || got.Identifier != "a@b.c" {
		t.Errorf("decoded wrong: %+v", got)
	}
}
