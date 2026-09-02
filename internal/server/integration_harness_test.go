package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/ratelimit"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// Integration tests for the Browser Flow contract (ADR 0006). They run the
// real public and admin handlers over a real Postgres — real RLS, real
// flow rows, real CSRF cookies — and are skipped unless a database is
// pointed at:
//
//	PRATU_TEST_DATABASE_URL=postgres://pratu:pratu@localhost:35432/pratu?sslmode=disable go test ./internal/server/
//
// The role must be unprivileged (no superuser, no BYPASSRLS) or
// storage.Connect refuses it: RLS is silently inert under an elevated
// role, which would make tenant isolation untested.

const testBaseDomain = "pratu.test"

// testPassword clears the length policy; the breach checker is stubbed so
// no HIBP call happens.
const testPassword = "integration-test-password"

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	if url := os.Getenv("PRATU_TEST_DATABASE_URL"); url != "" {
		ctx := context.Background()
		pool, err := storage.Connect(ctx, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "integration tests: connect: %v\n", err)
			os.Exit(1)
		}
		if _, err := storage.Migrate(ctx, pool); err != nil {
			fmt.Fprintf(os.Stderr, "integration tests: migrate: %v\n", err)
			os.Exit(1)
		}
		testPool = pool
	}
	code := m.Run()
	if testPool != nil {
		testPool.Close()
	}
	os.Exit(code)
}

// harness is one server pair (public + admin) over the shared pool.
type harness struct {
	pool   *pgxpool.Pool
	public *httptest.Server
	admin  *httptest.Server
	ip     string
}

// newHarness assembles what cmd/pratu wires at startup, minus listeners:
// same handlers, same resolver, same limiter, a stubbed breach checker,
// and no Courier drain — One-Time Codes are read straight from the
// outbox instead.
func newHarness(t *testing.T, referenceUI bool) *harness {
	t.Helper()
	if testPool == nil {
		t.Skip("PRATU_TEST_DATABASE_URL not set")
	}

	// Per-IP limits are global counters keyed by client IP, and every
	// httptest connection arrives from loopback. Trusting loopback lets
	// each test present its own X-Forwarded-For address, so one test
	// cannot spend another's budget.
	proxies, err := ParseProxies([]string{"127.0.0.0/8", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	SetTrustedProxies(proxies)
	t.Cleanup(func() { SetTrustedProxies(nil) })

	resolver := tenant.NewResolver(testBaseDomain, storage.NewTenantStore(testPool))
	providers := oauth2.NewProviders([]byte("integration-test-system-secret-0123456789"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &harness{
		pool: testPool,
		ip:   nextTestIP(),
	}
	clearIPBudget(testPool, h.ip)
	h.public = httptest.NewServer(NewPublic(testPool, resolver, stubBreachChecker{}, ratelimit.New(testPool), providers, referenceUI, log))
	h.admin = httptest.NewServer(NewAdmin(testPool, testRootKey, testBaseDomain, providers))
	t.Cleanup(h.public.Close)
	t.Cleanup(h.admin.Close)
	return h
}

const testRootKey = "integration-test-root-key"

// stubBreachChecker keeps the password policy offline: HIBP is not part
// of what these tests exercise.
type stubBreachChecker struct{}

func (stubBreachChecker) BreachCount(context.Context, string) (int, error) { return 0, nil }

var (
	ipSeq     int64
	tenantSeq int64
)

func nextTestIP() string {
	n := atomic.AddInt64(&ipSeq, 1)
	return fmt.Sprintf("198.51.%d.%d", (n/250)%250, n%250+1)
}

// clearIPBudget hands back the endpoint budgets keyed to one client IP.
// Those counters live in the database and outlive the process, while the
// addresses here restart from the same sequence every run — so without
// this, a run inside a limit window inherits the previous run's spending,
// and a test that deliberately spends a whole budget finds it already
// spent. Called wherever an address is handed out, never mid-test: the
// spending within a test is the thing under test.
func clearIPBudget(pool *pgxpool.Pool, ip string) {
	if pool == nil {
		return
	}
	_, _ = pool.Exec(context.Background(), `DELETE FROM rate_limits WHERE key LIKE $1`, "%:"+ip)
}

// testTenant is a Tenant created for one test. Tenants are fully isolated
// identity namespaces, so tests need no cleanup between them and each one
// exercises the isolation too.
type testTenant struct {
	Slug string
	Host string
	ID   string
}

// createTenant goes through the admin API an operator would use, so the
// ui config block is validated and stored the same way in tests as in
// production.
func (h *harness) createTenant(t *testing.T, cfg map[string]any) *testTenant {
	t.Helper()
	slug := fmt.Sprintf("it-%d-%d", time.Now().UnixNano()%1_000_000, atomic.AddInt64(&tenantSeq, 1))
	body := map[string]any{"slug": slug, "name": "Integration " + slug}
	for k, v := range cfg {
		body[k] = v
	}
	r := h.adminRequest(t, http.MethodPost, "/admin/tenants", body)
	if r.Status != http.StatusCreated {
		t.Fatalf("create tenant: status %d, body %s", r.Status, r.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	r.decode(t, &created)
	return &testTenant{Slug: slug, Host: slug + "." + testBaseDomain, ID: created.ID}
}

func (h *harness) adminRequest(t *testing.T, method, path string, body any) *resp {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.admin.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testRootKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return readResp(t, res)
}

// latestCode reads a One-Time Code out of the Courier outbox. The outbox
// is the delivery boundary, so a test can take the code from it without
// running a Courier or racing its log output.
func (h *harness) latestCode(t *testing.T, recipient string) string {
	t.Helper()
	var code string
	err := h.pool.QueryRow(context.Background(),
		`SELECT payload->>'code' FROM courier_messages
		  WHERE recipient = $1 AND payload ? 'code'
		  ORDER BY created_at DESC LIMIT 1`, recipient,
	).Scan(&code)
	if err != nil {
		t.Fatalf("no One-Time Code delivered to %s: %v", recipient, err)
	}
	return code
}

// clearSendCooldown drops the per-address delivery counters. Registration
// already spends an address's cooldown on its verification code, so a
// test that then drives Recovery for the same address has to hand the
// budget back — the cooldown is not what it is testing.
func (h *harness) clearSendCooldown(t *testing.T, tenantID, value string) {
	t.Helper()
	_, err := h.pool.Exec(context.Background(),
		`DELETE FROM rate_limits WHERE key LIKE $1`, "send%:"+tenantID+":%:"+value)
	if err != nil {
		t.Fatal(err)
	}
}

// browser is one client: its own cookie jar (session + CSRF cookies) and
// its own client IP. Redirects are never followed — they are the thing
// under test. One browser drives one Tenant: the jar keys cookies by the
// httptest host, so it cannot model the host-scoped isolation two tenants
// would have in a real browser.
type browser struct {
	h      *harness
	tenant *testTenant
	hc     *http.Client
	ip     string
}

func (h *harness) browser(t *testing.T, tn *testTenant) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{
		h:      h,
		tenant: tn,
		ip:     h.ip,
		hc: &http.Client{
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// withIP gives this browser its own rate-limit budget — a full one, even
// if an earlier run already spent something against this address.
func (b *browser) withIP(ip string) *browser {
	clearIPBudget(b.h.pool, ip)
	clone := *b
	clone.ip = ip
	return &clone
}

const (
	acceptHTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	acceptJSON = "application/json"
	acceptAny  = "*/*"
)

func (b *browser) do(t *testing.T, method, path, accept, contentType string, body io.Reader, headers map[string]string) *resp {
	t.Helper()
	req, err := http.NewRequest(method, b.h.public.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	// The Host header selects the Tenant (ADR 0003).
	req.Host = b.tenant.Host
	req.Header.Set("X-Forwarded-For", b.ip)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := b.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return readResp(t, res)
}

func (b *browser) getHTML(t *testing.T, path string) *resp {
	t.Helper()
	return b.do(t, http.MethodGet, path, acceptHTML, "", nil, nil)
}

func (b *browser) getJSON(t *testing.T, path string) *resp {
	t.Helper()
	return b.do(t, http.MethodGet, path, acceptJSON, "", nil, nil)
}

// postForm submits like an HTML form: url-encoded, and an HTML client by
// construction.
func (b *browser) postForm(t *testing.T, path string, form url.Values) *resp {
	t.Helper()
	return b.do(t, http.MethodPost, path, acceptHTML, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()), nil)
}

func (b *browser) postJSON(t *testing.T, path string, body any, headers ...map[string]string) *resp {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]string
	if len(headers) > 0 {
		h = headers[0]
	}
	return b.do(t, http.MethodPost, path, acceptJSON, "application/json", bytes.NewReader(raw), h)
}

// createFlow starts a Browser Flow as a JSON client, which is how a test
// gets hold of the flow id and CSRF token before switching to HTML.
func (b *browser) createFlow(t *testing.T, path string) flowResponse {
	t.Helper()
	r := b.getJSON(t, path)
	if r.Status != http.StatusOK {
		t.Fatalf("create flow %s: status %d, body %s", path, r.Status, r.Body)
	}
	var f flowResponse
	r.decode(t, &f)
	return f
}

// readFlow is what a tenant's screen does after landing on a redirect.
func (b *browser) readFlow(t *testing.T, id string) flowResponse {
	t.Helper()
	r := b.getJSON(t, "/self-service/flows/"+id)
	if r.Status != http.StatusOK {
		t.Fatalf("read flow %s: status %d, body %s", id, r.Status, r.Body)
	}
	var f flowResponse
	r.decode(t, &f)
	return f
}

type resp struct {
	Status   int
	Location string
	Body     []byte
	Header   http.Header
	Cookies  []*http.Cookie
}

func readResp(t *testing.T, res *http.Response) *resp {
	t.Helper()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return &resp{
		Status:   res.StatusCode,
		Location: res.Header.Get("Location"),
		Body:     body,
		Header:   res.Header,
		Cookies:  res.Cookies(),
	}
}

func (r *resp) decode(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, dst); err != nil {
		t.Fatalf("decode %s: %v", r.Body, err)
	}
}

func (r *resp) cookie(name string) *http.Cookie {
	for _, c := range r.Cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// errorMessage pulls the message out of an APIError body.
func (r *resp) errorMessage(t *testing.T) string {
	t.Helper()
	var e struct {
		Error apiError `json:"error"`
	}
	r.decode(t, &e)
	return e.Error.Message
}

// --- assertions -------------------------------------------------------

func (r *resp) requireRedirect(t *testing.T, want string) {
	t.Helper()
	if r.Status != http.StatusSeeOther && r.Status != http.StatusFound {
		t.Fatalf("expected a redirect to %s, got status %d body %s", want, r.Status, r.Body)
	}
	if r.Location != want {
		t.Fatalf("Location = %q, want %q", r.Location, want)
	}
}

// requireRedirectToFlow asserts the browser was sent to a screen carrying
// a flow, and returns that flow's id.
func (r *resp) requireRedirectToFlow(t *testing.T, screen string) string {
	t.Helper()
	if r.Status != http.StatusSeeOther {
		t.Fatalf("expected 303 to %s, got status %d body %s", screen, r.Status, r.Body)
	}
	u, err := url.Parse(r.Location)
	if err != nil {
		t.Fatalf("Location %q: %v", r.Location, err)
	}
	if got := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String(); got != screen {
		t.Fatalf("redirected to %q, want screen %q", got, screen)
	}
	id := u.Query().Get("flow")
	if id == "" {
		t.Fatalf("Location %q carries no flow id", r.Location)
	}
	return id
}

func (r *resp) requireStatus(t *testing.T, want int) {
	t.Helper()
	if r.Status != want {
		t.Fatalf("status = %d, want %d (body %s)", r.Status, want, r.Body)
	}
	if want < 300 || want >= 400 {
		if r.Location != "" {
			t.Fatalf("unexpected Location %q on a %d response", r.Location, r.Status)
		}
	}
}

// firstMessage is the message a screen would render after a redirect.
func firstMessage(t *testing.T, f flowResponse) string {
	t.Helper()
	if len(f.Messages) == 0 {
		t.Fatalf("flow %s carries no messages", f.ID)
	}
	return f.Messages[0].Text
}
