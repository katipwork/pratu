package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/katipwork/pratu/internal/identity"
	"github.com/katipwork/pratu/internal/tenant"
)

// Endpoint limits (per Q24: Postgres counters, no CAPTCHA in v1). IP keys
// are global — attackers spread across tenants; identifier keys are
// per-tenant.
const (
	limitFlowCreatePerIP = 30 // per minute
	limitLoginPerIP      = 30 // per minute
	limitLoginPerID      = 5  // per minute, per identifier
	limitRegisterPerIP   = 20 // per hour
	limitVerifyPerIP     = 30 // per minute
	limitResendPerIP     = 10 // per minute
	limitRecoveryPerIP   = 10 // per minute
)

// Send caps: the SMS ones are the SMS-pumping protection — a per-address
// cooldown and daily cap, plus a per-tenant daily SMS ceiling because real
// pumping attacks rotate phone numbers.
const (
	sendCooldown       = time.Minute
	smsPerAddressDay   = 5
	emailPerAddressDay = 20
)

// errRateLimited surfaces a blocked action out of a tenant transaction;
// the transaction rolls back (keeping the flow reusable) while the
// counters, written outside it, keep the burnt attempt.
type errRateLimited struct {
	retryAfter time.Duration
}

func (errRateLimited) Error() string { return "rate limited" }

// allow enforces one endpoint limit, answering 429 (with Retry-After) when
// exceeded. Callers stop on false.
func (a *publicAPI) allow(w http.ResponseWriter, r *http.Request, key string, limit int, window time.Duration) bool {
	ok, retryAfter, err := a.limiter.Allow(r.Context(), key, limit, window)
	if err != nil {
		internalError(w, err)
		return false
	}
	if !ok {
		writeRateLimited(w, retryAfter)
		return false
	}
	return true
}

// allowSend enforces the delivery caps for one address. Called inside
// tenant transactions; returns errRateLimited to unwind them.
func (a *publicAPI) allowSend(ctx context.Context, t *tenant.Tenant, channel, value string) error {
	perDay := emailPerAddressDay
	if channel == identity.ChannelSMS {
		perDay = smsPerAddressDay
	}
	checks := []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{fmt.Sprintf("send:%s:%s:%s", t.ID, channel, value), 1, sendCooldown},
		{fmt.Sprintf("sendday:%s:%s:%s", t.ID, channel, value), perDay, 24 * time.Hour},
	}
	if channel == identity.ChannelSMS {
		checks = append(checks, struct {
			key    string
			limit  int
			window time.Duration
		}{fmt.Sprintf("smsday:%s", t.ID), t.Config.EffectiveSMSDailyCap(), 24 * time.Hour})
	}
	for _, c := range checks {
		ok, retryAfter, err := a.limiter.Allow(ctx, c.key, c.limit, c.window)
		if err != nil {
			return err
		}
		if !ok {
			return errRateLimited{retryAfter: retryAfter}
		}
	}
	return nil
}

func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	if secs := int(retryAfter.Seconds()); secs > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	writeError(w, http.StatusTooManyRequests, "too many requests; try again later")
}

// clientIP keys the per-IP limits. RemoteAddr only for now: forwarded
// headers are trustworthy only behind a proxy we control, which needs its
// own config before it is safe to honor.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
