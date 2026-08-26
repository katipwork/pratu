// Package server assembles the two HTTP listeners: the public server,
// addressed via tenant hostnames, and the admin server, which must never
// be reachable through them.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/flow"
	"github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/ratelimit"
	"github.com/katipwork/pratu/internal/tenant"
)

type ctxKey int

const tenantKey ctxKey = 0

func requestTenant(r *http.Request) *tenant.Tenant {
	return r.Context().Value(tenantKey).(*tenant.Tenant)
}

// NewPublic builds the tenant-facing handler. Health checks are
// tenant-agnostic; everything else resolves the tenant from the Host
// header first.
func NewPublic(pool *pgxpool.Pool, resolver *tenant.Resolver, breach password.BreachChecker, limiter *ratelimit.Limiter, providers *oauth2.Providers, log *slog.Logger) http.Handler {
	api := &publicAPI{pool: pool, breach: breach, limiter: limiter, providers: providers, log: log}

	tenanted := http.NewServeMux()
	tenanted.HandleFunc("POST /self-service/registration/api", api.createFlowHandler(flow.KindRegistration, false))
	tenanted.HandleFunc("GET /self-service/registration/browser", api.createFlowHandler(flow.KindRegistration, true))
	tenanted.HandleFunc("POST /self-service/registration", api.submitRegistration)
	tenanted.HandleFunc("POST /self-service/login/api", api.createFlowHandler(flow.KindLogin, false))
	tenanted.HandleFunc("GET /self-service/login/browser", api.createFlowHandler(flow.KindLogin, true))
	tenanted.HandleFunc("POST /self-service/login", api.submitLogin)
	tenanted.HandleFunc("POST /self-service/verification", api.submitVerification)
	tenanted.HandleFunc("POST /self-service/verification/resend", api.resendVerification)
	tenanted.HandleFunc("POST /self-service/recovery/api", api.createFlowHandler(flow.KindRecovery, false))
	tenanted.HandleFunc("GET /self-service/recovery/browser", api.createFlowHandler(flow.KindRecovery, true))
	tenanted.HandleFunc("POST /self-service/recovery", api.submitRecoveryAddress)
	tenanted.HandleFunc("POST /self-service/recovery/code", api.submitRecoveryCode)
	tenanted.HandleFunc("POST /self-service/recovery/totp", api.submitRecoveryTOTP)
	tenanted.HandleFunc("POST /self-service/recovery/password", api.submitRecoveryPassword)
	tenanted.HandleFunc("POST /self-service/login/totp", api.submitLoginTOTP)
	tenanted.HandleFunc("POST /self-service/login/sms/send", api.loginSMSSend)
	tenanted.HandleFunc("POST /self-service/login/sms", api.loginSMSSubmit)
	tenanted.HandleFunc("POST /self-service/recovery/sms/send", api.recoverySMSSend)
	tenanted.HandleFunc("POST /self-service/recovery/sms", api.recoverySMSSubmit)
	tenanted.HandleFunc("POST /self-service/mfa/totp/enroll", api.enrollTOTP)
	tenanted.HandleFunc("POST /self-service/mfa/totp/confirm", api.confirmTOTP)
	tenanted.HandleFunc("DELETE /self-service/mfa/totp", api.unenrollTOTP)
	tenanted.HandleFunc("POST /self-service/mfa/sms/enroll", api.enrollSMS)
	tenanted.HandleFunc("POST /self-service/mfa/sms/confirm", api.confirmSMS)
	tenanted.HandleFunc("DELETE /self-service/mfa/sms", api.unenrollSMS)
	tenanted.HandleFunc("GET /.well-known/openid-configuration", api.oauthDiscovery)
	tenanted.HandleFunc("GET /.well-known/jwks.json", api.oauthJWKS)
	tenanted.HandleFunc("GET /oauth2/auth", api.oauthAuthorize)
	tenanted.HandleFunc("GET /oauth2/auth/requests/{challenge}", api.oauthChallengeInfo)
	tenanted.HandleFunc("POST /oauth2/auth/accept", api.oauthAccept)
	tenanted.HandleFunc("GET /oauth2/auth/finish", api.oauthFinish)
	tenanted.HandleFunc("POST /oauth2/token", api.oauthToken)
	tenanted.HandleFunc("POST /oauth2/introspect", api.oauthIntrospect)
	tenanted.HandleFunc("POST /oauth2/revoke", api.oauthRevoke)
	tenanted.HandleFunc("GET /sessions/whoami", api.whoami)
	tenanted.HandleFunc("GET /sessions", api.listSessions)
	tenanted.HandleFunc("DELETE /sessions", api.revokeOtherSessions)
	tenanted.HandleFunc("DELETE /sessions/{id}", api.revokeSession)
	tenanted.HandleFunc("POST /self-service/logout", api.logout)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/alive", alive)
	mux.HandleFunc("GET /health/ready", ready(pool))
	mux.Handle("/", resolveTenant(resolver, tenanted))
	return mux
}

func resolveTenant(resolver *tenant.Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, err := resolver.Resolve(r.Context(), r.Host)
		if errors.Is(err, tenant.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown tenant")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "tenant resolution failed")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey, t)))
	})
}

func alive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func ready(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unreachable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
