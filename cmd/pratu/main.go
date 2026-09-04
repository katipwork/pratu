package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/adminkey"
	"github.com/katipwork/pratu/internal/config"
	"github.com/katipwork/pratu/internal/courier"
	"github.com/katipwork/pratu/internal/oauth2"
	"github.com/katipwork/pratu/internal/password"
	"github.com/katipwork/pratu/internal/ratelimit"
	"github.com/katipwork/pratu/internal/secrets"
	"github.com/katipwork/pratu/internal/server"
	"github.com/katipwork/pratu/internal/storage"
	"github.com/katipwork/pratu/internal/tenant"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(log, os.Args[2:])
	case "migrate":
		err = migrate(log, os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `pratu - multi-tenant authentication server

Usage:
  pratu serve   [-config pratu.yaml]   run the public and admin servers
  pratu migrate [-config pratu.yaml]   apply pending database migrations
  pratu version                        print the version
`)
}

func loadConfig(args []string, cmd string) (config.Config, error) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	path := fs.String("config", "", "path to YAML config file")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return config.Load(*path)
}

func serve(log *slog.Logger, args []string) error {
	cfg, err := loadConfig(args, "serve")
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := storage.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	cip, err := secrets.NewCipher(cfg.Encryption.Keys)
	if err != nil {
		return err
	}
	storage.SetCipher(cip)
	if cip == nil {
		log.Warn("encryption.keys not set; TOTP secrets, factor phones, and signing keys are stored unencrypted")
	} else if keys, creds, err := storage.EncryptAtRest(ctx, pool); err != nil {
		return fmt.Errorf("encrypt-at-rest sweep: %w", err)
	} else if keys+creds > 0 {
		log.Info("encrypted legacy plaintext secrets", "tenant_keys", keys, "credentials", creds)
	}

	proxies, err := server.ParseProxies(cfg.Public.TrustedProxies)
	if err != nil {
		return err
	}
	server.SetTrustedProxies(proxies)
	if len(proxies) > 0 {
		log.Info("honoring forwarded headers from trusted proxies", "ranges", cfg.Public.TrustedProxies)
	}

	resolver := tenant.NewResolver(cfg.BaseDomain, storage.NewTenantStore(pool))

	var driver courier.Driver
	switch cfg.Courier.Driver {
	case "webhook":
		driver = courier.NewWebhookDriver(cfg.Courier.WebhookURL)
	default:
		log.Warn("courier is using the log driver; one-time codes will appear in the log (dev only)")
		driver = courier.LogDriver{Log: log}
	}
	go drainCourier(ctx, log, pool, driver)

	breach := password.NewHIBP(cfg.HIBP.BaseURL)
	limiter := ratelimit.New(pool)
	go runJanitor(ctx, log, pool, limiter)

	var providers *oauth2.Providers
	if cfg.OAuth2.SystemSecret != "" {
		providers = oauth2.NewProviders([]byte(cfg.OAuth2.SystemSecret))
	} else {
		log.Warn("oauth2.system_secret not set; OAuth2 provider endpoints are disabled")
	}

	if cfg.Public.ReferenceUI {
		log.Info("reference login UI enabled at /ui/ on tenant hostnames")
	}
	// Config already validated the ring at load, so this cannot fail for
	// a configuration reason.
	ring, err := adminkey.NewKeyring(cfg.Admin.RootKey, cfg.Admin.Keys)
	if err != nil {
		log.Error("admin keys", "err", err)
		os.Exit(1)
	}
	for _, k := range cfg.Admin.Keys {
		log.Info("scoped admin key configured", "name", k.Name,
			"capabilities", k.Capabilities, "tenants", k.Tenants)
	}

	public := &http.Server{Addr: cfg.Public.Listen, Handler: server.NewPublic(pool, resolver, breach, limiter, providers, cfg.Public.ReferenceUI, log)}
	admin := &http.Server{Addr: cfg.Admin.Listen, Handler: server.NewAdmin(pool, ring, cfg.BaseDomain, providers)}

	errc := make(chan error, 2)
	go func() {
		log.Info("public server listening", "addr", cfg.Public.Listen, "base_domain", cfg.BaseDomain)
		errc <- public.ListenAndServe()
	}()
	go func() {
		log.Info("admin server listening", "addr", cfg.Admin.Listen)
		errc <- admin.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := public.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return admin.Shutdown(shutdownCtx)
}

// runJanitor sweeps dead rows — expired flows/sessions/codes, spent
// OAuth2 rows, old courier messages, stale rate-limit windows — once at
// startup and then every 10 minutes.
func runJanitor(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, limiter *ratelimit.Limiter) {
	sweep := func() {
		deleted, err := storage.CleanupExpired(ctx, pool)
		if err != nil && ctx.Err() == nil {
			log.Error("janitor sweep failed", "error", err)
		}
		if len(deleted) > 0 {
			args := make([]any, 0, len(deleted)*2)
			for table, n := range deleted {
				args = append(args, table, n)
			}
			log.Info("janitor swept expired rows", args...)
		}
		if _, err := limiter.Cleanup(ctx, 48*time.Hour); err != nil && ctx.Err() == nil {
			log.Error("rate limit cleanup failed", "error", err)
		}
	}

	sweep()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// drainCourier delivers pending outbox messages until the context ends.
func drainCourier(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool, driver courier.Driver) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := storage.CourierDrain(ctx, pool, driver); err != nil && ctx.Err() == nil {
				log.Error("courier drain failed", "error", err)
			}
		}
	}
}

func migrate(log *slog.Logger, args []string) error {
	cfg, err := loadConfig(args, "migrate")
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := storage.Connect(ctx, cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	applied, err := storage.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	for _, v := range applied {
		log.Info("applied migration", "version", v)
	}
	log.Info("migrations up to date", "applied_now", len(applied))
	return nil
}
