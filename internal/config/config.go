// Package config loads Pratu's configuration from a YAML file with
// environment-variable overrides (PRATU_*).
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// BaseDomain is the parent domain for tenant subdomains: tenant "acme"
	// is served at acme.<BaseDomain> (ADR 0003).
	BaseDomain string     `yaml:"base_domain"`
	Public     Public     `yaml:"public"`
	Admin      Admin      `yaml:"admin"`
	Database   Database   `yaml:"database"`
	Courier    Courier    `yaml:"courier"`
	HIBP       HIBP       `yaml:"hibp"`
	OAuth2     OAuth2     `yaml:"oauth2"`
	Encryption Encryption `yaml:"encryption"`
}

type Encryption struct {
	// Keys seal secrets at rest (TOTP secrets, second-factor phones,
	// tenant signing keys). The first key encrypts; all keys decrypt, so
	// rotation is prepending a new key. Each must be at least 32
	// characters. Empty means secrets are stored unencrypted.
	Keys []string `yaml:"keys"`
}

type OAuth2 struct {
	// SystemSecret keys the HMAC over authorize codes and refresh tokens
	// (min 32 chars). When empty, the OAuth2 provider endpoints are
	// disabled.
	SystemSecret string `yaml:"system_secret"`
}

type HIBP struct {
	// BaseURL of a Pwned-Passwords-compatible range API; empty means the
	// public api.pwnedpasswords.com. The check itself is a per-tenant
	// setting and fails open when the API is unreachable.
	BaseURL string `yaml:"base_url"`
}

type Courier struct {
	// Driver delivers outbox messages: "log" (dev default; codes end up in
	// the log) or "webhook" (POST each message as JSON to WebhookURL).
	Driver     string `yaml:"driver"`
	WebhookURL string `yaml:"webhook_url"`
}

type Public struct {
	Listen string `yaml:"listen"`
	// TrustedProxies are CIDR ranges (or bare IPs) whose X-Forwarded-For
	// and X-Forwarded-Proto headers are honored. Empty means forwarded
	// headers are ignored entirely.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// ReferenceUI serves the built-in reference login UI at /ui/ on
	// tenant hostnames. Off by default: the server is headless, and the
	// reference UI is a starter/dev convenience.
	ReferenceUI bool `yaml:"reference_ui"`
}

type Admin struct {
	Listen string `yaml:"listen"`
	// RootKey authorizes the platform-level admin API. When empty, the
	// admin API (beyond health checks) refuses all requests.
	RootKey string `yaml:"root_key"`
}

type Database struct {
	URL string `yaml:"url"`
}

func defaults() Config {
	return Config{
		Public:  Public{Listen: ":4433"},
		Admin:   Admin{Listen: ":4434"},
		Courier: Courier{Driver: "log"},
	}
}

// Load reads the YAML file at path (skipped when path is empty), applies
// PRATU_* environment overrides, and validates the result.
func Load(path string) (Config, error) {
	cfg := defaults()

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	override(&cfg.BaseDomain, "PRATU_BASE_DOMAIN")
	override(&cfg.Public.Listen, "PRATU_PUBLIC_LISTEN")
	override(&cfg.Admin.Listen, "PRATU_ADMIN_LISTEN")
	override(&cfg.Admin.RootKey, "PRATU_ADMIN_ROOT_KEY")
	override(&cfg.Database.URL, "PRATU_DATABASE_URL")
	override(&cfg.Courier.Driver, "PRATU_COURIER_DRIVER")
	override(&cfg.Courier.WebhookURL, "PRATU_COURIER_WEBHOOK_URL")
	override(&cfg.HIBP.BaseURL, "PRATU_HIBP_BASE_URL")
	override(&cfg.OAuth2.SystemSecret, "PRATU_OAUTH2_SYSTEM_SECRET")
	if v, ok := os.LookupEnv("PRATU_ENCRYPTION_KEYS"); ok {
		cfg.Encryption.Keys = splitList(v)
	}
	if v, ok := os.LookupEnv("PRATU_TRUSTED_PROXIES"); ok {
		cfg.Public.TrustedProxies = splitList(v)
	}
	if v, ok := os.LookupEnv("PRATU_REFERENCE_UI"); ok {
		cfg.Public.ReferenceUI = v == "true" || v == "1"
	}

	if cfg.BaseDomain == "" {
		return Config{}, errors.New("base_domain is required (or set PRATU_BASE_DOMAIN)")
	}
	if cfg.Database.URL == "" {
		return Config{}, errors.New("database.url is required (or set PRATU_DATABASE_URL)")
	}
	if s := cfg.OAuth2.SystemSecret; s != "" && len(s) < 32 {
		return Config{}, errors.New("oauth2.system_secret must be at least 32 characters")
	}
	switch cfg.Courier.Driver {
	case "log":
	case "webhook":
		if cfg.Courier.WebhookURL == "" {
			return Config{}, errors.New("courier.webhook_url is required with the webhook driver")
		}
	default:
		return Config{}, fmt.Errorf("courier.driver must be \"log\" or \"webhook\", got %q", cfg.Courier.Driver)
	}
	return cfg, nil
}

func override(dst *string, env string) {
	if v, ok := os.LookupEnv(env); ok {
		*dst = v
	}
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
