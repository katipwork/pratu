// Package config loads Pratu's configuration from a YAML file with
// environment-variable overrides (PRATU_*).
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// BaseDomain is the parent domain for tenant subdomains: tenant "acme"
	// is served at acme.<BaseDomain> (ADR 0003).
	BaseDomain string   `yaml:"base_domain"`
	Public     Public   `yaml:"public"`
	Admin      Admin    `yaml:"admin"`
	Database   Database `yaml:"database"`
}

type Public struct {
	Listen string `yaml:"listen"`
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
		Public: Public{Listen: ":4433"},
		Admin:  Admin{Listen: ":4434"},
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

	if cfg.BaseDomain == "" {
		return Config{}, errors.New("base_domain is required (or set PRATU_BASE_DOMAIN)")
	}
	if cfg.Database.URL == "" {
		return Config{}, errors.New("database.url is required (or set PRATU_DATABASE_URL)")
	}
	return cfg, nil
}

func override(dst *string, env string) {
	if v, ok := os.LookupEnv(env); ok {
		*dst = v
	}
}
