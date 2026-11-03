package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("KNOTWORK_BASE_URL", "")
	t.Setenv("KNOTWORK_DATABASE_URL", "")
	t.Setenv("KNOTWORK_OIDC_ISSUER", "")
	t.Setenv("KNOTWORK_OIDC_CLIENT_ID", "")
	t.Setenv("KNOTWORK_OIDC_CLIENT_SECRET", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "sqlite://./data/knotwork.db" {
		t.Fatalf("unexpected database url %q", cfg.DatabaseURL)
	}
	if cfg.SetupSecret == "" {
		t.Fatal("expected generated setup secret")
	}
	if cfg.OIDC.Enabled() {
		t.Fatal("OIDC should be disabled")
	}
	if !strings.HasSuffix(cfg.OIDC.RedirectURL, "/auth/callback") {
		t.Fatalf("unexpected redirect url %q", cfg.OIDC.RedirectURL)
	}
}

func TestLoadPartialOIDCFails(t *testing.T) {
	t.Setenv("KNOTWORK_OIDC_ISSUER", "https://accounts.example.com")
	t.Setenv("KNOTWORK_OIDC_CLIENT_ID", "")
	t.Setenv("KNOTWORK_OIDC_CLIENT_SECRET", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected partial OIDC configuration to fail")
	}
}

func TestLoadRejectsNonHTTPBaseURL(t *testing.T) {
	t.Setenv("KNOTWORK_BASE_URL", "ftp://example.com")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid scheme to fail")
	}
}

func TestLoadRejectsBaseURLWithPath(t *testing.T) {
	t.Setenv("KNOTWORK_BASE_URL", "https://example.com/knotwork")
	if _, err := Load(); err == nil {
		t.Fatal("expected base URL with a path to fail")
	}
}
