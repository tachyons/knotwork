// Package config loads Knotwork's single-node configuration from the environment.
//
// Knotwork is configured entirely by environment variables so the same binary can
// run from a systemd unit, a container, or a shell without a config file parser.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr           string
	BaseURL        string
	DatabaseURL    string
	DataDir        string
	RepoRoot       string
	SocketPath     string
	GitBinary      string
	DockerHost     string
	SessionTTL     time.Duration
	BackupInterval time.Duration
	BundleDebounce time.Duration
	TLSCert        string
	TLSKey         string
	SetupSecret    string
	AdminEmails    []string
	LogLevel       string // "debug", "info", "warn", "error"
	LogFormat      string // "text", "json"
	OIDC           OIDC
	S3             S3
}

type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (o OIDC) Enabled() bool {
	return o.Issuer != "" || o.ClientID != "" || o.ClientSecret != ""
}

type S3 struct {
	Bucket         string
	Region         string
	Endpoint       string
	AccessKey      string
	SecretKey      string
	ForcePathStyle bool
}

func (s S3) Enabled() bool { return s.Bucket != "" }

// Load reads configuration from the environment. Missing values fall back to
// local-development defaults; a partial OIDC configuration is a hard error so a
// misconfigured instance never silently runs without authentication.
func Load() (Config, error) {
	baseURL := env("BASE_URL", "http://localhost:8080")
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Config{}, fmt.Errorf("invalid KNOTWORK_BASE_URL %q", baseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Config{}, fmt.Errorf("KNOTWORK_BASE_URL must be http or https, got %q", u.Scheme)
	}
	if u.Path != "" && u.Path != "/" {
		return Config{}, fmt.Errorf("KNOTWORK_BASE_URL must not include a path, got %q", baseURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("KNOTWORK_BASE_URL must not include a query or fragment, got %q", baseURL)
	}

	dataDir := env("DATA_DIR", "./data")
	cfg := Config{
		Addr:           env("ADDR", ":8080"),
		BaseURL:        strings.TrimRight(baseURL, "/"),
		DatabaseURL:    env("DATABASE_URL", "sqlite://"+dataDir+"/knotwork.db"),
		DataDir:        dataDir,
		RepoRoot:       env("REPO_ROOT", dataDir+"/repos"),
		SocketPath:     env("SOCKET_PATH", "/tmp/knotwork-internal.sock"),
		GitBinary:      env("GIT_BINARY", "git"),
		DockerHost:     env("DOCKER_HOST", "unix:///var/run/docker.sock"),
		SessionTTL:     envDuration("SESSION_TTL", 24*time.Hour),
		BackupInterval: envDuration("BACKUP_INTERVAL", 6*time.Hour),
		BundleDebounce: envDuration("BUNDLE_DEBOUNCE", 30*time.Second),
		LogLevel:       env("LOG_LEVEL", "info"),
		LogFormat:      env("LOG_FORMAT", "text"),
		TLSCert:        os.Getenv("KNOTWORK_TLS_CERT"),
		TLSKey:         os.Getenv("KNOTWORK_TLS_KEY"),
		SetupSecret:    os.Getenv("KNOTWORK_SETUP_SECRET"),
		AdminEmails:    splitCSV(os.Getenv("KNOTWORK_ADMIN_EMAILS")),
		OIDC: OIDC{
			Issuer:       os.Getenv("KNOTWORK_OIDC_ISSUER"),
			ClientID:     os.Getenv("KNOTWORK_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("KNOTWORK_OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("KNOTWORK_OIDC_REDIRECT_URL"),
		},
		S3: S3{
			Bucket:         os.Getenv("KNOTWORK_S3_BUCKET"),
			Region:         env("S3_REGION", "us-east-1"),
			Endpoint:       os.Getenv("KNOTWORK_S3_ENDPOINT"),
			AccessKey:      os.Getenv("KNOTWORK_S3_ACCESS_KEY"),
			SecretKey:      os.Getenv("KNOTWORK_S3_SECRET_KEY"),
			ForcePathStyle: envBool("S3_FORCE_PATH_STYLE", false),
		},
	}
	if cfg.OIDC.RedirectURL == "" {
		cfg.OIDC.RedirectURL = cfg.BaseURL + "/auth/callback"
	}
	if cfg.SetupSecret == "" {
		cfg.SetupSecret = randomHex(16)
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return Config{}, errors.New("KNOTWORK_TLS_CERT and KNOTWORK_TLS_KEY must be set together")
	}

	oidcSet := 0
	for _, v := range []string{cfg.OIDC.Issuer, cfg.OIDC.ClientID, cfg.OIDC.ClientSecret} {
		if v != "" {
			oidcSet++
		}
	}
	if oidcSet != 0 && oidcSet != 3 {
		return Config{}, errors.New("KNOTWORK_OIDC_ISSUER, KNOTWORK_OIDC_CLIENT_ID and KNOTWORK_OIDC_CLIENT_SECRET must be set together")
	}
	if cfg.SessionTTL <= 0 {
		return Config{}, errors.New("KNOTWORK_SESSION_TTL must be positive")
	}
	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv("KNOTWORK_" + key); v != "" {
		return v
	}
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv("KNOTWORK_" + key)
	if v == "" {
		v = os.Getenv(key)
	}
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envBool(key string, def bool) bool {
	v := os.Getenv("KNOTWORK_" + key)
	if v == "" {
		v = os.Getenv(key)
	}
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
