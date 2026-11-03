package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/domain"

	"golang.org/x/oauth2"
)

const (
	sessionCookie = "knotwork_session"
	oauthCookie   = "knotwork_oauth"
)

type Service struct {
	DB     *database.DB
	Cfg    config.Config
	OIDC   *OIDC
	Tokens *Tokens
	Log    *slog.Logger
	Key    ed25519.PrivateKey
}

func NewService(ctx context.Context, cfg config.Config, store *database.DB, log *slog.Logger) (*Service, error) {
	key, err := LoadOrCreateKey(filepath.Join(cfg.DataDir, "instance.key"))
	if err != nil {
		return nil, fmt.Errorf("load instance key: %w", err)
	}
	s := &Service{
		DB:     store,
		Cfg:    cfg,
		Tokens: NewTokens(key, cfg.BaseURL, 12*time.Hour),
		Log:    log,
		Key:    key,
	}
	if cfg.OIDC.Enabled() {
		provider, err := NewOIDC(ctx, cfg.OIDC)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery: %w", err)
		}
		s.OIDC = provider
	}
	return s, nil
}

// Register installs every authentication, setup, and device-flow route.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	// Sign-out mutates state, so GET is rejected explicitly. Without this
	// route the Git Smart HTTP catch-all (GET /) would answer 404 instead.
	mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("GET /auth/break-glass", s.breakGlass)
	mux.HandleFunc("POST /auth/device/code", s.deviceCode)
	mux.HandleFunc("POST /auth/device/token", s.deviceToken)
	mux.Handle("GET /auth/device", s.RequireUser(http.HandlerFunc(s.devicePage)))
	mux.Handle("POST /auth/device", s.RequireUser(http.HandlerFunc(s.deviceApprove)))
	mux.HandleFunc("GET /setup", s.setup)
	mux.Handle("GET /api/me", s.RequireUser(http.HandlerFunc(s.me)))
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.Error(w, "OIDC is not configured on this instance", http.StatusServiceUnavailable)
		return
	}
	state := database.NewToken()[:32]
	nonce := database.NewToken()[:32]
	verifier := oauth2.GenerateVerifier()
	next := safeNext(r.URL.Query().Get("next"))
	payload, _ := json.Marshal(oauthState{State: state, Nonce: nonce, Verifier: verifier, Next: next})
	//nolint:gosec // Secure follows the configured base URL; HttpOnly and SameSite are set.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthCookie,
		Value:    base64.RawURLEncoding.EncodeToString(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, s.OIDC.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.Error(w, "OIDC is not configured on this instance", http.StatusServiceUnavailable)
		return
	}
	cookie, err := r.Cookie(oauthCookie)
	if err != nil {
		http.Error(w, "missing login state", http.StatusBadRequest)
		return
	}
	var state oauthState
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || json.Unmarshal(raw, &state) != nil {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	//nolint:gosec // clearing a cookie; Secure follows the configured base URL.
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})

	if r.URL.Query().Get("state") != state.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	claims, err := s.OIDC.Exchange(r.Context(), r.URL.Query().Get("code"), state.Verifier, state.Nonce)
	if err != nil {
		s.Log.Warn("oidc callback failed", "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	username := sanitizeUsername(claims.PreferredUsername)
	if username == "" {
		username = sanitizeUsername(strings.Split(claims.Email, "@")[0])
	}
	if username == "" {
		username = "user-" + database.NewID()[:8]
	}
	user, err := s.DB.UpsertOIDCUser(r.Context(), claims.Subject, claims.Email, username, claims.Name)
	if err != nil {
		s.Log.Error("provisioning oidc user failed", "error", err, "subject", claims.Subject)
		http.Error(w, "could not provision user", http.StatusInternalServerError)
		return
	}
	if !user.IsActive {
		http.Error(w, "account is disabled", http.StatusForbidden)
		return
	}
	if s.adminEmail(claims.Email) && !user.IsAdmin() {
		if err := s.DB.SetUserRole(r.Context(), user.ID, domain.RoleAdmin); err == nil {
			user.Role = domain.RoleAdmin
		}
	}
	if user.IsAdmin() {
		completed, _ := s.DB.SetupCompleted(r.Context())
		if !completed {
			if err := s.DB.CompleteSetup(r.Context()); err != nil {
				s.Log.Warn("complete setup failed", "error", err)
			}
		}
	}

	token, err := s.DB.CreateSession(r.Context(), user.ID, "web", s.Cfg.SessionTTL)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, token, s.Cfg.SessionTTL)
	http.Redirect(w, r, defaultNext(state.Next), http.StatusFound)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.DB.DeleteSession(r.Context(), c.Value)
	}
	//nolint:gosec // clearing a cookie; Secure follows the configured base URL.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure()})
	http.Redirect(w, r, "/", http.StatusFound)
}

type oauthState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
}

type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// UserFromRequest resolves a session cookie, an Ed25519 bearer token, or HTTP Basic credentials.
func (s *Service) UserFromRequest(r *http.Request) (domain.User, bool) {
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		raw := strings.TrimPrefix(header, "Bearer ")
		return s.userFromToken(r.Context(), raw)
	}
	if username, password, ok := r.BasicAuth(); ok {
		token := password
		if token == "" {
			token = username
		}
		return s.userFromToken(r.Context(), token)
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return domain.User{}, false
	}
	user, err := s.DB.UserForSession(r.Context(), cookie.Value)
	if err != nil {
		return domain.User{}, false
	}
	return user, true
}

func (s *Service) userFromToken(ctx context.Context, raw string) (domain.User, bool) {
	if raw == "" {
		return domain.User{}, false
	}
	if s.Tokens != nil {
		if claims, err := s.Tokens.Parse(raw); err == nil {
			user, err := s.DB.GetUserByID(ctx, claims.UserID)
			if err != nil || !user.IsActive {
				return domain.User{}, false
			}
			return user, true
		}
	}
	// Opaque tokens are used by SCIM integrations.
	if s.DB != nil {
		if user, err := s.DB.UserForSession(ctx, raw); err == nil {
			return user, true
		}
	}
	return domain.User{}, false
}

func (s *Service) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.UserFromRequest(r)
		if !ok {
			if wantsJSON(r) {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}

func (s *Service) RequireAdmin(next http.Handler) http.Handler {
	return s.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := UserFromContext(r.Context())
		if !user.IsAdmin() {
			writeJSONError(w, http.StatusForbidden, "instance admin required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequireSCIM requires a bearer session previously minted by an instance admin.
func (s *Service) RequireSCIM(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.UserFromRequest(r)
		if !ok || !user.IsAdmin() {
			writeSCIMError(w, http.StatusUnauthorized, "invalid SCIM bearer token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}

func (s *Service) secure() bool { return strings.HasPrefix(s.Cfg.BaseURL, "https://") }

func (s *Service) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	//nolint:gosec // Secure follows the configured base URL; HttpOnly and SameSite are set.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Service) adminEmail(email string) bool {
	for _, e := range s.Cfg.AdminEmails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (s *Service) setup(w http.ResponseWriter, r *http.Request) {
	completed, err := s.DB.SetupCompleted(r.Context())
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	if completed {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	key := r.URL.Query().Get("key")
	if subtle.ConstantTimeCompare([]byte(key), []byte(s.Cfg.SetupSecret)) != 1 {
		http.Error(w, "invalid or missing setup key", http.StatusForbidden)
		return
	}
	if s.OIDC == nil {
		http.Error(w, "OIDC must be configured before setup can complete", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = setupTemplate.Execute(w, map[string]string{"LoginURL": "/auth/login?next=/"})
}

func (s *Service) breakGlass(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	user, expires, err := s.DB.ConsumeBreakGlass(r.Context(), token)
	if err != nil {
		http.Error(w, "invalid or expired break-glass token", http.StatusUnauthorized)
		return
	}
	ttl := time.Until(expires)
	if ttl <= 0 {
		http.Error(w, "break-glass token expired", http.StatusUnauthorized)
		return
	}
	session, err := s.DB.CreateSession(r.Context(), user.ID, "break_glass", ttl)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, session, ttl)
	s.Log.Warn("break-glass session used", "user", user.Username)
	http.Redirect(w, r, "/", http.StatusFound)
}

func WithUser(ctx context.Context, u domain.User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

type userKey struct{}

func UserFromContext(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(userKey{}).(domain.User)
	return u, ok
}

func wantsJSON(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") ||
		strings.HasPrefix(r.URL.Path, "/scim/") ||
		strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

func defaultNext(next string) string { return safeNext(next) }

func sanitizeUsername(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), ".-_")
	if len(out) > 39 {
		out = out[:39]
	}
	return out
}

var setupTemplate = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Knotwork setup</title>
<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem}</style></head>
<body><h1>Knotwork setup</h1>
<p>Setup key accepted. Continue with your OIDC provider; the first user becomes the instance administrator.</p>
<p><a href="{{.LoginURL}}">Continue to sign in</a></p></body></html>`))
