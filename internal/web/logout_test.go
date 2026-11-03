package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogoutRejectsGET(t *testing.T) {
	server, db, _, handler := setupTestServer(t)
	cookie := authedCookie(t, server)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth/logout status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if _, err := db.UserForSession(t.Context(), cookie.Value); err != nil {
		t.Fatalf("GET /auth/logout revoked the session: %v", err)
	}
}

func TestLogoutDeletesSessionOnSameOriginPOST(t *testing.T) {
	server, db, _, handler := setupTestServer(t)
	cookie := authedCookie(t, server)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", "http://example.com")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("POST /auth/logout status = %d, want %d (body: %s)", rec.Code, http.StatusFound, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("redirect = %q, want /", loc)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookie.Name && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected %s cookie to be cleared, got %v", cookie.Name, rec.Result().Cookies())
	}
	if _, err := db.UserForSession(t.Context(), cookie.Value); err == nil {
		t.Fatal("session still resolves after logout")
	}
}

func TestLogoutRejectsCrossSitePOST(t *testing.T) {
	server, db, _, handler := setupTestServer(t)
	cookie := authedCookie(t, server)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST /auth/logout status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if _, err := db.UserForSession(t.Context(), cookie.Value); err != nil {
		t.Fatalf("cross-site logout revoked the session: %v", err)
	}
}

func TestSignOutIsPostForm(t *testing.T) {
	server, _, _, handler := setupTestServer(t)
	cookie := authedCookie(t, server)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/auth/logout"`) || !strings.Contains(body, `method="POST"`) {
		t.Fatalf("expected a POST form to /auth/logout, got:\n%s", body)
	}
	if strings.Contains(body, `href="/auth/logout"`) {
		t.Fatalf("sign-out must not be a GET link, got:\n%s", body)
	}
}
