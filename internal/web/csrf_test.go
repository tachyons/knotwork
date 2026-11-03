package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// authedCookie mints a web session for a fresh admin user and returns the
// cookie that carries it.
func authedCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	ctx := t.Context()
	user, err := s.DB.UpsertOIDCUser(ctx, "csrf-sub", "csrf@example.com", "csrf", "CSRF Tester")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	token, err := s.DB.CreateSession(ctx, user.ID, "web", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return &http.Cookie{Name: "knotwork_session", Value: token}
}

func TestCrossOriginProtection(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		path         string
		body         string
		origin       string
		secFetchSite string
		authed       bool
		wantStatus   int
	}{
		{
			name:       "same-origin browser POST is allowed",
			method:     http.MethodPost,
			path:       "/api/repos",
			body:       `{"name":"csrf-same-origin","private":true}`,
			origin:     "http://example.com",
			authed:     true,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "cross-site browser POST is rejected",
			method:     http.MethodPost,
			path:       "/api/repos",
			body:       `{"name":"csrf-cross-site","private":true}`,
			origin:     "https://evil.example",
			authed:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:         "cross-site fetch metadata is rejected",
			method:       http.MethodPost,
			path:         "/api/repos",
			body:         `{"name":"csrf-fetch-metadata","private":true}`,
			secFetchSite: "cross-site",
			authed:       true,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "same-origin fetch metadata is allowed",
			method:       http.MethodPost,
			path:         "/api/repos",
			body:         `{}`,
			secFetchSite: "same-origin",
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:       "headerless non-browser client is allowed",
			method:     http.MethodPost,
			path:       "/api/repos",
			body:       `{}`,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "safe method is never rejected",
			method:     http.MethodGet,
			path:       "/api/repos",
			origin:     "https://evil.example",
			authed:     true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "cross-site PUT is rejected",
			method:     http.MethodPut,
			path:       "/api/repos",
			origin:     "https://evil.example",
			authed:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site DELETE is rejected",
			method:     http.MethodDelete,
			path:       "/api/admin/peers/evil.example",
			origin:     "https://evil.example",
			authed:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "git smart http is exempt",
			method:     http.MethodPost,
			path:       "/alice/demo.git/git-receive-pack",
			origin:     "https://evil.example",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "scim is exempt",
			method:     http.MethodPost,
			path:       "/scim/v2/Users",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "mcp is exempt",
			method:     http.MethodPost,
			path:       "/api/mcp/messages",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "federation inbox is exempt",
			method:     http.MethodPost,
			path:       "/inbox",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "device code flow is exempt",
			method:     http.MethodPost,
			path:       "/auth/device/code",
			origin:     "https://evil.example",
			wantStatus: http.StatusOK,
		},
		{
			name:       "device token flow is exempt",
			method:     http.MethodPost,
			path:       "/auth/device/token",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, _, _, handler := setupTestServer(t)

			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			if tc.authed {
				req.AddCookie(authedCookie(t, server))
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s status = %d, want %d (body: %s)",
					tc.method, tc.path, rec.Code, tc.wantStatus, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

func TestCrossOriginRejectionIsJSON(t *testing.T) {
	server, _, _, handler := setupTestServer(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/repos", strings.NewReader(`{"name":"csrf"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(authedCookie(t, server))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if !strings.Contains(rec.Body.String(), "cross-origin") {
		t.Fatalf("body = %q, want cross-origin rejection message", strings.TrimSpace(rec.Body.String()))
	}
}
