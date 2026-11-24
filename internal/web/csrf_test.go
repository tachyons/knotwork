package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewCrossOriginProtectionRejectsBaseURLWithPath(t *testing.T) {
	if _, err := newCrossOriginProtection("http://example.com/prefix"); err == nil {
		t.Fatal("expected a base URL with a path to be rejected")
	}
}

func TestCrossOriginCheck(t *testing.T) {
	guard, err := newCrossOriginProtection("http://example.com")
	if err != nil {
		t.Fatalf("newCrossOriginProtection: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := crossOriginCheck(guard, discardLogger(), next)

	tests := []struct {
		name         string
		method       string
		host         string
		origin       string
		secFetchSite string
		wantRejected bool
	}{
		{
			name:   "same-origin POST is allowed",
			method: http.MethodPost,
			origin: "http://example.com",
		},
		{
			name:         "cross-site POST is rejected",
			method:       http.MethodPost,
			origin:       "https://evil.example",
			wantRejected: true,
		},
		{
			name:         "same-origin fetch metadata is allowed",
			method:       http.MethodPost,
			secFetchSite: "same-origin",
		},
		{
			name:         "cross-site fetch metadata is rejected",
			method:       http.MethodPost,
			secFetchSite: "cross-site",
			wantRejected: true,
		},
		{
			name:         "same-site fetch metadata is rejected",
			method:       http.MethodPost,
			secFetchSite: "same-site",
			wantRejected: true,
		},
		{
			name:         "cross-origin Origin with same-origin fetch metadata is rejected",
			method:       http.MethodPost,
			origin:       "http://google.com",
			secFetchSite: "same-origin",
			wantRejected: true,
		},
		{
			name:         "cross-origin Origin with none fetch metadata is rejected",
			method:       http.MethodPost,
			origin:       "http://google.com",
			secFetchSite: "none",
			wantRejected: true,
		},
		{
			name:   "headerless non-browser client is allowed",
			method: http.MethodPost,
		},
		{
			name:   "safe method is never rejected",
			method: http.MethodGet,
			origin: "https://evil.example",
		},
		{
			name:   "trusted origin is allowed behind a proxy",
			method: http.MethodPost,
			host:   "internal:8080",
			origin: "http://example.com",
		},
		{
			name:         "untrusted origin is rejected behind a proxy",
			method:       http.MethodPost,
			host:         "internal:8080",
			origin:       "https://evil.example",
			wantRejected: true,
		},
		{
			name:         "cross-site PATCH is rejected",
			method:       http.MethodPatch,
			origin:       "https://evil.example",
			wantRejected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tc.method, "/api/repos", nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rejected := rec.Code == http.StatusForbidden; rejected != tc.wantRejected {
				t.Fatalf("status = %d, wantRejected = %v", rec.Code, tc.wantRejected)
			}
			if !tc.wantRejected && rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want handler to run (%d)", rec.Code, http.StatusNoContent)
			}
		})
	}
}

func TestCrossOriginProtectionEndToEnd(t *testing.T) {
	server, _, _, handler := setupTestServer(t)
	cookie := authedCookie(t, server)

	tests := []struct {
		name         string
		method       string
		path         string
		body         string
		origin       string
		secFetchSite string
		wantStatus   int
	}{
		{
			name:       "same-origin POST creates a repo",
			method:     http.MethodPost,
			path:       "/api/repos",
			body:       `{"name":"csrf-e2e","private":true}`,
			origin:     "http://example.com",
			wantStatus: http.StatusCreated,
		},
		{
			name:         "cross-origin Origin with same-origin fetch metadata is rejected",
			method:       http.MethodPost,
			path:         "/api/repos",
			body:         `{"name":"csrf-spoof","private":true}`,
			origin:       "http://google.com",
			secFetchSite: "same-origin",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:       "cross-site POST is rejected",
			method:     http.MethodPost,
			path:       "/api/repos",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site SCIM is rejected",
			method:     http.MethodPost,
			path:       "/scim/v2/Users",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site MCP is rejected",
			method:     http.MethodPost,
			path:       "/api/mcp/messages",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site git push is rejected",
			method:     http.MethodPost,
			path:       "/alice/demo.git/git-receive-pack",
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site federation inbox is rejected",
			method:     http.MethodPost,
			path:       "/inbox",
			body:       `{}`,
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cross-site device code is rejected",
			method:     http.MethodPost,
			path:       "/auth/device/code",
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "headerless SCIM reaches the handler",
			method:     http.MethodPost,
			path:       "/scim/v2/Users",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "headerless git reaches the handler",
			method:     http.MethodPost,
			path:       "/alice/demo.git/git-receive-pack",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "headerless device code reaches the handler",
			method:     http.MethodPost,
			path:       "/auth/device/code",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
			req.AddCookie(cookie)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s status = %d, want %d (body: %s)",
					tc.method, tc.path, rec.Code, tc.wantStatus, strings.TrimSpace(rec.Body.String()))
			}
			if tc.wantStatus == http.StatusForbidden {
				if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
					t.Fatalf("Content-Type = %q, want application/json", got)
				}
				if !strings.Contains(rec.Body.String(), "cross-origin") {
					t.Fatalf("body = %q, want cross-origin rejection", strings.TrimSpace(rec.Body.String()))
				}
			}
		})
	}
}
