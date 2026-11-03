package web

import (
	"log/slog"
	"net/http"
	"strings"

	"knotwork/internal/gitengine"
)

// newCrossOriginProtection builds the origin guard for browser requests. It
// rejects state-changing requests whose Origin or Sec-Fetch-Site header says
// they came from another site. Requests carrying neither header are assumed to
// be non-browser clients and pass through, which covers git, SCIM IdPs,
// federation peers, and MCP clients.
func newCrossOriginProtection(baseURL string, log *slog.Logger) *http.CrossOriginProtection {
	cop := http.NewCrossOriginProtection()
	if baseURL == "" {
		return cop
	}
	// Trust the configured public origin so reverse proxies that rewrite Host
	// do not turn legitimate same-origin requests into cross-origin ones.
	if err := cop.AddTrustedOrigin(baseURL); err != nil {
		log.Warn("ignoring base URL as CSRF trusted origin", "base_url", baseURL, "error", err)
	}
	return cop
}

// csrfMiddleware applies the origin check to every request that is not part of
// a non-browser protocol surface.
func csrfMiddleware(cop *http.CrossOriginProtection, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !nonBrowserSurface(r) {
			if err := cop.Check(r); err != nil {
				writeError(w, http.StatusForbidden, "cross-origin request rejected")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// nonBrowserSurface reports whether r belongs to a protocol whose clients never
// send browser origin headers. These surfaces authenticate with bearer tokens,
// HTTP Basic, HTTP signatures, or their own credentials, so origin checks do not
// apply. The predicate reuses the Git router's parser instead of matching paths
// by hand, because `/{owner}/{repo}.git/...` is not expressible as a ServeMux
// pattern.
func nonBrowserSurface(r *http.Request) bool {
	if gitengine.IsGitRequest(r) {
		return true
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/scim/v2/"):
		return true
	case strings.HasPrefix(p, "/api/mcp/"):
		return true
	case p == "/inbox":
		return true
	case p == "/auth/device/code", p == "/auth/device/token":
		return true
	}
	return false
}
