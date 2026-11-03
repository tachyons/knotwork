package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

// newCrossOriginProtection builds the origin guard for browser requests. It
// rejects non-safe requests whose Origin or Sec-Fetch-Site header says they came
// from another site. Requests carrying neither header are non-browser clients
// (git, SCIM IdPs, federation peers, MCP clients) and pass through, so no
// per-route exemptions are needed.
func newCrossOriginProtection(baseURL string) (*http.CrossOriginProtection, error) {
	cop := http.NewCrossOriginProtection()
	if baseURL == "" {
		return cop, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL for CSRF trusted origin: %w", err)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("base URL must not include a path: %q", baseURL)
	}
	// Trust the configured public origin so reverse proxies that rewrite Host
	// do not turn legitimate same-origin requests into cross-origin ones.
	origin := u.Scheme + "://" + u.Host
	if err := cop.AddTrustedOrigin(origin); err != nil {
		return nil, fmt.Errorf("add CSRF trusted origin %q: %w", origin, err)
	}
	return cop, nil
}

// crossOriginCheck rejects cross-site browser requests before they reach a
// handler. Check returns nil for safe methods and for requests without
// Origin/Sec-Fetch-Site, so non-browser protocols pass without exemptions.
func crossOriginCheck(cop *http.CrossOriginProtection, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := cop.Check(r); err != nil {
			log.DebugContext(r.Context(), "cross-origin request rejected",
				"origin", r.Header.Get("Origin"),
				"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
				"error", err)
			writeError(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}
