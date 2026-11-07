package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

// errCrossOrigin is returned when a state-changing request presents an Origin
// header that matches neither the request host nor the configured public origin.
var errCrossOrigin = errors.New("origin does not match request host or trusted origin")

// crossOriginGuard enforces same-origin checks for state-changing requests.
//
// It wraps http.CrossOriginProtection, which returns early when Sec-Fetch-Site
// is "same-origin" or "none" without inspecting Origin. That is safe against a
// real browser, where Sec-Fetch-Site is a forbidden header, but a proxy or a
// non-browser client can rewrite it. When Origin is present this guard validates
// it independently against the request host and the configured public origin, so
// that combination cannot bypass the check.
type crossOriginGuard struct {
	cop           *http.CrossOriginProtection
	trustedOrigin string
}

// newCrossOriginProtection builds the origin guard for browser requests. It
// rejects non-safe requests whose Origin or Sec-Fetch-Site header says they came
// from another site. Requests carrying neither header are non-browser clients
// (git, SCIM IdPs, federation peers, MCP clients) and pass through, so no
// per-route exemptions are needed.
func newCrossOriginProtection(baseURL string) (*crossOriginGuard, error) {
	guard := &crossOriginGuard{cop: http.NewCrossOriginProtection()}
	if baseURL == "" {
		return guard, nil
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
	guard.trustedOrigin = u.Scheme + "://" + u.Host
	if err := guard.cop.AddTrustedOrigin(guard.trustedOrigin); err != nil {
		return nil, fmt.Errorf("add CSRF trusted origin %q: %w", guard.trustedOrigin, err)
	}
	return guard, nil
}

// Check validates Origin when present, then defers to the stdlib check for
// Sec-Fetch-Site. Safe methods are always allowed.
func (g *crossOriginGuard) Check(r *http.Request) error {
	if err := g.checkOrigin(r); err != nil {
		return err
	}
	return g.cop.Check(r)
}

func (g *crossOriginGuard) checkOrigin(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser client; the stdlib handles Sec-Fetch-Site when present.
		return nil
	}
	if origin == g.trustedOrigin {
		return nil
	}
	if u, err := url.Parse(origin); err == nil && u.Host == r.Host {
		return nil
	}
	return errCrossOrigin
}

// crossOriginCheck rejects cross-site browser requests before they reach a
// handler. Check returns nil for safe methods and for requests without
// Origin/Sec-Fetch-Site, so non-browser protocols pass without exemptions.
func crossOriginCheck(guard *crossOriginGuard, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := guard.Check(r); err != nil {
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
