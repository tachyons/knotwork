# Review: CSRF protection branch (`fix/csrf-protection`)

Independent review of `280e27a`, `cdd9d8f`, `d38ec5d`. Verdict at review time:
**request changes**. Status below is the disposition after triage; nothing is
fixed yet unless checked.

## Critical

- [ ] **SCIM/MCP exemptions skip the check on cookie-authenticated routes.**
  `nonBrowserSurface` bypasses `/scim/v2/*` and `/api/mcp/*`, but both accept the
  session cookie via `RequireUser`/`RequireSCIM` → `UserFromRequest`. A same-site
  sibling origin sends the cookie and `Sec-Fetch-Site: same-site`, which the
  stdlib would reject and the exemption lets through.
  **Fix:** delete the path exemptions. Header-less non-browser clients already
  pass `CrossOriginProtection.Check`; the list only widens the hole. If a
  browser-based client must be supported, gate on `Authorization` presence or an
  explicit trusted origin, never on the path.
  Owner sign-off needed because issue #3 listed these exemptions.

## Required

- [ ] **403s lose the security headers.** `csrfMiddleware` wraps
  `securityHeaders`, so the rejection is written before they run. Move
  `securityHeaders` outermost in `Server.wrap` and update ARCHITECTURE.
- [ ] **Invalid `BaseURL` silently disables the trusted origin.**
  `AddTrustedOrigin` rejects URLs with a path, but `config.Load` accepts them.
  Parse the URL, pass `scheme://host`, and fail loudly instead of warning.
- [ ] **Trusted-origin/reverse-proxy path is untested.** Add a case with
  `req.Host = "internal:8080"` + `Origin: http://example.com`, and a
  non-matching origin expecting 403.
- [ ] **Table asserts handler statuses, not CSRF decisions.** Split into a
  middleware unit table over a stub handler (`wantRejected bool`), a
  `nonBrowserSurface` path table (if any exemptions survive), and two or three
  end-to-end cases. Reuse one server per table.
- [ ] **ARCHITECTURE claims SCIM/MCP are bearer-only.** They accept the session
  cookie; correct or remove with the Critical fix.

## Optional / Nit

- [ ] Call `Check` first and evaluate exemptions only on rejection; avoids
  parsing paths for every safe request.
- [ ] Rename `csrfMiddleware` → `crossOriginCheck` for consistency with
  `securityHeaders`/`recoverPanic`.
- [ ] Log the rejection reason (`Origin`, `Sec-Fetch-Site`) at debug.
- [ ] Move `authedCookie` next to `setupTestServer` in `ui_test.go`.
- [ ] Assert `Allow: POST` in `TestLogoutRejectsGET`.
- [ ] Scope the sign-out markup assertion to the logout form.
- [ ] `display: contents` → `display: inline` on `.logout-form`; add
  `.link-button:active { transform: none }` and a comment that unlayered CSS
  intentionally beats Oat's layered button styles.
- [ ] `gitengine.IsGitRequest` → `IsSmartHTTPRequest`, with a small test.

## Verified well

- `gitengine.IsGitRequest` reuses `parseGitRequest`, so the predicate cannot
  drift from the real routes.
- The explicit `GET /auth/logout` 405 route is necessary: without it the Git
  catch-all answers 404.
- Logout tests assert the session is still valid on GET and actually revoked on
  POST.
- Stdlib-only, no token plumbing, no new dependencies.
