# Review: CSRF protection branch (`fix/csrf-protection`)

Independent review of `280e27a`, `cdd9d8f`, `d38ec5d`. Verdict at review time:
**request changes**. All findings below are resolved in the follow-up commit.

## Critical

- [x] **SCIM/MCP exemptions skipped the check on cookie-authenticated routes.**
  `nonBrowserSurface` bypassed `/scim/v2/*` and `/api/mcp/*`, but both accept the
  session cookie via `RequireUser`/`RequireSCIM` → `UserFromRequest`. A same-site
  sibling origin sends the cookie and `Sec-Fetch-Site: same-site`, which the
  stdlib rejects and the exemption let through.
  **Fix applied:** all path exemptions removed, along with `nonBrowserSurface`
  and the `gitengine.IsGitRequest` export. Header-less non-browser clients already
  pass `CrossOriginProtection.Check`. Regression tests now assert 403 for
  cross-site SCIM, MCP, Git, inbox, and device-code POSTs.

## Required

- [x] **403s lost the security headers.** `securityHeaders` now wraps logging,
  panic recovery, and the origin check, so CSRF rejections and recovered panics
  carry `nosniff`/CSP/referrer headers. Panics are also logged with status 500.
- [x] **Invalid `BaseURL` silently disabled the trusted origin.** The origin is
  parsed to `scheme://host`, a path is rejected by both `config.Load` and the
  constructor, and `Server.Build` now returns an error that `serve` logs and
  exits on.
- [x] **Trusted-origin/reverse-proxy path is tested.** `TestCrossOriginCheck`
  covers `Host: internal:8080` + `Origin: http://example.com` (allowed) and a
  non-matching origin (403).
- [x] **Tests assert CSRF decisions, not handler statuses.** `TestCrossOriginCheck`
  is a unit table over a stub handler; `TestCrossOriginProtectionEndToEnd` keeps
  ten end-to-end cases on a single server, including header-less pass-through.
- [x] **ARCHITECTURE no longer claims SCIM/MCP are bearer-only.** The exemption
  list is gone and the wrapper order is corrected.

## Optional / Nit

- [x] `Check` runs first; there is no path parsing left on safe requests.
- [x] `csrfMiddleware` renamed to `crossOriginCheck`.
- [x] Rejections log `Origin`, `Sec-Fetch-Site`, and the stdlib error at debug.
- [x] `authedCookie` moved next to `setupTestServer` in `ui_test.go`.
- [x] `TestLogoutRejectsGET` asserts `Allow: POST`.
- [x] The sign-out markup assertion matches the exact form snippet and
  `link-button` submit.
- [x] `.logout-form` uses `display: inline`; `.link-button:active` resets Oat's
  press transform; a comment records the unlayered-vs-layered override.
- [x] `gitengine.IsGitRequest` deleted rather than renamed, since no caller
  remains.

## Verified well

- The explicit `GET /auth/logout` 405 route is necessary: without it the Git
  catch-all answers 404.
- Logout tests assert the session is still valid on GET and actually revoked on
  POST.
- Stdlib-only, no token plumbing, no new dependencies.
