# Implementation Plan: CSRF Protection & Strict State Mutation Security (#3)

## Overview

Knotwork's HTTP surface has no origin/CSRF check today. `Server.wrap`
(`internal/web/server.go:82`) applies only panic recovery, request logging, and
security headers. The sole defense is `SameSite=Lax` on the session cookie, which
does not cover navigation-triggered state changes (e.g. `GET /auth/logout`) and is
a browser-side setting we do not control.

This plan adds origin-based CSRF protection across the whole mux using the Go
stdlib `net/http.CrossOriginProtection` (Go 1.27 is pinned in `go.mod`, the type
landed in Go 1.25), removes the one state-changing GET, and locks the behaviour in
with table-driven tests. No new dependencies, no token plumbing, no store changes.

Scope is issue #3's first slice: middleware + sign-out + tests + docs. Token-based
CSRF (double-submit/synchronizer) is deliberately replaced by stdlib origin checks,
per the owner's note on the issue.

## Architecture Decisions

1. **Use `http.CrossOriginProtection`, not a token scheme.** The owner's issue
   comment directs this: no dependency, no token plumbing in templates/JS. It
   validates `Origin` / `Sec-Fetch-Site` on unsafe methods and allows requests with
   neither header (Git CLI, IdPs, federation peers, MCP clients).
2. **Wrap once, in `Server.wrap`, before the router.** One choke point means every
   route added later — including the #6/#35/#36 work — inherits protection. The
   wrapper order is `securityHeaders → logging → recoverPanic → crossOriginCheck →
   mux`, so rejections and recovered panics still carry security headers.
3. **No route exemptions; rely on header-less pass-through.** ServeMux wildcards
   cannot express `/{owner}/{repo}.git/`, and every candidate exemption
   (`/scim/v2/`, `/api/mcp/`, `/inbox`, device flow) also accepts the session
   cookie, so a path allowlist would have skipped the check on cookie-authenticated
   routes. `CrossOriginProtection.Check` already allows requests with neither
   `Origin` nor `Sec-Fetch-Site`, which is exactly how git, SCIM IdPs, federation
   peers, and MCP clients connect. *(Revised after review; an earlier revision
   added a `nonBrowserSurface` predicate and `gitengine.IsGitRequest`.)*
4. **Construct the trusted origin from `scheme://host` and fail at startup.** A
   `BaseURL` with a path is rejected by `config.Load` and by the constructor, so
   `Server.Build` returns an error instead of logging a warning and continuing
   without the trusted origin.
5. **Trust `Cfg.BaseURL` as an origin.** `AddTrustedOrigin(cfg.BaseURL)` keeps
   same-origin browser requests working when a reverse proxy rewrites `Host`.
6. **Keep `Secure` cookie derivation on `Cfg.BaseURL`.** `secure()`
   (`internal/auth/service.go:275`) currently uses the scheme of the configured
   public base URL. Honouring `X-Forwarded-Proto` without a trusted-proxy config is
   spoofable and adds config surface; `BaseURL` is already required and authoritative
   for OIDC redirects. This deviates from issue AC #3 and is documented in the SRS
   note. **Confirmed by owner (2026-11-03): `BaseURL` only, no trusted-proxy flag.**
7. **Sign-out becomes POST-only.** `GET /auth/logout` mutates state and is reachable
   by navigation, which `CrossOriginProtection` cannot cover (GET is a safe method).
   **Confirmed by owner (2026-11-03): hard 405, no compatibility shim.**

## Task List

### Phase 1: Origin protection middleware

- [ ] Task 1: Add CSRF middleware and wire it into `Server.wrap`
- [ ] Task 2: Table-driven tests for the middleware matrix

### Checkpoint: Middleware
- [ ] `mise exec -- go test ./internal/web ./internal/gitengine` passes
- [ ] Manual curl matrix: cross-site POST → 403, same-origin → normal, no headers → normal
- [ ] No new module in `go.mod` / `go.sum`

### Phase 2: Remove the state-changing GET

- [ ] Task 3: Make sign-out a POST form
- [ ] Task 4: Tests for sign-out method and cookie clearing

### Checkpoint: Sign-out
- [ ] `GET /auth/logout` → 405; same-origin `POST` → 302 + session deleted
- [ ] Frontend bundle rebuilt and committed (`internal/web/static`)
- [ ] Browser check: sign out from the nav works, no CSP violations

### Phase 3: Documentation and closeout

- [ ] Task 5: Document the CSRF model in SRS and ARCHITECTURE
- [ ] Task 6: Final gate and issue update draft

### Checkpoint: Complete
- [ ] `make check` and `make ci` pass
- [ ] `make vuln` reports no new findings
- [ ] Every acceptance criterion in issue #3 is met or explicitly deferred in writing

## Tasks

### Task 1: Add CSRF middleware and wire it into `Server.wrap`

**Description:** Add `internal/web/csrf.go` containing `newCrossOriginProtection`
(trusted origin from `Cfg.BaseURL`, returning an error on a bad URL) and
`crossOriginCheck(cop, log, next)` which calls `cop.Check(r)` and rejects with the
existing `writeError(w, 403, "cross-origin request rejected")` shape so API
clients get JSON. Wire it into `wrap()` inside panic recovery, with security
headers outermost.

No skip list: `CrossOriginProtection.Check` already passes requests with neither
`Origin` nor `Sec-Fetch-Site`, which covers Git Smart HTTP, SCIM, MCP, `/inbox`,
and the device flow.

**Acceptance criteria:**
- [ ] Cross-site browser POST/PUT/DELETE/PATCH is rejected with 403 JSON
- [ ] Same-origin browser requests are unaffected
- [ ] Requests with neither `Origin` nor `Sec-Fetch-Site` are unaffected, so no
  route needs an exemption
- [ ] `GET`/`HEAD`/`OPTIONS` are never rejected
- [ ] No new dependency; `go.mod`/`go.sum` unchanged

**Verification:**
- [ ] `mise exec -- go build ./...`
- [ ] `mise exec -- go vet ./...`
- [ ] `mise exec -- go test ./internal/web ./internal/gitengine`
- [ ] Manual: `curl -X POST -H 'Origin: https://evil.example' localhost:8080/api/repos` → 403

**Dependencies:** None

**Files likely touched:**
- `internal/web/csrf.go` (new)
- `internal/web/server.go`

**Estimated scope:** Small (3 files)

---

### Task 2: Table-driven tests for the middleware matrix

**Description:** Add `internal/web/csrf_test.go` using the existing
`setupTestServer` harness. Cover the full matrix so a future route addition cannot
silently regress protection.

Cases: same-origin `Origin`; cross-site `Origin`; `Sec-Fetch-Site: same-origin`;
`Sec-Fetch-Site: cross-site`; no headers; safe method with cross-site `Origin`;
header-less pass-through on SCIM, Git, and device flow; authenticated same-origin
`POST /api/repos` still succeeds.

**Acceptance criteria:**
- [ ] Every matrix row asserts an exact status code, not just "not 403"
- [ ] Exemption cases assert the request reached the handler (e.g. 400/401/404), proving the skip works
- [ ] Test fails if the middleware is removed from `wrap()`

**Verification:**
- [ ] `mise exec -- go test ./internal/web -run TestCSRF -v`
- [ ] Mutation check: comment out the middleware, confirm tests fail, restore

**Dependencies:** Task 1

**Files likely touched:**
- `internal/web/csrf_test.go` (new)

**Estimated scope:** Small (1 file)

---

### Task 3: Make sign-out a POST form

**Description:** Remove the `GET /auth/logout` route in
`internal/auth/service.go:65`, keep `POST`. Replace the nav anchor at
`internal/web/templates.go:56` with a small form posting to `/auth/logout`
containing a submit button styled as a link (`.link-button` in
`frontend/src/styles.css` if Oat has no equivalent). Rebuild the committed bundle.

**Acceptance criteria:**
- [ ] `GET /auth/logout` returns 405 and does not delete a session
- [ ] Same-origin `POST /auth/logout` deletes the session, clears the cookie, and 302s to `/`
- [ ] Cross-site `POST /auth/logout` is rejected with 403
- [ ] Nav still reads "Sign out" and is keyboard-accessible
- [ ] No inline styles/scripts; CSP unchanged

**Verification:**
- [ ] `mise exec -- go test ./internal/web ./internal/auth`
- [ ] `mise exec -- pnpm --dir frontend run build` then `git status` shows refreshed `internal/web/static`
- [ ] Manual: sign out in the browser, confirm redirect and cleared cookie

**Dependencies:** Task 1 (middleware must protect the new POST)

**Files likely touched:**
- `internal/auth/service.go`
- `internal/web/templates.go`
- `frontend/src/styles.css`
- `internal/web/static/*` (generated)

**Estimated scope:** Small (4 files, one generated)

---

### Task 4: Tests for sign-out method and cookie clearing

**Description:** Extend the web/auth tests: 405 on GET, 302 + `Max-Age=0` cookie on
POST, and 403 for cross-site POST. Assert the nav no longer emits an
`<a href="/auth/logout">`.

**Acceptance criteria:**
- [ ] All three behaviours asserted
- [ ] Session row is gone after a successful POST (check via `DB`)

**Verification:**
- [ ] `mise exec -- go test ./internal/web ./internal/auth -run 'Logout|CSRF' -v`

**Dependencies:** Task 3

**Files likely touched:**
- `internal/web/csrf_test.go` or `internal/web/ui_test.go`

**Estimated scope:** Small (1 file)

---

### Task 5: Document the CSRF model in SRS and ARCHITECTURE

**Description:** Add a bullet to SRS §6.2 stating that browser-originated
state-changing requests must pass same-origin validation and that header-less
requests are treated as non-browser clients. Add the middleware chain to
ARCHITECTURE's request-flow section, noting that no route is exempt because
header-less clients pass.

**Acceptance criteria:**
- [ ] SRS §6.2 names the enforcement point and the header-less pass-through rule
- [ ] ARCHITECTURE shows `securityHeaders → logging → recoverPanic → crossOriginCheck → mux`
- [ ] The `BaseURL` vs `X-Forwarded-Proto` decision is recorded

**Verification:**
- [ ] Read both diffs; no stale claims about token-based CSRF

**Dependencies:** Tasks 1–4

**Files likely touched:**
- `docs/SRS.md`
- `docs/ARCHITECTURE.md`

**Estimated scope:** Extra small (2 files)

---

### Task 6: Final gate and issue update draft

**Description:** Run the full gate, then draft (do not post) a comment for issue #3
listing what shipped and the two deviations: stdlib origin checks instead of tokens,
and `Secure` derived from `BaseURL` rather than `X-Forwarded-Proto`. Posting
requires explicit owner permission.

**Acceptance criteria:**
- [ ] `make check`, `make ci`, and `make vuln` pass
- [ ] Draft comment covers every AC in #3 with met/deferred status
- [ ] No push, no issue comment, no PR without explicit permission

**Verification:**
- [ ] Paste gate output in the draft comment
- [ ] Confirm `git status` is clean apart from intended files

**Dependencies:** Tasks 1–5

**Files likely touched:** none (draft in chat)

**Estimated scope:** Extra small

## Out of Scope

- Double-submit cookie / synchronizer token plumbing (replaced by decision 1).
- `GET /auth/break-glass` and `GET /setup`: state-changing, but gated by
  single-use unguessable tokens; converting them would break the documented
  bootstrap journeys. Revisit if tokens ever become guessable or reusable.
- Per-origin allowlists for third-party browser clients (e.g. browser-based MCP or
  Git tooling). `AddTrustedOrigin` is the extension point if that becomes a need.
- Rate limiting, session rotation, and the SCIM token TTL bug (tracked in #35).

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| ServeMux bypass pattern for `*.git/` is impossible (verified panic) | Med | No exemptions at all: `Check` passes header-less clients, so no predicate or pattern is needed |
| Proxy rewrites `Host`, blocking legitimate browser POSTs | Med | `AddTrustedOrigin(Cfg.BaseURL)`; tested with `Origin` = BaseURL and `Host` = internal |
| Browser-based MCP/Git clients send an `Origin` header and get rejected | Low | Non-browser clients send no headers and pass; browser clients can be added as trusted origins |
| Bundle drift after CSS change | Med | Rebuild in Task 3 and rely on CI's bundle-freshness check |
| `Secure` flag stays wrong behind TLS-terminating proxies | Low | Decision 6 + SRS note; revisit with a `KNOTWORK_TRUST_PROXY` flag if demanded |

## Open Questions

1. ~~Confirm the stdlib substitution for AC #1/#4.~~ **Resolved:** stdlib
   `CrossOriginProtection`; no double-submit/synchronizer token.
2. ~~`Secure` cookie source.~~ **Resolved:** `Cfg.BaseURL` only.
3. ~~`GET /auth/logout` behaviour.~~ **Resolved:** hard 405.
4. **Task tracking:** default is `tasks/todo.md`. Say the word if you want these as
   GitHub sub-issues under #3 instead.

## Status

Implemented 2026-11-03 on `fix/csrf-protection`:

- `280e27a` — origin protection middleware + test matrix (Tasks 1–2)
- `cdd9d8f` — POST-only sign-out (Tasks 3–4)
- `d38ec5d` — docs and task closeout (Tasks 5–6)
- follow-up — review fixes: exemptions removed, headers outermost, `Build`
  returns an error, tests split (see `tasks/review.md`)

`make check`, `make ci` (race + shuffled), and `make vuln` pass. The issue #3
comment is drafted but **not posted**; pushing or commenting needs explicit
permission.

## Definition of Done

- `make check` and `make ci` pass; `make vuln` clean.
- No new dependencies; no inline scripts/styles; CSP untouched.
- Tests cover cross-site rejection, same-origin pass-through, header-less
  pass-through on each non-browser surface, and sign-out.
- Docs updated; issue #3 ACs met or explicitly deferred in writing.
- Committed frontend bundle matches source.
