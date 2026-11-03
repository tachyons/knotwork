# Todo: CSRF Protection & Strict State Mutation Security (#3)

Plan: `tasks/plan.md`

## Phase 1: Origin protection middleware

- [x] **Task 1** — Add `internal/web/csrf.go` (`newCrossOriginProtection`, `csrfMiddleware`, `nonBrowserSurface`), export `gitengine.IsGitRequest`, wire into `Server.wrap` (`280e27a`)
- [x] **Task 2** — Table-driven `internal/web/csrf_test.go` covering same-origin, cross-site, `Sec-Fetch-Site`, header-less, safe methods, all exemptions

## Checkpoint: Middleware

- [x] `mise exec -- go test ./internal/web ./internal/gitengine`
- [x] Manual curl matrix (cross-site → 403, same-origin → normal, no headers → normal) — covered by `TestCrossOriginProtection`
- [x] `go.mod`/`go.sum` unchanged

## Phase 2: Remove the state-changing GET

- [x] **Task 3** — Drop `GET /auth/logout`; nav becomes a POST form; `.link-button` CSS; rebuild bundle (`cdd9d8f`)
- [x] **Task 4** — Tests: GET → 405, same-origin POST → 302 + cleared cookie + session deleted, cross-site POST → 403

## Checkpoint: Sign-out

- [x] `mise exec -- go test ./internal/web ./internal/auth`
- [x] `mise exec -- pnpm --dir frontend run build`; `internal/web/static` committed
- [x] Browser: sign out works, no CSP violations — verified end-to-end over HTTP against a live server with `bunx oauth2-mock-server` (OIDC login → POST sign-out → 401 on replay); no Chrome DevTools MCP was available for a click-through

## Phase 3: Documentation and closeout

- [x] **Task 5** — SRS §6.2 bullet + ARCHITECTURE request pipeline + `BaseURL`/XFP decision
- [x] **Task 6** — `make check`, `make ci`, `make vuln` all pass; #3 comment drafted (not posted)

## Checkpoint: Complete

- [x] Every issue #3 acceptance criterion met or explicitly deferred in writing
- [x] No push / issue comment / PR without explicit permission
