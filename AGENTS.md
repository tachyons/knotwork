# AGENTS.md

Knotwork is a single-node Git collaboration server in Go with a vanilla
TypeScript UI. Module path is `knotwork`; the binary and CLI are `knotwork`.

## Product and engineering principles

- Optimize for solo developers and small organizations (under 100 users). One
  binary, SQLite, and local disk are the default; PostgreSQL, S3, federation,
  SCIM, apps, and MCP are opt-in. Do not add mandatory services or daemons.
- Performance is a feature. Measure before optimizing; avoid N+1 queries,
  paginate unbounded lists, lazy-load heavy assets, and keep first-load JS
  within budget. Regressions are bugs.
- Standard library first. Use a maintained, well-established library only when
  stdlib is insufficient; never hand-roll protocols, crypto, or parsers.
- Less is more. Every surface needs an owner, docs, and tests. Hide disabled
  features instead of shipping dead links; delete code that does not earn its
  keep.
- Apps and agents are first-class actors. Give them scoped credentials, audit
  trails, attribution in the UI, and server-rendered integration surfaces. MCP
  is the primary agent interface; keep it scoped and documented.
- Storage is an interface. New relational code goes behind domain-scoped store
  interfaces with per-dialect SQL; new Git access goes behind
  `gitengine.Storage`. Do not assume `Repository.DiskPath` in new code.
- No third-party JavaScript in the Knotwork origin. Integrate through webhooks,
  server-rendered status, and outbound links; the CSP allows only the Vite
  bundle.

## Verified commands

Toolchains are pinned in `.mise.toml`; run them through `mise exec -- ...` or
through the Makefile (`make help` lists targets). `make setup` installs the
toolchains and frontend dependencies and enables the committed `.githooks`.

```sh
make check                            # fmt-check, tidy-check, vet, lint, test, web-check
make ci                               # check + race/shuffled tests (same gate as CI)
make vuln                             # govulncheck ./...
make build                            # web bundle + bin/knotwork
make run                              # go run ./cmd/knotwork serve
```

Individual commands:

```sh
mise exec -- go build ./...
mise exec -- go test ./...
mise exec -- go test ./internal/ci -run TestParse -v   # single test
mise exec -- go vet ./...
mise exec -- golangci-lint run ./...
mise exec -- golangci-lint fmt         # gofumpt + goimports
mise exec -- govulncheck ./...
```

Frontend (from `frontend/`):

```sh
mise exec -- pnpm install
mise exec -- pnpm run check   # tsc --noEmit + biome check
mise exec -- pnpm run lint:fix
mise exec -- pnpm run build   # check, then vite build into internal/web/static
```

`pnpm run build` writes `internal/web/static/{app.js,app.css,chunks/}`, which is
committed because `internal/web/static.go` embeds it with `go:embed`. Rebuild
the frontend before `go build` if assets changed; plain `go build ./...` still
works from a clean checkout because the output is committed. CI rebuilds the
bundle and fails if the committed output is stale.

## Layout

- `cmd/knotwork/` — `serve`, `admin`, `auth login`, `hook`, and `mcp` entrypoints.
- `internal/domain` — dependency-free entities/constants.
- `internal/database` — store and embedded migrations (`0001_init.sql`).
- `internal/auth` — OIDC, sessions, JWTs, device flow, SCIM, break-glass.
- `internal/gitengine` — bare repos, hooks, hook IPC, Smart HTTP, browsing.
- `internal/federation` — signatures, allowlisted inbox, ForgeFed.
- `internal/ci` — parser, Docker runner, log hub, executor.
- `internal/backup` — git bundles and database snapshots.
- `internal/mcp`, `internal/manifest` — MCP server and app manifests.
- `internal/web` — router, JSON API, HTML templates, static assets.
- `frontend/` — Oat CSS, `@pierre/trees`, `@pierre/diffs`, `@pierre/highlights`.
- `.golangci.yml`, `frontend/biome.json` — lint/format configuration.
- `.githooks/` — pre-commit and pre-push gates (enabled by `make setup`).
- `.github/workflows/ci.yml` — CI mirror of `make ci` plus bundle freshness.

`docs/SRS.md` is authoritative; `docs/ARCHITECTURE.md` maps request flows.

## Quirks

- Environment variables are `KNOTWORK_*`. `KNOTWORK_DATA_DIR`, not `DATA_DIR`.
- OIDC is disabled until issuer, client ID, and secret are all set; `/auth/login`
  then returns 503. There is no password login by design.
- Git Smart HTTP is registered as catch-all `GET /` and `POST /` in
  `internal/web/server.go` because `/{owner}/{repo}.git/...` cannot coexist with
  other two-segment mux patterns. `gitengine.parseGitRequest` filters them.
- The daemon must own the Unix socket at `KNOTWORK_SOCKET_PATH`; generated hook
  scripts exec `knotwork hook <kind>`. Hooks fail closed if it is missing.
- `git http-backend` is invoked through `net/http/cgi`; `gitengine.NewManager`
  resolves `git` to an absolute path because CGI does not search `PATH`.
- SQLite uses `MaxOpenConns(1)` plus WAL. `database.Open` creates the parent
  directory for file-backed SQLite.
- CI config prefers `.knotwork-ci.yml` and falls back to `.forge-ci.yml`.
- Federation accepts only allowlisted peers with valid Ed25519 HTTP signatures.
- pnpm 12 needs `frontend/pnpm-workspace.yaml` (`allowBuilds: esbuild`) and
  `minimumReleaseAge: 0` because `@knadh/oat` releases frequently.
- The web bundle includes all Shiki language chunks (~12 MB). Initial JS is
  `app.js`; language chunks load on demand.
- Templates are Go `html/template` sets built by `newPage` in
  `internal/web/templates.go`; each page supplies a `content` block.
- Do not add inline styles/scripts to templates; the CSP allows only
  same-origin scripts and the Vite bundle.
