# Knotwork

[![CI](https://github.com/tachyons/knotwork/actions/workflows/ci.yml/badge.svg)](https://github.com/tachyons/knotwork/actions/workflows/ci.yml)

Knotwork is a single-node, self-hosted Git collaboration server. It combines
OIDC-only authentication, Git Smart HTTP, merge requests, embedded Docker CI,
SCIM provisioning, S3 backups, an MCP endpoint, and opt-in ForgeFed federation
in one Go binary.

The original project name was ForgeLite. A few compatibility inputs still accept
the old spelling: the CI loader reads `.forge-ci.yml` when
`.knotwork-ci.yml` is absent, and MCP resources accept `forge://` URIs.

## Requirements

- [mise](https://mise.jdx.dev/) (pins Go, Node, pnpm, and golangci-lint)
- Git
- Docker, only if you run pipelines

## Quick start

```sh
mise install

# Build the web UI, then the server and CLI.
make build

# Point the daemon at a writable directory and an OIDC provider.
export KNOTWORK_BASE_URL=http://localhost:8080
export KNOTWORK_DATA_DIR=./data
export KNOTWORK_OIDC_ISSUER=https://accounts.example.com
export KNOTWORK_OIDC_CLIENT_ID=knotwork
export KNOTWORK_OIDC_CLIENT_SECRET=...
export KNOTWORK_ADMIN_EMAILS=you@example.com

./bin/knotwork serve
```

On first boot the daemon prints a setup URL. Visit it, complete the OIDC flow,
and the first administrator claims the instance. Passwords are never stored or
accepted.

A full list of environment variables is in `.env.example`. Notable defaults:

| Variable | Default | Purpose |
| --- | --- | --- |
| `KNOTWORK_ADDR` | `:8080` | Listen address |
| `KNOTWORK_DATABASE_URL` | `sqlite://./data/knotwork.db` | SQLite, or `postgres://...` |
| `KNOTWORK_REPO_ROOT` | `./data/repos` | Bare repository storage |
| `KNOTWORK_SOCKET_PATH` | `/tmp/knotwork-internal.sock` | Git hook ↔ daemon IPC |
| `KNOTWORK_BACKUP_INTERVAL` | `6h` | Database snapshot cadence |
| `KNOTWORK_BUNDLE_DEBOUNCE` | `30s` | Per-repository bundle debounce |

## CLI

```sh
knotwork serve                        # run the daemon
knotwork status                       # print instance counters

knotwork auth login                   # device-flow Git credential
knotwork admin grant-role --email ... --role admin
knotwork admin break-glass --email ... --duration 15m
knotwork admin revoke-sessions [--email ...]
knotwork admin scim-token --email ...
knotwork admin peers list|add|remove
knotwork mcp                          # stdio MCP; requires KNOTWORK_MCP_TOKEN
```

`break-glass` prints a single-use emergency URL. It only works for an existing
administrator and expires after the requested duration.

MCP is opt-in on the existing server. It is not a separate service. Streamable
HTTP is `POST /api/mcp` with the same API token as the API, sent as
`Authorization: Bearer` or as HTTP Basic (the password, or the username when
the password is empty). `GET /api/mcp/sse` and `POST /api/mcp/messages` remain
for legacy SSE clients. Local stdio is `KNOTWORK_MCP_TOKEN=... knotwork mcp`.
The token is an existing device-flow bearer or instance JWT. stdout is the
protocol stream. Protected-resource metadata is at
`/.well-known/oauth-protected-resource/api/mcp`. MCP HTTP requests use the
server request log: the response carries `X-Request-ID` and the access line
records it as `req_id`.

## Git

Clone URLs are ordinary HTTPS remotes:

```sh
git clone http://localhost:8080/alice/demo.git
```

Authenticate with a personal access token from the device flow:

```sh
knotwork auth login
git clone http://localhost:8080/alice/demo.git
```

Branch protection is enforced in the `pre-receive` hook. Hooks talk to the
daemon over a Unix socket, so they never open SQLite or PostgreSQL directly.
The hook fails closed when the socket is unavailable.

## Pipelines

Commit a `.knotwork-ci.yml` file to opt in:

```yaml
stages: [test, build]

unit:
  stage: test
  image: golang:1.27
  script:
    - go test ./...

build:
  stage: build
  image: golang:1.27
  script:
    - go build ./...
```

Jobs run in ephemeral Docker containers with bridge networking. Federated merge
requests create an approval-gated pipeline; an authorized maintainer must
approve before any container starts.

## Development

Toolchains are pinned in `.mise.toml`. `make setup` installs them, installs the
frontend dependencies, and enables the committed git hooks. `make help` lists
every target.

```sh
make setup                # mise install + pnpm install + git hooks
make check                # fmt, tidy, vet, lint, tests, frontend checks
make ci                   # full gate: check + race/shuffled tests
make vuln                 # govulncheck
make build                # web bundle + bin/knotwork
make run                  # go run ./cmd/knotwork serve
```

The pre-commit hook lints staged Go and frontend files; the pre-push hook runs
the full test suite, `golangci-lint`, and the frontend checks. Go code is
formatted with `gofumpt` and `goimports` through `golangci-lint`:

```sh
make fmt                  # apply formatting
make fmt-check            # fail if formatting is stale
make lint-fix             # apply safe lint fixes
```

Frontend commands (from `frontend/`):

```sh
pnpm dev                  # Vite dev server
pnpm run check            # tsc --noEmit + biome check
pnpm run lint:fix         # apply Biome fixes
pnpm run build            # run check, then emit into internal/web/static
```

GitHub Actions (`.github/workflows/ci.yml`) runs the same gate on every push
and pull request: formatting, `go.mod` tidiness, vet, `golangci-lint`,
`govulncheck`, race-enabled tests, frontend type-check/lint, and a check that
the committed `internal/web/static` bundle matches the current frontend
sources.

The frontend is vanilla TypeScript with Vite. It uses [Oat](https://oat.ink)
for semantic CSS, [`@pierre/trees`](https://trees.software) for the file tree,
and [`@pierre/diffs`](https://diffs.com) with
[`@pierre/highlights`](https://diffs.com/highlights) for diffs and code viewing.
Built assets are embedded with `go:embed`, so `go build` works without Node once
`internal/web/static` exists.

## Layout

```
cmd/knotwork/          serve, admin, auth, and hook entrypoints
internal/domain/       dependency-free entities and state constants
internal/database/     SQLite/PostgreSQL store and embedded migrations
internal/auth/         OIDC, sessions, Ed25519 JWTs, device flow, SCIM
internal/gitengine/    bare repos, Smart HTTP, hook IPC, tree/blob/diff reads
internal/federation/   HTTP signatures, allowlisted inbox, ForgeFed activities
internal/ci/           pipeline parser, Docker runner, log hub, executor
internal/backup/       debounced git bundles and compressed DB snapshots
internal/mcp/          MCP Streamable HTTP, legacy SSE, and stdio
internal/web/          HTML UI, JSON API, embedded static assets
frontend/              Oat + Pierre UI source
docs/SRS.md            authoritative specification
docs/ARCHITECTURE.md   implementation map and request flows
```

## Security model

- OIDC is the only interactive login path. A partial OIDC configuration refuses
  to start rather than silently disabling authentication.
- Web sessions and CLI tokens are stored as SHA-256 hashes. Instance JWTs are
  Ed25519-signed.
- Federation is deny-by-default: only peers marked `allowlisted` are ingested,
  and every inbox request must carry a valid HTTP signature and fresh digest.
- Git Smart HTTP is HTTPS-only in production; set `KNOTWORK_TLS_CERT`/`KEY` or
  terminate TLS at a reverse proxy.
- Backups go to S3-compatible storage or local disk; database snapshots use
  `VACUUM INTO` for SQLite and `pg_dump` for PostgreSQL.

See `docs/SRS.md` for the full requirements and `docs/ARCHITECTURE.md` for how
the packages fit together.
