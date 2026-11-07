# Architecture

Knotwork is a modular monolith. One Go process owns HTTP, Git, CI orchestration,
backups, and federation; the packages below are adapters around a small domain
core. There is no message broker and no second service to deploy.

## Package map

| Package | Responsibility |
| --- | --- |
| `internal/domain` | Entities and state constants. Imports nothing from the app. |
| `internal/config` | Environment loading and validation. |
| `internal/database` | `database/sql` store, migrations, SQLite/PostgreSQL rebinding. |
| `internal/auth` | OIDC, sessions, Ed25519 JWTs, device flow, SCIM, break-glass. |
| `internal/gitengine` | Bare repositories, hooks, hook IPC, Smart HTTP, tree/blob/diff. |
| `internal/federation` | HTTP signatures, allowlisted inbox, ForgeFed activities. |
| `internal/ci` | Pipeline parser, Docker runner, log hub, executor. |
| `internal/backup` | Debounced `git bundle` and compressed database snapshots. |
| `internal/mcp` | MCP server over SSE with tools and resources. |
| `internal/manifest` | Third-party app manifest validation and webhook signing. |
| `internal/web` | Router, HTML pages, JSON API, embedded static assets. |
| `cmd/knotwork` | `serve`, `admin`, `auth`, and `hook` commands. |

Dependency direction is inward: `web` and `cmd` depend on adapters, adapters
depend on `domain`, and `domain` depends on nothing.

## Startup

`knotwork serve`:

1. Loads configuration from `KNOTWORK_*` variables and validates OIDC plus TLS.
2. Creates the data directory and opens SQLite (WAL, single writer) or
   PostgreSQL (20 connections).
3. Applies embedded migrations in filename order.
4. Loads or creates `data/instance.key` (Ed25519).
5. Builds the bare-repository manager and starts the hook Unix socket.
6. Starts the backup manager and auth service.
7. Registers routes and serves HTTP(S).

SQLite uses `MaxOpenConns(1)` to avoid `SQLITE_BUSY`; WAL still permits
concurrent readers from the CLI and backup jobs. Queries are written with `?`
and rebound to `$1` for PostgreSQL.

## Authentication

Interactive login is OIDC authorization-code + PKCE + nonce. The callback
provisions the user just-in-time; the first user becomes the instance admin.
Configured `KNOTWORK_ADMIN_EMAILS` always resolve to admin. Sessions are random
tokens stored as SHA-256 hashes with an expiry and revocation timestamp.

CLI access uses a device flow. `knotwork auth login` requests a code, opens
`/auth/device`, and polls `/auth/device/token`; on approval it stores a bearer
token with `git credential approve`. Bearer tokens are Ed25519 JWTs for API and
Git use, or opaque session tokens for SCIM.

`knotwork admin break-glass` mints a single-use session URL for an existing
admin. SCIM authenticates through the same `UserFromRequest` resolver as the
API, so it accepts bearer tokens and session cookies; deactivation
(`active: false` or `DELETE`) revokes every live session immediately.

## Request pipeline

Every route is wrapped once in `Server.wrap`: security headers, structured
request logging, panic recovery, then CSRF protection. CSRF protection uses the
stdlib `net/http.CrossOriginProtection`, which rejects every non-safe method
(`POST`, `PUT`, `PATCH`, `DELETE`, ...) when `Origin` or `Sec-Fetch-Site` says the
request came from another site. The stdlib trusts `Sec-Fetch-Site: same-origin`
and returns early, so Knotwork validates a present `Origin` header itself against
the request host or the configured public origin; a rewritten fetch-metadata
header cannot bypass the check. Requests carrying neither header are non-browser
clients — git, SCIM IdPs, federation peers, MCP clients — and pass, so no route
needs an exemption.

`Cfg.BaseURL` is registered as a trusted origin so reverse proxies that rewrite
`Host` do not break same-origin form posts. `KNOTWORK_BASE_URL` must be an origin
without a path; a path is rejected at startup because the router is mounted at
the root.

Sign-out is `POST /auth/logout` only; `GET` returns 405 because origin checks
cannot cover navigation-triggered state changes. Session cookies are `HttpOnly`,
`SameSite=Lax`, and `Secure` when `Cfg.BaseURL` is HTTPS.

## Git path

Repositories are bare directories under `KNOTWORK_REPO_ROOT`, addressed as
`owner/name.git`. The Smart HTTP handler delegates to `git http-backend` through
`net/http/cgi`, so request and response bodies stream and pushes never land in
server memory or temporary files.

Because clone URLs live at the site root, Git routes are catch-all `GET /` and
`POST /` handlers that parse `/{owner}/{repo}.git/{endpoint}` and return 404 for
unrelated paths. Exact UI and API patterns remain more specific in `ServeMux`.

Authorization:

- Writes require a session/JWT with `write` or `admin` repository role.
- Private reads require any role on the repository.
- Public reads are anonymous but still carry identity when present.

`git init --bare` installs `pre-receive` and `post-receive` hooks. Each hook
runs `knotwork hook <kind>`, which sends JSON to a Unix socket owned by the
daemon. `pre-receive` rejects protected-branch pushes from non-admins, branch
deletion, and non-fast-forward updates. It fails closed when the daemon is
unreachable. `post-receive` triggers the backup debounce and creates pipelines
for updated branches.

`gitengine.ListTree`, `ReadBlob`, and `DiffRange` back the UI. Refs and paths are
validated before use, and blobs are capped at 1 MiB before being sent to the
browser. The UI tree comes from `git ls-tree`; file contents come from
`git show <ref>:<path>`.

## Merge requests and CI

Merge requests are stored in `merge_requests`, numbered per target repository.
Federated offers create a row, fetch the source branch into
`refs/federated/mr/<n>`, and create a `pending_approval` pipeline.

The executor:

1. Refuses to run a pipeline that still requires approval.
2. Clones the bare repository into a temporary directory (`--shared`).
3. Checks out the pipeline commit.
4. Loads `.knotwork-ci.yml` (or legacy `.forge-ci.yml`).
5. Runs jobs in stage order inside `docker run --rm` with bridge networking.

Job output is fanned out through `ci.Hub` to SSE subscribers at
`/api/pipelines/{id}/logs`. Artifact collection is not implemented yet; jobs
with artifact paths log a notice.

## Federation

Federation is deny-by-default. `POST /inbox`:

1. Reads a bounded body and parses the activity.
2. Resolves the actor host to a stored peer and requires
   `trust_status = allowlisted`.
3. Verifies the draft-cavage `Signature` header with the peer's Ed25519 key,
   including `Digest` and a five-minute `Date` skew.
4. Accepts only `Offer` activities for merge requests.

Outbound delivery signs `(request-target) host date digest` and requires an
HTTPS inbox. `/actor` publishes the instance key.

## Backups

Post-receive events reset a per-repository debounce timer. Once quiet, the
manager writes `git bundle create --all` and uploads it. Database snapshots run
on `KNOTWORK_BACKUP_INTERVAL`:

- SQLite: `VACUUM INTO` a temporary file, then zstd-compress and upload.
- PostgreSQL: pipe `pg_dump --no-owner --no-acl` through zstd.

Uploads retry three times with exponential backoff. The blob store is S3 (with
optional custom endpoint/path-style) or local disk for development.

## UI

The HTML layer uses semantic markup styled by Oat. Vite builds
`frontend/src/main.ts` into `internal/web/static/{app.js,app.css,chunks/}`;
`go:embed` ships those files inside the binary.

Vanilla entry points are used from Pierre's packages:

- `@pierre/trees` renders the repository tree.
- `@pierre/diffs` renders merge-request patches.
- `@pierre/highlights` is the preferred highlighter, with `shiki-js` as the
  fallback when WebAssembly/SIMD is unavailable.

Pages are deliberately small: `data-page` selects the client-side initializer,
and `data-repo` / `data-ref` / `data-number` carry server context. The JSON API
returns tree paths, blob text, and unified patches; no templating happens on the
client.

## Testing

Tests cover the CI parser, federation signatures, manifest validation, database
state transitions, auth tokens, and real Git repository browsing. Git tests
create a bare repository, push fixture commits, and disable the generated hooks
for the fixture push.

```sh
mise exec -- go test ./...
mise exec -- go vet ./...
mise exec -- golangci-lint run ./...
```

## Known limits

- CI artifacts are not collected.
- Federation ingestion records the merge request before fetching; a failed
  fetch leaves the row for an operator to inspect.
- SQLite is the default; PostgreSQL behavior is exercised through the same SQL
  but not by an integration test in this repository.
- `internal/web/static` is generated output and must be rebuilt after frontend
  changes.
