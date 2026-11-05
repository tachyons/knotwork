# Knotwork — Software Requirements Specification

**Product Name:** Knotwork

**Version:** 1.0.0-Draft

**Date:** October 2026

**Status:** Architecture Baseline & Specification

---

## 1. Introduction

### 1.1 Purpose

This document defines the formal functional and non-functional requirements, data models, interface constraints, user personas, journeys, and system behaviors for **Knotwork**: a single-node, federated Git collaboration platform built in Go. It targets small teams, independent engineering organizations, and self-hosters who need sovereign code hosting without the operational overhead of distributed microservices, multi-region database clusters, or three-phase consensus protocols.

### 1.2 Scope

Knotwork encompasses:

* Native Git Smart HTTP hosting (push/pull via host `git`, pure HTTPS, no SSH).
* Single Sign-On via OpenID Connect (OIDC Client), internal OIDC Provider for tokens/CLI, and directory provisioning via SCIM 2.0. No local password storage or authentication.
* Async disaster recovery (point-in-time SQLite/PostgreSQL snapshots and incremental Git bundles to S3-compatible object storage).
* Opt-in federation based on ForgeFed/ActivityPub with explicit peer instance allowlists.
* An embedded, local Docker-based CI engine executing a subset of GitLab CI syntax, alongside pluggable runner hooks and mandatory approval gates for federated contributions.
* Native Model Context Protocol (MCP) server endpoints for external AI coding agents.
* A declarative App Manifest standard for third-party extensions.
* Break-glass administrative access and cold-start configuration exclusively via a dedicated host-level CLI.

### 1.3 Definitions, Acronyms, and Abbreviations

* **OIDC:** OpenID Connect (RFC 6749, RFC 7636).
* **SCIM:** System for Cross-domain Identity Management (RFC 7643, RFC 7644).
* **ActivityPub:** W3C decentralized social networking protocol.
* **ForgeFed:** ActivityPub extension vocabulary for software forge federation.
* **MCP:** Model Context Protocol for LLM runtime context exchange.
* **Smart HTTP:** Git over HTTP/HTTPS using `git-upload-pack` and `git-receive-pack` with stateless RPC.
* **Bare Repo:** A Git repository without a checked-out working tree, managed directly by the server engine.

---

## 2. Overall Description

### 2.1 Product Perspective

Knotwork replaces complex distributed setups (such as multi-node GitLab or GitHub Enterprise) with an appliance-like, single-binary architecture. Scalability and external collaboration are addressed horizontally across the internet through **asynchronous federation** (ForgeFed) rather than internally through distributed consensus algorithms.

### 2.2 Operating Environment

* **Binary Target:** Linux (AMD64, ARM64), static or dynamically linked to host `glibc`/`musl`.
* **Host Prerequisites:**
  * `git` binary (v2.38+) installed on the host `$PATH`.
  * Docker or Podman daemon with Unix socket accessible (optional, required only for embedded CI).
* **Storage Options:** Local NVMe/SSD for repositories and DB.
  * Embedded SQLite 3 (WAL mode) for zero-dependency operation.
  * PostgreSQL 15+ for team instances.
* **Upstream S3:** Any AWS S3 or S3-compatible API (MinIO, Cloudflare R2, Wasabi, Backblaze B2).

---

## 3. User Personas

### Persona 1: Platform Engineer / Self-Hoster ("DevOps Dave")

* **Background:** Senior infrastructure engineer running homelabs and internal tooling for an 8-person engineering consultancy.
* **Pain Points:** Tired of hosting GitLab Omnibus instances that consume 8GB of RAM idling and break on background database migrations. Frustrated by Gitea/Forgejo requiring custom SSH user setups and complex key rotations.
* **Goals:** Deploy a single Go binary or small Docker container, set 5 environment variables, plug in Google Workspace or Okta via OIDC, and let it run with near-zero maintenance.

### Persona 2: Internal Core Developer ("Dev Priya")

* **Background:** Backend engineer writing Go and TypeScript daily.
* **Pain Points:** Dealing with SSH key expired-passphrase errors, complex CI pipelines that require separate runners, and corporate tools that do not natively interface with new AI coding tools.
* **Goals:** Authenticate Git via terminal browser prompts (Device Flow), push branches over fast HTTPS, run local automated tests via `.knotwork-ci.yml`, and connect Claude/Cursor via MCP to generate contextual diffs and summarize review discussions.

### Persona 3: Open-Source Contributor ("External Eli")

* **Background:** Independent open-source developer hosted on a different Knotwork instance (`src.eli-dev.org`).
* **Pain Points:** Having to create accounts and enter personal email addresses on every separate organization's self-hosted platform just to submit a single bug fix.
* **Goals:** Fork a public repository hosted on Dave's instance (`git.dave-consulting.com`), push code to his own instance, and open a cross-instance Merge Request directly without ever signing up on Dave's server.

---

## 4. User Journeys

### Journey 1: Cold-Start Bootstrap & First-Time Login (Dave)

```
[Start: Fresh VM] ──► Deploy Knotwork Binary ──► Run `knotwork serve`
                            │
                            ▼
              Instance prints Setup Secret to stdout:
              "Setup Key: 6f1b-c89a-... Visit: /setup?key=6f1b-..."
                            │
                            ▼
              Dave opens browser -> navigates to /setup
                            │
                            ▼
              Inputs:
              - Domain: git.company.com
              - OIDC Issuer: https://accounts.google.com
              - Client ID & Secret
                            │
                            ▼
              Redirects to Google Workspace -> Authenticates
                            │
                            ▼
              Knotwork claims Dave as 'instance_admin'
              `/setup` route is permanently locked in DB
```

### Journey 2: Developer Git Push via Device Flow (Priya)

```
Terminal: $ git push origin main
     │
     ▼
Knotwork HTTP 401 Unauthorized
(WWW-Authenticate: Bearer realm="Knotwork", device_flow="/auth/device")
     │
     ▼
Knotwork CLI Credential Helper catches 401:
"Open browser to https://git.company.com/auth/device and enter: WXYZ-1234"
     │
     ▼
Priya enters code in browser -> Confirms Google OIDC prompt
     │
     ▼
Knotwork issues short-lived Ed25519-signed JWT to Git Credential Helper
Credential helper caches token in system keyring (macOS Keychain / Linux Secret Service)
     │
     ▼
Git completes Smart HTTP `send-pack` over HTTPS
Pipeline automatically enqueued
```

### Journey 3: Cross-Instance Federated Pull Request & Approval (Eli & Dave)

```
Eli (on remote instance `src.eli.org`):
  1. Clicks "Federate with https://git.company.com/team/core"
  2. Submits branch `fix-null-pointer` as Federated MR
  3. Remote instance sends signed ForgeFed Activity `Offer(MergeRequest)` to Dave's instance

Dave's Instance (`git.company.com`):
  1. Verifies HTTP Signature of `src.eli.org`
  2. Checks `federation_peers` table:
     - Domain is 'allowlisted'
  3. Git worker runs:
     `git fetch https://src.eli.org/team/core.git fix-null-pointer:refs/federated/mr/42`
  4. Web UI registers Merge Request #42 with status: "External Contribution"
  5. CI pipeline created in state: "Pending Maintainer Approval"

Dave (Maintainer):
  1. Inspects diff in Web UI
  2. Clicks "Approve & Run CI"
  3. Local Docker Runner executes `.knotwork-ci.yml`
  4. Tests pass -> Dave clicks "Merge"
  5. ActivityPub `Accept(MergeRequest)` activity dispatched back to `src.eli.org`
```

---

## 5. User Stories & Acceptance Criteria

### Epics Overview

* **EP-01:** Authentication & Directory Services (OIDC & SCIM)
* **EP-02:** Git Wire Protocol & Repository Management
* **EP-03:** Federation & Trust Control (ForgeFed)
* **EP-04:** Embedded CI & Extensibility
* **EP-05:** Disaster Recovery & System Operations

---

### Epic 1: Authentication & Directory Services (OIDC & SCIM)

#### US-1.1: Zero-Password OIDC Authentication

* **As an** instance user
* **I want to** authenticate exclusively using our corporate OIDC identity provider
* **So that** I do not have to manage local credentials or worry about credential stuffing attacks.
* **Acceptance Criteria:**
  1. The platform shall NOT store password hashes, provide password reset forms, or allow password authentication under any endpoint.
  2. System must support standard OpenID Connect authorization code flow with PKCE (RFC 7636).
  3. When an unauthenticated user visits any protected web route, they are automatically directed to the IdP redirect handler or shown an IdP login button.
  4. On successful token exchange, the user record is provisioned just-in-time (JIT) using claims (`sub`, `email`, `preferred_username`, `name`).

#### US-1.2: SCIM 2.0 User & Group Synchronization

* **As an** IT administrator
* **I want** our identity provider (e.g., Okta/Entra ID) to push account provisioning and deprovisioning to Knotwork
* **So that** terminated employees immediately lose repository and API access.
* **Acceptance Criteria:**
  1. System must expose standard SCIM 2.0 endpoints under `/scim/v2/Users` and `/scim/v2/Groups` protected by an admin-generated bearer token.
  2. `POST /scim/v2/Users` shall create an active local user profile mapped to the external SCIM `id`.
  3. `PATCH /scim/v2/Users/{id}` with `{"active": false}` shall set `is_active = 0` in the database, immediately invalidating all active web sessions, PATs, and CLI tokens for that user.
  4. Disabled users attempting Git pushes or API calls must receive an immediate `403 Forbidden`.

#### US-1.3: Git CLI Device Authorization Flow

* **As a** developer
* **I want to** authenticate `git push` and `git fetch` operations without manual API token copy-pasting
* **So that** I have a fast, single-step terminal onboarding flow.
* **Acceptance Criteria:**
  1. The server must implement RFC 8628 (OAuth 2.0 Device Authorization Grant) under `/auth/device/code`.
  2. The bundled `knotwork auth login` CLI command shall display a 4-letter/8-character user code and open the default browser.
  3. Once confirmed in the browser, the CLI shall receive an Ed25519-signed JWT personal access token and automatically register itself with `git-credential-helper`.

#### Epic 2: Git Wire Protocol & Repository Management

#### US-2.1: Pure HTTPS Git Smart Protocol Execution

* **As a** developer
* **I want to** clone, fetch, and push repositories strictly over HTTPS
* **So that** our infrastructure does not have to open port 22 or maintain SSH public keys.
* **Acceptance Criteria:**
  1. All Git interactions must route through `/info/refs`, `/git-upload-pack`, and `/git-receive-pack`.
  2. The server must directly stream request bodies to host `git` subprocesses using `os/exec` with zero buffering in memory or temporary files.
  3. The platform must reject unauthenticated write requests with HTTP `401 Unauthorized` and proper `WWW-Authenticate` headers.
  4. Repositories must be stored as bare repos (`git init --bare`) on local disk.

#### US-2.2: IPC-Backed Pre-Receive Branch Protection

* **As a** project maintainer
* **I want to** prevent direct pushes to `main` and block non-fast-forward (force) pushes
* **So that** repository history remains linear and changes are reviewed via Merge Requests.
* **Acceptance Criteria:**
  1. Repositories must be provisioned with a static `hooks/pre-receive` executable.
  2. During push, the hook must connect to Knotwork's local Unix domain socket (`/tmp/knotwork-internal.sock`) and validate ref transactions against the pusher's identity (`FORGE_ACTOR_ID`).
  3. If a push targets a protected branch without maintainer privileges, the hook must exit with non-zero status and print an explicit error to Git stdout: `Remote rejected: Branch [main] is protected`.

### Epic 3: Federation & Trust Control (ForgeFed)

#### US-3.1: Explicit Allowlist Federation Peer Management

* **As an** instance administrator
* **I want** to define an explicit allowlist of remote forge instances
* **So that** random or malicious servers cannot spam my server with merge requests, activities, or tracking scripts.
* **Acceptance Criteria:**
  1. System must operate by default in `allowlist_only` mode.
  2. Inbound ActivityPub HTTP requests from servers not present in `federation_peers` with `trust_status = 'allowlisted'` must be dropped with HTTP `403 Forbidden`.
  3. The web admin interface and CLI must provide actions to add, inspect, verify, and revoke remote peer domains.
  4. Each remote peer must have its public key cached and periodically refreshed via standard WebFinger / Actor endpoints.

#### US-3.2: Isolated Federated Merge Request Ingestion

* **As a** maintainer
* **I want** cross-instance pull requests to be fetched into an isolated Git reference namespace
* **So that** unverified external code never pollutes my local branch tree.
* **Acceptance Criteria:**
  1. Upon receiving an `Offer(MergeRequest)` activity, the server must fetch remote commits via HTTPS into `refs/federated/mr/{id}`.
  2. The web interface must clearly identify the Merge Request with a "Federated" badge displaying the origin server domain (e.g., `eli@src.eli.org`).
  3. When an MR is merged, Knotwork must dispatch an `Accept(MergeRequest)` activity back to the source instance inbox signed with the instance's Ed25519 private key.

### Epic 4: Embedded CI & Extensibility

#### US-4.1: Embedded Ephemeral Docker CI Execution

* **As a** developer
* **I want** basic automated tests to run inside clean Docker containers on push
* **So that** I have immediate feedback without setting up external runner architectures.
* **Acceptance Criteria:**
  1. The platform must parse `.knotwork-ci.yml` supporting `stages`, `image`, `script`, and `artifacts`.
  2. Jobs must execute against the local Docker socket (`/var/run/docker.sock`) using ephemeral containers (`--rm`) mounting the cloned commit workspace.
  3. Terminal output (stdout/stderr) must stream live to the web UI via Server-Sent Events (SSE).
  4. Containers must run without elevated privileges (no `--privileged` flag).

#### US-4.2: Federated CI Maintainer Approval Gate

* **As a** security-conscious maintainer
* **I want** CI pipelines on federated MRs to pause until I explicitly approve them
* **So that** malicious external actors cannot execute cryptominers or steal internal CI secrets.
* **Acceptance Criteria:**
  1. Any pipeline triggered by a commit originating from an external federated instance must be marked `status = 'pending_approval'`.
  2. The Docker engine must NOT spawn containers for `pending_approval` pipelines.
  3. The Web UI must show an "Approve and Run Pipeline" button accessible exclusively to users with `write` or `admin` permissions on the target repository.
  4. Approvals must be logged with timestamp and `approved_by` user ID for auditing.

#### US-4.3: Model Context Protocol (MCP) Integration

* **As an** AI agent or AI-assisted developer
* **I want to** interface with Knotwork via MCP over Streamable HTTP, legacy SSE, or stdio
* **So that** external clients can inspect merge requests and repository content and submit review comments.
* **Acceptance Criteria:**
  1. `POST /api/mcp` serves stateless Streamable HTTP. The same endpoint accepts a legacy `initialize` / `notifications/initialized` session and a 2026-07-28 client that uses `server/discover`. The server uses `github.com/modelcontextprotocol/go-sdk` v1.8.0. That release's supported protocol versions are 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, and 2026-07-28. A 2026-07-28 request must carry that SDK's per-request `_meta` (`io.modelcontextprotocol/protocolVersion` and client capabilities) and a matching `Mcp-Protocol-Version` header. The SDK also sends `Mcp-Method` and `Mcp-Name` for that revision. 2026-07-28 is not offered on a stateful Streamable HTTP session.
  2. Legacy HTTP+SSE remains: `GET /api/mcp/sse` emits the `endpoint` event, and `POST /api/mcp/messages?session=` carries client messages. Responses are SSE `message` events and the POST returns 202. This transport does not serve protocol 2026-07-28.
  3. `knotwork mcp` serves the same tools and resources on stdio. It requires `KNOTWORK_MCP_TOKEN`, an existing API bearer (device-flow session token or instance JWT). It does not assume an administrator, accept a caller-supplied user id, or skip authentication. stdout is only the protocol stream.
  4. Resources are `knotwork://{owner}/{repo}/tree/{ref}` and `knotwork://{owner}/{repo}/diff/{number}`, plus the `forge://` aliases. `resources/list` returns the HEAD tree of repositories the bearer may read. `resources/read` returns that text in the standard `contents` array.
  5. Tools are `get_mr_details(repo, number)` and `create_review_comment(repo, number, path, line, body)`. Creating a review comment requires repository role `write` or `admin`.
  6. Every HTTP MCP request resolves its principal from that request's API token. The token may be an `Authorization: Bearer` value or HTTP Basic credentials, where the password is the token and an empty password uses the username. This is the same check Git Smart HTTP uses. A session id cannot select a different user. Missing, invalid, and revoked credentials are refused. Each MCP response includes `X-Request-ID`, and the server access log records that id as `req_id` along with method, path, and status. Protected resource metadata (RFC 9728) is at `/.well-known/oauth-protected-resource/api/mcp` for the resource `{base}/api/mcp`. Knotwork does not embed an authorization server.

### Epic 5: Disaster Recovery & Operations

#### US-5.1: Debounced Asynchronous S3 Repository Bundling

* **As a** platform administrator
* **I want** repository changes to automatically snapshot to S3 in the background
* **So that** I have offsite disaster recovery without slowing down developer `git push` speeds.
* **Acceptance Criteria:**
  1. On Git `post-receive`, an internal event must reset a 30-second debounce timer for that repository.
  2. Upon timer expiration, a worker must execute `git bundle create /tmp/{id}.bundle --all` and stream the file to `s3://{bucket}/repos/{id}/bundles/{timestamp}.bundle`.
  3. The local `git push` command must complete immediately and NOT block waiting for S3 uploads.
  4. S3 failures must log clear alerts and retry with exponential backoff without corrupting local repositories.

#### US-5.2: Non-Blocking Database Snapshot to S3

* **As an** administrator
* **I want** the database to automatically back up to S3 without taking the system offline
* **So that** I have reliable point-in-time recovery without read/write locks.
* **Acceptance Criteria:**
  1. For SQLite: Run `VACUUM INTO '/tmp/snapshot.db'` followed by `zstd` compression and stream to S3 on a configurable schedule (default: every 6 hours).
  2. For PostgreSQL: Pipe `pg_dump` through `zstd` to S3 via standard worker stream.
  3. Database operations must continue servicing read and write traffic normally during backup creation.

#### US-5.3: Host CLI Break-Glass Recovery

* **As an** administrator locked out of the upstream OIDC provider
* **I want to** generate an emergency administrative session from the host server terminal
* **So that** I can fix authentication issues and maintain the system during IdP outages.

* **Acceptance Criteria:**
  1. The command `knotwork admin break-glass --duration 15m` executed on the host must write an ephemeral token directly into the local database.
  2. The command outputs a single-use URL: `https://{domain}/auth/break-glass?token={token}`.
  3. Navigating to this URL provides an authenticated session with `instance_admin` privileges for the specified duration.
  4. Break-glass sessions are revoked immediately after the duration expires or when manually invalidated via `knotwork admin revoke-sessions`.

---

## 6. Non-Functional Requirements (NFRs)

### 6.1 Performance & Scalability

* **Git Wire Latency:** Smart HTTP `info/refs` processing overhead added by Knotwork must be under 15ms (excluding host `git` execution time).
* **System Footprint:** The idle server process must consume less than 64MB of RSS RAM when running on SQLite.
* **Concurrency:** The system must handle up to 50 concurrent Git clone/push operations on an entry-level 4-core, 8GB RAM host without connection drops.

### 6.2 Security & Cryptography

* **No Plaintext Passwords:** No password storage, hashing algorithms (bcrypt/argon2), or credential verification logic shall exist in the codebase.
* **Transport Security:** Pure HTTPS; internal auto-cert generation via ACME Let's Encrypt or manual TLS certificate specification.
* **Federation Signatures:** All outbound ActivityPub payloads must be signed using Ed25519 HTTP Signatures conforming to `draft-cavage-http-signatures-12`.
* **CI Isolation:** Docker containers must not share the host network (`--net=bridge` or `--net=none`) and must enforce read-only workspace roots where applicable.

### 6.3 Reliability & Availability

* **Database Resiliency:** SQLite must strictly enforce `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;` to ensure zero database-locked crashes under multi-threaded read/write workloads.
* **Zero Downtime Restores:** Rebuilding an instance from S3 backups requires only: downloading the latest DB snapshot and unpacking the latest Git bundles into the repository root.

---

## 7. Data Dictionary & System Entity Relationships

```
                     ┌───────────────────────┐
                     │         users         │
                     │  (OIDC Authenticated) │
                     └───────────┬───────────┘
                                 │ 1
                                 │
                                 │ *
                     ┌───────────▼───────────┐
                     │     repositories      │
                     │  (Bare repos on disk) │
                     └───────────┬───────────┘
                                 │ 1
                                 │
         ┌───────────────────────┴───────────────────────┐
         │ *                                             │ *
┌────────▼──────────────┐                       ┌────────▼──────────────┐
│    merge_requests     │                       │       pipelines       │
│  (Local & Federated)  │                       │   (Local Docker CI)   │
└────────┬──────────────┘                       └───────────────────────┘
         │ *
         │
         │ *
┌────────▼──────────────┐
│   federation_peers    │
│  (Allowlisted Hosts)  │
└───────────────────────┘
```

---

## 8. App Manifest Specification

To avoid proprietary API implementations, third-party apps register via a declarative manifest format:

```yaml
# app-manifest.yaml
name: "LinterBot"
id: "com.example.linter"
version: "1.0.0"
homepage: "https://linter.example.com"
callback_url: "https://linter.example.com/webhook"

permissions:
  repositories: read
  merge_requests: write
  checks: write

events:
  - push
  - merge_request.created
  - merge_request.updated

public_key: "ed25519-public-key-hex"
```

* **Authentication:** Knotwork delivers webhook events with an `X-Knotwork-Signature` header containing an Ed25519 signature generated with the instance key.
* **API Access:** The app exchanges its registered private key for short-lived OAuth 2.1 access tokens restricted to the declared permission scopes.

---

## 9. Verification & Quality Control Matrix

| Requirement | Test Type | Verification Method | Pass Criteria |
| --- | --- | --- | --- |
| **US-1.1** (Zero Passwords) | Security Audit | Automated code grep for hashing libraries + blackbox scan | Zero password prompts; all auth redirected to OIDC provider |
| **US-1.2** (SCIM Sync) | Integration Test | Dispatch SCIM `PATCH active=false` payload | Target user active session cut; subsequent Git push returns 403 |
| **US-2.1** (Smart HTTP) | E2E Test | Standard terminal `git push` via HTTPS test harness | Repository bare directory reflects pushed commits |
| **US-3.1** (Peer Allowlist) | Integration Test | Send ForgeFed `Offer(MR)` from non-allowlisted host | Request dropped with HTTP 403; zero disk refs created |
| **US-4.2** (CI Approval) | E2E Test | Open federated MR from allowlisted peer | Pipeline created in `pending_approval`; 0 containers launched until manual click |
| **US-5.1** (S3 Bundling) | Unit / E2E | Push commit -> wait 30s debounce -> verify S3 bucket | Valid `.bundle` exists in S3; unpacks cleanly with `git clone` |
| **US-5.3** (Break-Glass) | CLI Integration | Execute `knotwork admin break-glass` in air-gapped environment | Valid single-use URL generated; grants temporary admin session |
