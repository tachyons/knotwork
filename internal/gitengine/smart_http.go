package gitengine

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"strings"

	"knotwork/internal/domain"
)

// HTTPHandler serves Git Smart HTTP by proxying to `git http-backend` through
// the standard library CGI bridge. Request and response bodies are streamed,
// so pushes never land in server memory or temporary files.
type HTTPHandler struct {
	Manager         *Manager
	HookServer      *HookServer
	RepoByPath      func(ctx context.Context, path string) (domain.Repository, error)
	UserFromRequest func(r *http.Request) (domain.User, bool)
	Role            func(ctx context.Context, repo domain.Repository, user domain.User) (string, error)
	Logger          *slog.Logger
	Limiter         *ConcurrencyLimiter
	MaxPushSize     int64
	OnPushSuccess   func(ctx context.Context, repo domain.Repository, user domain.User, refs []RefUpdate)
}

// Register installs catch-all GET/POST handlers. Git clone URLs live at the
// site root (`/{owner}/{repo}.git`), which cannot be expressed as a ServeMux
// wildcard without colliding with other two-segment subtrees.
func (h *HTTPHandler) Register(mux *http.ServeMux) {
	mux.Handle("GET /", h)
	mux.Handle("POST /", h)
}

// IsGitRequest reports whether r targets the Git Smart HTTP surface. It reuses
// the same parser as ServeHTTP so callers cannot drift from the real routes.
func IsGitRequest(r *http.Request) bool {
	_, ok := parseGitRequest(r)
	return ok
}

type gitRequest struct {
	owner    string
	repo     string
	endpoint string
	write    bool
}

func parseGitRequest(r *http.Request) (gitRequest, bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || !strings.HasSuffix(parts[1], ".git") {
		return gitRequest{}, false
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return gitRequest{}, false
	}
	if !repoSegmentPattern.MatchString(owner) || !repoSegmentPattern.MatchString(repo) || strings.HasPrefix(owner, "-") || strings.HasPrefix(repo, "-") {
		return gitRequest{}, false
	}
	switch {
	case len(parts) == 4 && parts[2] == "info" && parts[3] == "refs":
		service := r.URL.Query().Get("service")
		if service != "" && service != "git-upload-pack" && service != "git-receive-pack" {
			return gitRequest{}, false
		}
		return gitRequest{
			owner:    owner,
			repo:     repo,
			endpoint: "info/refs",
			write:    service == "git-receive-pack",
		}, true
	case len(parts) == 3 && parts[2] == "git-upload-pack":
		return gitRequest{owner: owner, repo: repo, endpoint: "git-upload-pack"}, true
	case len(parts) == 3 && parts[2] == "git-receive-pack":
		return gitRequest{owner: owner, repo: repo, endpoint: "git-receive-pack", write: true}, true
	}
	return gitRequest{}, false
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, ok := parseGitRequest(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.serve(w, r, req)
}

func (h *HTTPHandler) serve(w http.ResponseWriter, r *http.Request, req gitRequest) {
	if h.RepoByPath == nil {
		http.NotFound(w, r)
		return
	}
	repoPath := req.owner + "/" + req.repo

	if h.Logger != nil {
		h.Logger.DebugContext(r.Context(), "git http request received",
			"owner", req.owner,
			"repo", req.repo,
			"endpoint", req.endpoint,
			"write", req.write,
		)
	}

	repo, err := h.RepoByPath(r.Context(), repoPath)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		http.NotFound(w, r)
		return
	}

	var user domain.User
	var hasUser bool
	if h.UserFromRequest != nil {
		user, hasUser = h.UserFromRequest(r)
	}

	switch {
	case req.write:
		// Smart HTTP pushes require authentication even for public repositories.
		if !hasUser {
			w.Header().Add("WWW-Authenticate", `Basic realm="Knotwork"`)
			w.Header().Add("WWW-Authenticate", `Bearer realm="Knotwork", device_flow="/auth/device"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !h.canWrite(r.Context(), repo, user, w) {
			return
		}
		if h.Manager != nil {
			_ = h.Manager.InstallHooks(repo.DiskPath)
		}
		// DoS defense: reject push payloads exceeding configured maximum input size
		maxPush := h.MaxPushSize
		if maxPush <= 0 {
			maxPush = 104857600 // 100MB default
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPush)

	case repo.IsPrivate:
		// Private reads require an authenticated user with repo access.
		if !hasUser {
			w.Header().Add("WWW-Authenticate", `Basic realm="Knotwork"`)
			w.Header().Add("WWW-Authenticate", `Bearer realm="Knotwork", device_flow="/auth/device"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !h.canRead(r.Context(), repo, user, w) {
			return
		}
	}
	// Public reads may still carry an identity; the hook server uses it for
	// audit trails even though no authorization is required.

	// Concurrency limiting for git processes to prevent system resource exhaustion.
	limiter := h.Limiter
	if limiter == nil && h.Manager != nil {
		limiter = h.Manager.Limiter
	}
	if limiter != nil {
		if err := limiter.Acquire(r.Context()); err != nil {
			if h.Logger != nil {
				h.Logger.WarnContext(r.Context(), "git process concurrency limit reached", "error", err)
			}
			http.Error(w, "server busy: too many concurrent git operations", http.StatusServiceUnavailable)
			return
		}
		defer limiter.Release()
	}

	gitBin := "git"
	if h.Manager != nil && h.Manager.GitBinary != "" {
		gitBin = h.Manager.GitBinary
	}

	env := append(SafeGitEnv(gitBin),
		"GIT_PROJECT_ROOT="+h.Manager.Root,
		"GIT_HTTP_EXPORT_ALL=1",
		"PATH_INFO="+r.URL.Path,
		"REMOTE_USER="+user.Username,
		"KNOTWORK_ACTOR_ID="+user.ID,
		"KNOTWORK_REPO_PATH="+repo.DiskPath,
		"KNOTWORK_SOCKET="+h.Manager.SocketPath,
		"KNOTWORK_BINARY="+h.Manager.SelfBinary,
	)

	args := []string{
		"-c", "receive.fsckObjects=true",
		"-c", "fetch.fsckObjects=true",
		"-c", "transfer.fsckObjects=true",
		"-c", "receive.maxInputSize=104857600",
		"http-backend",
	}

	if h.Logger != nil {
		h.Logger.DebugContext(r.Context(), "executing git http-backend",
			"repo", repoPath,
			"disk_path", repo.DiskPath,
			"git_bin", gitBin,
			"actor", user.Username,
		)
	}

	handler := &cgi.Handler{
		Path:       gitBin,
		Args:       args,
		Env:        env,
		InheritEnv: []string{"LANG", "TZ"}, // Do NOT inherit HOME or ambient configs
	}
	handler.ServeHTTP(w, r)

	if req.endpoint == "git-receive-pack" && h.HookServer != nil && h.Manager != nil {
		refs := h.HookServer.PopApprovedRefs(repo.DiskPath)
		if len(refs) > 0 && h.OnPushSuccess != nil {
			if h.Logger != nil {
				h.Logger.DebugContext(r.Context(), "processing approved refs after push",
					"repo", repoPath,
					"approved_count", len(refs),
				)
			}
			var confirmed []RefUpdate
			for _, update := range refs {
				if IsZeroSHA(update.New) {
					confirmed = append(confirmed, update)
					continue
				}
				if sha, err := h.Manager.ResolveCommit(r.Context(), repo.DiskPath, update.Ref); err == nil && sha == update.New {
					confirmed = append(confirmed, update)
				}
			}
			if len(confirmed) > 0 {
				if h.Logger != nil {
					h.Logger.DebugContext(r.Context(), "triggering on-push success handlers",
						"repo", repoPath,
						"confirmed_count", len(confirmed),
					)
				}
				h.OnPushSuccess(r.Context(), repo, user, confirmed)
			}
		}
	}
}

func (h *HTTPHandler) canWrite(ctx context.Context, repo domain.Repository, user domain.User, w http.ResponseWriter) bool {
	role, err := h.Role(ctx, repo, user)
	if err != nil {
		if h.Logger != nil {
			h.Logger.ErrorContext(ctx, "repo role lookup failed", "repo", repo.Path, "error", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if role != "admin" && role != "write" {
		http.Error(w, "write access denied", http.StatusForbidden)
		return false
	}
	return true
}

func (h *HTTPHandler) canRead(ctx context.Context, repo domain.Repository, user domain.User, w http.ResponseWriter) bool {
	if user.IsAdmin() {
		return true
	}
	role, err := h.Role(ctx, repo, user)
	if err != nil {
		if h.Logger != nil {
			h.Logger.ErrorContext(ctx, "repo role lookup failed", "repo", repo.Path, "error", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if role == "" {
		http.Error(w, "access denied", http.StatusForbidden)
		return false
	}
	return true
}
