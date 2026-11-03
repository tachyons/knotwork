// Package web assembles Knotwork's HTTP surface: the HTML UI, JSON admin/API
// routes, Git Smart HTTP, SCIM, federation inbox, and MCP.
package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"knotwork/internal/auth"
	"knotwork/internal/backup"
	"knotwork/internal/ci"
	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/domain"
	"knotwork/internal/federation"
	"knotwork/internal/gitengine"
	"knotwork/internal/logging"
	"knotwork/internal/mcp"
)

type Server struct {
	Cfg           config.Config
	DB            *database.DB
	Auth          *auth.Service
	Git           *gitengine.Manager
	Hook          *gitengine.HookServer
	CI            *ci.Executor
	Hub           *ci.Hub
	Backup        *backup.Manager
	Fed           *federation.InboxService
	MCP           *mcp.Server
	Log           *slog.Logger
	OnPushSuccess func(ctx context.Context, repo domain.Repository, user domain.User, refs []gitengine.RefUpdate)

	mux *http.ServeMux
}

// Build registers every route and returns the wrapped handler.
func (s *Server) Build() http.Handler {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.mux.HandleFunc("GET /{$}", s.home)
	s.mux.Handle("GET /repos/new", s.Auth.RequireUser(http.HandlerFunc(s.newRepoPage)))
	s.mux.Handle("POST /repos/new", s.Auth.RequireUser(http.HandlerFunc(s.createRepoForm)))
	s.mux.HandleFunc("GET /repos/{owner}/{repo}", s.repoPage)
	s.mux.HandleFunc("GET /repos/{owner}/{repo}/merge-requests/{number}", s.mrPage)
	s.mux.HandleFunc("GET /repos/{owner}/{repo}/pipelines/{id}", s.pipelinePage)
	s.registerStatic()

	s.Auth.Register(s.mux)
	s.Auth.RegisterSCIM(s.mux)

	s.registerGitHTTP()
	if s.Fed != nil {
		s.Fed.Register(s.mux)
	}
	if s.MCP != nil {
		s.MCP.Register(s.mux)
	}
	s.registerAPI()
	return s.wrap(s.mux)
}

func (s *Server) registerGitHTTP() {
	h := &gitengine.HTTPHandler{
		Manager:         s.Git,
		HookServer:      s.Hook,
		RepoByPath:      s.DB.GetRepoByPath,
		UserFromRequest: s.Auth.UserFromRequest,
		Role:            s.DB.RepoRole,
		Logger:          s.Log,
		OnPushSuccess:   s.OnPushSuccess,
	}
	h.Register(s.mux)
}

func (s *Server) wrap(next http.Handler) http.Handler {
	cop := newCrossOriginProtection(s.Cfg.BaseURL, s.Log)
	return s.recoverPanic(logging.Middleware(s.Log)(csrfMiddleware(cop, securityHeaders(next))))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; font-src 'self' data:; "+
				"worker-src 'self' blob:; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.Log.ErrorContext(r.Context(), "panic serving request", "path", r.URL.Path, "panic", v)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user, authed := s.Auth.UserFromRequest(r)
	repos, err := s.DB.ListRepos(r.Context())
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	var visible []repoEntry
	for _, repo := range repos {
		if !authed && repo.IsPrivate {
			continue
		}
		if authed {
			role, err := s.DB.RepoRole(r.Context(), repo, user)
			if err != nil || role == "" {
				continue
			}
		}
		visible = append(visible, repoEntry{Path: repo.Path, Description: repo.Description, Private: repo.IsPrivate})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTemplate.Execute(w, page{
		Title:  "Knotwork",
		Page:   "home",
		Authed: authed,
		User:   user,
		Repos:  visible,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) requireRepoAccess(w http.ResponseWriter, r *http.Request, write bool) (repoPath string, ok bool) {
	repoPath = r.PathValue("owner") + "/" + r.PathValue("repo")
	repo, err := s.DB.GetRepoByPath(r.Context(), repoPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return "", false
	}
	user, authed := s.Auth.UserFromRequest(r)
	if !authed {
		if !write && !repo.IsPrivate {
			return repoPath, true
		}
		writeError(w, http.StatusUnauthorized, "authentication required")
		return "", false
	}
	role, err := s.DB.RepoRole(r.Context(), repo, user)
	if err != nil || role == "" {
		writeError(w, http.StatusForbidden, "repository access denied")
		return "", false
	}
	if write && role != "admin" && role != "write" {
		writeError(w, http.StatusForbidden, "write access required")
		return "", false
	}
	return repoPath, true
}
