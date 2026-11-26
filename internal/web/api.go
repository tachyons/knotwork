package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knotwork/internal/domain"
	"knotwork/internal/federation"
	"knotwork/internal/gitengine"
)

var (
	repoNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	ErrInvalidRepoName = errors.New("name must match [A-Za-z0-9][A-Za-z0-9._-]*")
	ErrRepoConflict    = errors.New("repository already exists")
)

func (s *Server) registerAPI() {
	s.mux.Handle("GET /api/repos", s.Auth.RequireUser(http.HandlerFunc(s.listRepos)))
	s.mux.Handle("POST /api/repos", s.Auth.RequireUser(http.HandlerFunc(s.createRepo)))
	s.mux.HandleFunc("GET /api/repos/{owner}/{repo}/tree", s.repoTree)
	s.mux.HandleFunc("GET /api/repos/{owner}/{repo}/blob", s.repoBlob)
	s.mux.Handle("GET /api/repos/{owner}/{repo}/merge-requests", s.Auth.RequireUser(http.HandlerFunc(s.listMRs)))
	s.mux.HandleFunc("GET /api/repos/{owner}/{repo}/merge-requests/{number}/diff", s.mrDiff)
	s.mux.Handle("GET /api/repos/{owner}/{repo}/pipelines", s.Auth.RequireUser(http.HandlerFunc(s.listPipelines)))
	s.mux.Handle("POST /api/repos/{owner}/{repo}/pipelines/{id}/approve", s.Auth.RequireUser(http.HandlerFunc(s.approvePipeline)))
	s.mux.Handle("POST /api/repos/{owner}/{repo}/protected-branches", s.Auth.RequireUser(http.HandlerFunc(s.setProtectedBranches)))
	s.mux.Handle("GET /api/pipelines/{id}/logs", s.Auth.RequireUser(http.HandlerFunc(s.pipelineLogs)))

	s.mux.Handle("GET /api/admin/users", s.Auth.RequireAdmin(http.HandlerFunc(s.adminListUsers)))
	s.mux.Handle("GET /api/admin/peers", s.Auth.RequireAdmin(http.HandlerFunc(s.adminListPeers)))
	s.mux.Handle("POST /api/admin/peers", s.Auth.RequireAdmin(http.HandlerFunc(s.adminUpsertPeer)))
	s.mux.Handle("DELETE /api/admin/peers/{domain}", s.Auth.RequireAdmin(http.HandlerFunc(s.adminDeletePeer)))
}

func (s *Server) initializeRepo(ctx context.Context, user domain.User, name, description string, private bool) (domain.Repository, error) {
	if !repoNamePattern.MatchString(name) {
		return domain.Repository{}, ErrInvalidRepoName
	}
	path := user.Username + "/" + name
	if _, err := s.DB.GetRepoByPath(ctx, path); err == nil {
		return domain.Repository{}, ErrRepoConflict
	}
	diskPath, err := s.Git.Init(ctx, path)
	if err != nil {
		s.Log.Error("git init failed", "path", path, "error", err)
		return domain.Repository{}, fmt.Errorf("could not create repository: %w", err)
	}
	repo, err := s.DB.CreateRepo(ctx, user.ID, name, description, path, diskPath, private)
	if err != nil {
		_ = s.Git.Prune(path)
		return domain.Repository{}, fmt.Errorf("could not record repository: %w", err)
	}
	return repo, nil
}

func (s *Server) createRepo(w http.ResponseWriter, r *http.Request) {
	user, _ := s.Auth.UserFromRequest(r)
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Private     *bool  `json:"private"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	private := true
	if in.Private != nil {
		private = *in.Private
	}
	repo, err := s.initializeRepo(r.Context(), user, in.Name, in.Description, private)
	if err != nil {
		if errors.Is(err, ErrInvalidRepoName) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, ErrRepoConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		if strings.Contains(err.Error(), "could not record repository") {
			writeError(w, http.StatusConflict, "could not record repository")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create repository")
		return
	}
	writeJSON(w, http.StatusCreated, repo)
}

func (s *Server) listRepos(w http.ResponseWriter, r *http.Request) {
	user, _ := s.Auth.UserFromRequest(r)
	repos, err := s.DB.ListRepos(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]domain.Repository, 0, len(repos))
	for _, repo := range repos {
		role, err := s.DB.RepoRole(r.Context(), repo, user)
		if err == nil && role != "" {
			out = append(out, repo)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) repoTree(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, false)
	if !ok {
		return
	}
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		ref = repo.DefaultBranch
	}
	if ref == "" {
		ref = "HEAD"
	}
	paths, err := s.Git.ListTree(r.Context(), repo.DiskPath, ref)
	if err != nil {
		if errors.Is(err, gitengine.ErrInvalidRef) {
			writeError(w, http.StatusBadRequest, "invalid ref")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "could not read repository tree")
		return
	}
	if paths == nil {
		paths = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ref": ref, "paths": paths})
}

const maxBlobBytes = 1 << 20

func (s *Server) repoBlob(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, false)
	if !ok {
		return
	}
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		ref = repo.DefaultBranch
	}
	if ref == "" {
		ref = "HEAD"
	}
	filePath := r.URL.Query().Get("path")
	content, binary, err := s.Git.ReadBlob(r.Context(), repo.DiskPath, ref, filePath)
	if err != nil {
		switch {
		case errors.Is(err, gitengine.ErrInvalidRef):
			writeError(w, http.StatusBadRequest, "invalid ref")
		case errors.Is(err, gitengine.ErrPathMissing):
			writeError(w, http.StatusNotFound, "path not found")
		default:
			writeError(w, http.StatusUnprocessableEntity, "could not read file")
		}
		return
	}
	truncated := len(content) > maxBlobBytes
	if truncated {
		content = content[:maxBlobBytes]
	}
	if binary || !utf8.Valid(content) {
		writeJSON(w, http.StatusOK, map[string]any{
			"path": filePath, "ref": ref, "binary": true, "truncated": truncated, "content": "",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": filePath, "ref": ref, "binary": false, "truncated": truncated, "content": string(content),
	})
}

func (s *Server) mrDiff(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, false)
	if !ok {
		return
	}
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	number, err := strconv.ParseInt(r.PathValue("number"), 10, 64)
	if err != nil || number <= 0 {
		writeError(w, http.StatusBadRequest, "invalid merge request number")
		return
	}
	mr, err := s.DB.GetMRByNumber(r.Context(), repo.ID, number)
	if err != nil {
		writeError(w, http.StatusNotFound, "merge request not found")
		return
	}
	head, err := s.Git.ResolveCommit(r.Context(), repo.DiskPath,
		mr.HeadSHA, fmt.Sprintf("refs/federated/mr/%d", mr.Number), mr.SourceBranch)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "merge request head is not available")
		return
	}
	base, err := s.Git.ResolveCommit(r.Context(), repo.DiskPath, mr.TargetBranch, "HEAD")
	if err != nil {
		base = ""
	}
	patch, err := s.Git.DiffRange(r.Context(), repo.DiskPath, base, head)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "could not compute diff")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(patch)
}

func (s *Server) listMRs(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, false)
	if !ok {
		return
	}
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	mrs, err := s.DB.ListMRs(r.Context(), repo.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, mrs)
}

func (s *Server) listPipelines(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, false)
	if !ok {
		return
	}
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	pipelines, err := s.DB.ListPipelines(r.Context(), repo.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, pipelines)
}

func (s *Server) approvePipeline(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, true)
	if !ok {
		return
	}
	user, _ := s.Auth.UserFromRequest(r)
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	pipeline, err := s.DB.GetPipeline(r.Context(), r.PathValue("id"))
	if err != nil || pipeline.RepoID != repo.ID {
		writeError(w, http.StatusNotFound, "pipeline not found")
		return
	}
	approved, err := s.DB.ApprovePipeline(r.Context(), pipeline.ID, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not approve pipeline")
		return
	}
	if !approved {
		writeError(w, http.StatusConflict, "pipeline is not pending approval")
		return
	}
	pipeline, _ = s.DB.GetPipeline(r.Context(), pipeline.ID)
	//nolint:gosec // the pipeline must outlive this request; cancel is bounded by the timeout.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		if err := s.CI.RunPipeline(ctx, pipeline); err != nil && !errors.Is(err, context.Canceled) {
			s.Log.Error("pipeline failed", "pipeline", pipeline.ID, "error", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, pipeline)
}

func (s *Server) setProtectedBranches(w http.ResponseWriter, r *http.Request) {
	path, ok := s.requireRepoAccess(w, r, true)
	if !ok {
		return
	}
	user, _ := s.Auth.UserFromRequest(r)
	repo, err := s.DB.GetRepoByPath(r.Context(), path)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	role, _ := s.DB.RepoRole(r.Context(), repo, user)
	if role != "admin" {
		writeError(w, http.StatusForbidden, "repository admin required")
		return
	}
	var in struct {
		Branches []string `json:"branches"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.DB.SetProtectedBranches(r.Context(), repo.ID, strings.Join(in.Branches, ",")); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update branches")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"branches": in.Branches})
}

func (s *Server) pipelineLogs(w http.ResponseWriter, r *http.Request) {
	pipeline, err := s.DB.GetPipeline(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "pipeline not found")
		return
	}
	repo, err := s.DB.GetRepoByID(r.Context(), pipeline.RepoID)
	if err != nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	user, authed := s.Auth.UserFromRequest(r)
	if !authed {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	role, err := s.DB.RepoRole(r.Context(), repo, user)
	if err != nil || role == "" {
		writeError(w, http.StatusForbidden, "repository access denied")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch, unsubscribe := s.Hub.Subscribe(pipeline.ID)
	defer unsubscribe()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case chunk, open := <-ch:
			if !open {
				return
			}
			for _, line := range strings.Split(string(chunk), "\n") {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
			}
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) adminListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.DB.ListPeers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

func (s *Server) adminUpsertPeer(w http.ResponseWriter, r *http.Request) {
	var in domain.Peer
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	if in.Domain == "" || strings.ContainsAny(in.Domain, "/: ") {
		writeError(w, http.StatusBadRequest, "domain must be a bare hostname")
		return
	}
	if in.InboxURL != "" {
		if err := federation.ValidateOutboundURL(in.InboxURL); err != nil {
			writeError(w, http.StatusBadRequest, "inbox_url must be a public https URL: "+err.Error())
			return
		}
	}
	if in.TrustStatus == "" {
		in.TrustStatus = domain.PeerPending
	}
	switch in.TrustStatus {
	case domain.PeerAllowlisted, domain.PeerPending, domain.PeerBlocked:
	default:
		writeError(w, http.StatusBadRequest, "trust_status must be allowlisted, pending, or blocked")
		return
	}
	if in.PublicKeyPEM != "" {
		if _, err := federation.PublicKeyFromPEM(in.PublicKeyPEM); err != nil {
			writeError(w, http.StatusBadRequest, "public_key_pem must be an Ed25519 public key")
			return
		}
	}
	peer, err := s.DB.UpsertPeer(r.Context(), in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save peer")
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

func (s *Server) adminDeletePeer(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.DeletePeer(r.Context(), r.PathValue("domain")); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete peer")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
