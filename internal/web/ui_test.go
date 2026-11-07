package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knotwork/internal/auth"
	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/gitengine"
)

func setupTestServer(t *testing.T) (*Server, *database.DB, *gitengine.Manager, http.Handler) {
	t.Helper()
	ctx := t.Context()
	db, err := database.Open(ctx, "sqlite::memory:")
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	root := t.TempDir()
	gitMgr, err := gitengine.NewManager(root, "git", "", filepath.Join(root, "hook.sock"))
	if err != nil {
		t.Fatalf("gitengine.NewManager: %v", err)
	}

	cfg := config.Config{
		BaseURL:  "http://example.com",
		DataDir:  root,
		RepoRoot: root,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authSvc, err := auth.NewService(ctx, cfg, db, log)
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}

	server := &Server{
		Cfg:  cfg,
		DB:   db,
		Auth: authSvc,
		Git:  gitMgr,
		Log:  log,
	}
	handler, err := server.Build()
	if err != nil {
		t.Fatalf("server.Build: %v", err)
	}
	return server, db, gitMgr, handler
}

// authedCookie mints a web session for a fresh admin user and returns the
// cookie that carries it.
func authedCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	ctx := t.Context()
	user, err := s.DB.UpsertOIDCUser(ctx, "csrf-sub", "csrf@example.com", "csrf", "CSRF Tester")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	token, err := s.DB.CreateSession(ctx, user.ID, "web", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return &http.Cookie{Name: "knotwork_session", Value: token}
}

func TestNewRepoPageAuth(t *testing.T) {
	ctx := t.Context()
	_, db, _, handler := setupTestServer(t)

	// Unauthenticated request should redirect to login.
	req := httptest.NewRequestWithContext(ctx, "GET", "/repos/new", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated GET /repos/new status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/auth/login") {
		t.Fatalf("redirect location = %q, want login url", loc)
	}

	// Authenticated request should render the form.
	user, err := db.UpsertOIDCUser(ctx, "sub-1", "alice@example.com", "alice", "Alice")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	token, err := db.CreateSession(ctx, user.ID, "web", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	reqAuthed := httptest.NewRequestWithContext(ctx, "GET", "/repos/new", nil)
	reqAuthed.AddCookie(&http.Cookie{Name: "knotwork_session", Value: token})
	recAuthed := httptest.NewRecorder()
	handler.ServeHTTP(recAuthed, reqAuthed)

	if recAuthed.Code != http.StatusOK {
		t.Fatalf("authenticated GET /repos/new status = %d, want %d", recAuthed.Code, http.StatusOK)
	}
	body := recAuthed.Body.String()
	if !strings.Contains(body, `id="new-repo-form"`) {
		t.Fatalf("expected new-repo-form in HTML, got:\n%s", body)
	}
	if !strings.Contains(body, `alice /`) {
		t.Fatalf("expected user namespace 'alice /' in HTML, got:\n%s", body)
	}
}

func TestCreateRepoFormAndEmptyRepoInstructions(t *testing.T) {
	ctx := t.Context()
	_, db, _, handler := setupTestServer(t)

	user, err := db.UpsertOIDCUser(ctx, "sub-1", "alice@example.com", "alice", "Alice")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	token, err := db.CreateSession(ctx, user.ID, "web", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// 1. Invalid repo name
	formInvalid := url.Values{"name": {"-bad-name"}, "visibility": {"private"}}
	reqInvalid := httptest.NewRequestWithContext(ctx, "POST", "/repos/new", strings.NewReader(formInvalid.Encode()))
	reqInvalid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqInvalid.AddCookie(&http.Cookie{Name: "knotwork_session", Value: token})
	recInvalid := httptest.NewRecorder()
	handler.ServeHTTP(recInvalid, reqInvalid)
	if recInvalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid name status = %d, want %d", recInvalid.Code, http.StatusBadRequest)
	}
	if !strings.Contains(recInvalid.Body.String(), "match [A-Za-z0-9]") {
		t.Fatalf("expected validation error, got:\n%s", recInvalid.Body.String())
	}

	// 2. Valid creation
	formData := url.Values{
		"name":        {"my-project"},
		"description": {"My first repo"},
		"visibility":  {"private"},
	}
	reqCreate := httptest.NewRequestWithContext(ctx, "POST", "/repos/new", strings.NewReader(formData.Encode()))
	reqCreate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqCreate.AddCookie(&http.Cookie{Name: "knotwork_session", Value: token})
	recCreate := httptest.NewRecorder()
	handler.ServeHTTP(recCreate, reqCreate)

	if recCreate.Code != http.StatusSeeOther {
		t.Fatalf("create status = %d, want %d (body: %s)", recCreate.Code, http.StatusSeeOther, recCreate.Body.String())
	}
	if loc := recCreate.Header().Get("Location"); loc != "/repos/alice/my-project" {
		t.Fatalf("redirect = %q, want /repos/alice/my-project", loc)
	}

	// 3. Duplicate creation conflict
	recDup := httptest.NewRecorder()
	reqDup := httptest.NewRequestWithContext(ctx, "POST", "/repos/new", strings.NewReader(formData.Encode()))
	reqDup.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqDup.AddCookie(&http.Cookie{Name: "knotwork_session", Value: token})
	handler.ServeHTTP(recDup, reqDup)
	if recDup.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", recDup.Code, http.StatusConflict)
	}

	// 4. View empty repository page
	reqRepo := httptest.NewRequestWithContext(ctx, "GET", "/repos/alice/my-project", nil)
	reqRepo.AddCookie(&http.Cookie{Name: "knotwork_session", Value: token})
	recRepo := httptest.NewRecorder()
	handler.ServeHTTP(recRepo, reqRepo)

	if recRepo.Code != http.StatusOK {
		t.Fatalf("view repo status = %d, want %d", recRepo.Code, http.StatusOK)
	}
	repoHTML := recRepo.Body.String()
	if !strings.Contains(repoHTML, "Get started with this repository") {
		t.Fatalf("expected push instructions in empty repo page, got:\n%s", repoHTML)
	}
	if !strings.Contains(repoHTML, "knotwork auth login") {
		t.Fatalf("expected auth login instruction, got:\n%s", repoHTML)
	}
	if !strings.Contains(repoHTML, "git remote add origin http://example.com/alice/my-project.git") {
		t.Fatalf("expected git remote add command, got:\n%s", repoHTML)
	}

	// 5. API tree request on empty repo must return 200 OK with empty paths
	reqTree := httptest.NewRequestWithContext(ctx, "GET", "/api/repos/alice/my-project/tree", nil)
	reqTree.AddCookie(&http.Cookie{Name: "knotwork_session", Value: token})
	recTree := httptest.NewRecorder()
	handler.ServeHTTP(recTree, reqTree)

	if recTree.Code != http.StatusOK {
		t.Fatalf("GET /api/repos/.../tree status = %d, want %d (body: %s)", recTree.Code, http.StatusOK, recTree.Body.String())
	}
	var treeResp struct {
		Ref   string   `json:"ref"`
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(recTree.Body.Bytes(), &treeResp); err != nil {
		t.Fatalf("unmarshal tree response: %v", err)
	}
	if len(treeResp.Paths) != 0 {
		t.Fatalf("expected 0 paths for empty repo, got %v", treeResp.Paths)
	}
}
