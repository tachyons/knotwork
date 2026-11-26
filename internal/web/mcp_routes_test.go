package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"knotwork/internal/auth"
	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/domain"
	"knotwork/internal/gitengine"
	"knotwork/internal/logging"
	kmcp "knotwork/internal/mcp"
)

func TestMCPThroughWebStack(t *testing.T) {
	ctx := t.Context()
	db, err := database.Open(ctx, "sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.UpsertOIDCUser(ctx, "alice", "alice@example.com", "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserRole(ctx, user.ID, domain.RoleMember); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Knotwork Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Knotwork Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "README")
	git("commit", "-m", "init")
	shaCmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "HEAD")
	shaOut, err := shaCmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	repo, err := db.CreateRepo(ctx, user.ID, "demo", "demo", "alice/demo", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	mr, err := db.CreateFederatedMR(ctx, repo.ID, user.ID, "forge://peer/demo", "feature", "main", "Demo change", "desc", "actor", "peer.example", strings.TrimSpace(string(shaOut)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := db.CreateSession(ctx, user.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var listen net.ListenConfig
	ln, err := listen.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	logBuf := &lockedBuffer{}
	log := logging.NewLogger(logging.Config{Level: "info", Format: "json"}, logBuf)
	authSvc := &auth.Service{
		DB:     db,
		Cfg:    config.Config{BaseURL: base, DataDir: t.TempDir()},
		Tokens: auth.NewTokens(testWebKey(t), base, time.Hour),
		Log:    log,
	}
	app := &Server{
		Cfg:  authSvc.Cfg,
		DB:   db,
		Auth: authSvc,
		Git:  &gitengine.Manager{GitBinary: gitBin, Root: t.TempDir()},
		MCP:  &kmcp.Server{DB: db, Auth: authSvc, Git: &gitengine.Manager{GitBinary: gitBin}, Log: log},
		Log:  log,
	}
	httpServer := &httptest.Server{Listener: ln, Config: &http.Server{Handler: app.Build()}}
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	health, err := http.DefaultClient.Do(mustWebReq(t, http.MethodGet, base+"/healthz", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(health.Body)
	_ = health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", health.StatusCode)
	}
	home, err := http.DefaultClient.Do(mustWebReq(t, http.MethodGet, base+"/", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	homeBody, _ := io.ReadAll(home.Body)
	_ = home.Body.Close()
	if home.StatusCode != http.StatusOK || !strings.Contains(string(homeBody), "Knotwork") {
		t.Fatalf("home = %d %s", home.StatusCode, homeBody)
	}
	meta, err := http.DefaultClient.Do(mustWebReq(t, http.MethodGet, base+"/.well-known/oauth-protected-resource/api/mcp", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	metaBody, _ := io.ReadAll(meta.Body)
	_ = meta.Body.Close()
	if meta.StatusCode != http.StatusOK || !strings.Contains(string(metaBody), base+"/api/mcp") || strings.Contains(string(metaBody), "authorization_servers") {
		t.Fatalf("metadata = %d %s", meta.StatusCode, metaBody)
	}
	deniedReq := mustWebReq(t, http.MethodPost, base+"/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	deniedReq.Header.Set("X-Request-ID", "trace-mcp-denied")
	denied, err := http.DefaultClient.Do(deniedReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(denied.Body)
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized || !strings.Contains(denied.Header.Get("WWW-Authenticate"), base+"/.well-known/oauth-protected-resource/api/mcp") {
		t.Fatalf("unauthenticated mcp = %d %q", denied.StatusCode, denied.Header.Get("WWW-Authenticate"))
	}
	if denied.Header.Get("X-Request-ID") != "trace-mcp-denied" {
		t.Fatalf("X-Request-ID = %q", denied.Header.Get("X-Request-ID"))
	}
	assertMCPTrace(t, logBuf, "trace-mcp-denied", "/api/mcp", 401)

	const badBasic = "not-a-real-basic-token"
	badReq := mustWebReq(t, http.MethodPost, base+"/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	badReq.SetBasicAuth("knotwork", badBasic)
	badReq.Header.Set("X-Request-ID", "trace-mcp-basic-no")
	badRes, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badBody, _ := io.ReadAll(badRes.Body)
	_ = badRes.Body.Close()
	if badRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("basic auth status = %d", badRes.StatusCode)
	}
	challenge := strings.Join(badRes.Header.Values("WWW-Authenticate"), " ")
	if !strings.Contains(challenge, base+"/.well-known/oauth-protected-resource/api/mcp") || !strings.Contains(challenge, `Basic realm="Knotwork"`) {
		t.Fatalf("basic WWW-Authenticate = %q", badRes.Header.Values("WWW-Authenticate"))
	}
	if strings.Contains(string(badBody), badBasic) || strings.Contains(logBuf.String(), badBasic) || strings.Contains(logBuf.String(), token) {
		t.Fatal("trace log or body contains a credential")
	}
	assertMCPTrace(t, logBuf, "trace-mcp-basic-no", "/api/mcp", 401)
	if !traceHasMessage(t, logBuf, "trace-mcp-basic-no", "mcp credential refused") {
		t.Fatalf("missing refusal trace: %s", logBuf.String())
	}

	cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(cctx, &mcp.StreamableClientTransport{
		Endpoint:   base + "/api/mcp",
		HTTPClient: &http.Client{Transport: headerTransport{base: http.DefaultTransport, token: token}},
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-03-26"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(cctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": repo.Path, "number": mr.Number,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("content = %#v", res.Content)
	}

	basicSession, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(cctx, &mcp.StreamableClientTransport{
		Endpoint: base + "/api/mcp",
		HTTPClient: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			clone := r.Clone(r.Context())
			clone.SetBasicAuth("knotwork", token)
			clone.Header.Set("X-Request-ID", "trace-mcp-basic-yes")
			return http.DefaultTransport.RoundTrip(clone)
		})},
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-03-26"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = basicSession.Close() }()
	listed, err := basicSession.ListTools(cctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sawTool bool
	for _, tool := range listed.Tools {
		if tool.Name == "get_mr_details" {
			sawTool = true
		}
	}
	if !sawTool {
		t.Fatalf("basic auth tools = %#v", listed.Tools)
	}
	basicCall, err := basicSession.CallTool(cctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": repo.Path, "number": mr.Number,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(basicCall.Content) != 1 {
		t.Fatalf("basic auth content = %#v", basicCall.Content)
	}
	assertMCPTrace(t, logBuf, "trace-mcp-basic-yes", "/api/mcp", 200)
	if strings.Contains(logBuf.String(), token) || strings.Contains(logBuf.String(), badBasic) {
		t.Fatal("trace log contains a credential")
	}

	// The legacy SSE route must flush its endpoint event through the web
	// stack's status recorder. The handler stays open until the client leaves.
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	sseReq, err := http.NewRequestWithContext(sctx, http.MethodGet, base+"/api/mcp/sse", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	sseReq.Header.Set("Authorization", "Bearer "+token)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseRes, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sseRes.Body.Close() }()
	if sseRes.StatusCode != http.StatusOK || sseRes.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("sse = %d %q", sseRes.StatusCode, sseRes.Header.Get("Content-Type"))
	}
	buf := make([]byte, 512)
	n, err := sseRes.Body.Read(buf)
	if n == 0 && err != nil {
		t.Fatal(err)
	}
	event := string(buf[:n])
	if !strings.Contains(event, "event: endpoint") || !strings.Contains(event, "/api/mcp/messages?session=") {
		t.Fatalf("sse event = %q", event)
	}
}

type traceLog interface {
	String() string
}

// lockedBuffer lets the test read request logs while the server is still
// writing them. bytes.Buffer is not safe for that overlap.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func assertMCPTrace(t *testing.T, buf traceLog, reqID, path string, status int) {
	t.Helper()
	if !traceHasMessage(t, buf, reqID, "http request") {
		t.Fatalf("missing http trace req_id=%s path=%s status=%d\n%s", reqID, path, status, buf.String())
	}
	for _, entry := range decodeTraces(t, buf) {
		if entry["req_id"] != reqID || entry["msg"] != "http request" {
			continue
		}
		if entry["path"] != path {
			t.Fatalf("path = %v, want %s", entry["path"], path)
		}
		if entry["status"] != float64(status) {
			continue
		}
		return
	}
	t.Fatalf("missing http trace req_id=%s path=%s status=%d\n%s", reqID, path, status, buf.String())
}

func traceHasMessage(t *testing.T, buf traceLog, reqID, msg string) bool {
	t.Helper()
	for _, entry := range decodeTraces(t, buf) {
		if entry["req_id"] == reqID && entry["msg"] == msg {
			return true
		}
	}
	return false
}

func decodeTraces(t *testing.T, buf traceLog) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line: %v\n%s", err, line)
		}
		entries = append(entries, entry)
	}
	return entries
}

func mustWebReq(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type headerTransport struct {
	base  http.RoundTripper
	token string
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+h.token)
	return h.base.RoundTrip(clone)
}

func testWebKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
