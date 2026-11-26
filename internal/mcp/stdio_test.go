package mcp

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"knotwork/internal/database"
	"knotwork/internal/domain"
)

func TestStdioProcess(t *testing.T) {
	ctx := t.Context()
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "knotwork")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/knotwork")
	build.Dir = root
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	dbPath := filepath.Join(t.TempDir(), "knot.db")
	db, err := database.Open(ctx, "sqlite://"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	alice, err := db.UpsertOIDCUser(ctx, "alice", "alice@example.com", "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := db.UpsertOIDCUser(ctx, "bob", "bob@example.com", "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserRole(ctx, alice.ID, domain.RoleMember); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "README")
	gitRun(t, dir, "commit", "-m", "init")
	sha := gitRun(t, dir, "rev-parse", "HEAD")
	bobDir := filepath.Join(t.TempDir(), "bob")
	copyTree(t, dir, bobDir)
	private, err := db.CreateRepo(ctx, alice.ID, "secret", "secret", "alice/secret", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	bobRepo, err := db.CreateRepo(ctx, bob.ID, "notes", "notes", "bob/notes", bobDir, true)
	if err != nil {
		t.Fatal(err)
	}
	mr, err := db.CreateFederatedMR(ctx, private.ID, alice.ID, "forge://peer/secret", "feature", "main", "Secret change", "desc", "actor", "peer.example", sha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateFederatedMR(ctx, bobRepo.ID, bob.ID, "forge://peer/notes", "feature", "main", "Bob change", "desc", "actor", "peer.example", sha); err != nil {
		t.Fatal(err)
	}
	token, err := db.CreateSession(ctx, alice.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bobToken, err := db.CreateSession(ctx, bob.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	envFor := func(dbURL, rawToken string) []string {
		env := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"KNOTWORK_BASE_URL=http://127.0.0.1:9",
			"KNOTWORK_DATA_DIR=" + data,
			"KNOTWORK_DATABASE_URL=" + dbURL,
			"KNOTWORK_REPO_ROOT=" + t.TempDir(),
			"KNOTWORK_SOCKET_PATH=" + filepath.Join(t.TempDir(), "knot.sock"),
		}
		if rawToken != "" {
			env = append(env, "KNOTWORK_MCP_TOKEN="+rawToken)
		}
		return env
	}

	var stdout, stderr bytes.Buffer
	missing := exec.CommandContext(ctx, bin, "mcp")
	missing.Env = envFor("sqlite://"+dbPath, "")
	missing.Stdout = &stdout
	missing.Stderr = &stderr
	if err := missing.Run(); err == nil || missing.ProcessState.ExitCode() != 2 || stdout.Len() != 0 {
		t.Fatalf("missing token exit=%v stdout=%q stderr=%s", err, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badDB := exec.CommandContext(ctx, bin, "mcp")
	badDB.Env = envFor("sqlite://"+blocker+"/knot.db", token)
	badDB.Stdout = &stdout
	badDB.Stderr = &stderr
	if err := badDB.Run(); err == nil || stdout.Len() != 0 || strings.Contains(stderr.String(), token) {
		t.Fatalf("bad database exit=%v stdout=%q stderr=%s", err, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	badToken := exec.CommandContext(ctx, bin, "mcp")
	badToken.Env = envFor("sqlite://"+dbPath, "not-a-token")
	badToken.Stdout = &stdout
	badToken.Stderr = &stderr
	if err := badToken.Run(); err == nil || stdout.Len() != 0 || strings.Contains(stderr.String(), "not-a-token") {
		t.Fatalf("bad token exit=%v stdout=%q stderr=%s", err, stdout.String(), stderr.String())
	}

	call := func(raw string) *mcp.ClientSession {
		t.Helper()
		var errBuf bytes.Buffer
		cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(cctx, bin, "mcp")
		cmd.Env = envFor("sqlite://"+dbPath, raw)
		cmd.Stderr = &errBuf
		t.Cleanup(cancel)
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(cctx, &mcp.CommandTransport{Command: cmd}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
		if err != nil {
			t.Fatalf("stdio connect: %v\n%s", err, errBuf.String())
		}
		t.Cleanup(func() {
			_ = cs.Close()
			if strings.Contains(errBuf.String(), raw) {
				t.Errorf("stderr contains the bearer: %s", errBuf.String())
			}
		})
		if got := cs.InitializeResult().ProtocolVersion; got != "2026-07-28" {
			t.Fatalf("stdio negotiated %q", got)
		}
		return cs
	}

	aliceCS := call(token)
	t.Logf("client github.com/modelcontextprotocol/go-sdk v1.8.0 stdio CommandTransport negotiated %s", aliceCS.InitializeResult().ProtocolVersion)
	if _, err := aliceCS.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceCS.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": private.Path, "number": mr.Number,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceCS.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": bobRepo.Path, "number": 1,
	}}); err == nil {
		t.Fatal("alice read bob's private repository")
	}
	if err := db.RevokeSessions(context.Background(), alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceCS.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": private.Path, "number": mr.Number,
	}}); err == nil {
		t.Fatal("revoked stdio token still called a tool")
	}
	fresh, err := db.CreateSession(context.Background(), alice.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recovered := call(fresh)
	if _, err := recovered.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": private.Path, "number": mr.Number,
	}}); err != nil {
		t.Fatalf("recovered stdio token: %v", err)
	}
	bobCS := call(bobToken)
	if _, err := bobCS.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": private.Path, "number": mr.Number,
	}}); err == nil {
		t.Fatal("bob stdio process used alice's repository")
	}
	_ = aliceCS.Close()
	_ = recovered.Close()
	_ = bobCS.Close()
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
