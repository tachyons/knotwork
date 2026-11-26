package gitengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRequest(target string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), "GET", target, http.NoBody)
}

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestRepositoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	mgr, err := NewManager(root, "git", "", filepath.Join(root, "hook.sock"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	disk, err := mgr.Init(ctx, "alice/demo")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Verify core.hooksPath is set to the centralized hooks directory
	hooksPath := gitCmd(t, disk, "config", "core.hooksPath")
	if hooksPath != mgr.HooksDir {
		t.Fatalf("core.hooksPath = %q, want %q", hooksPath, mgr.HooksDir)
	}
	// Verify central pre-receive hook exists and is executable
	info, err := os.Stat(filepath.Join(mgr.HooksDir, "pre-receive"))
	if err != nil || info.Mode()&0o111 == 0 {
		t.Fatalf("central pre-receive missing or not executable: %v", err)
	}
	// Verify no per-repository hook files exist
	if _, err := os.Stat(filepath.Join(disk, "hooks", "pre-receive")); err == nil {
		t.Fatal("per-repo hooks/pre-receive should not exist")
	}
	if _, err := os.Stat(filepath.Join(disk, "hooks", "post-receive")); err == nil {
		t.Fatal("per-repo hooks/post-receive should not exist")
	}

	empty, err := mgr.IsEmpty(ctx, disk)
	if err != nil || !empty {
		t.Fatalf("IsEmpty before push: %v, %v", empty, err)
	}
	emptyPaths, err := mgr.ListTree(ctx, disk, "main")
	if err != nil {
		t.Fatalf("ListTree on empty repo: %v", err)
	}
	if len(emptyPaths) != 0 {
		t.Fatalf("expected 0 paths on empty repo, got %v", emptyPaths)
	}

	// The generated hooks expect a live daemon socket; disable them for the
	// fixture pushes while still exercising the real bare repository.
	gitCmd(t, disk, "config", "core.hooksPath", os.DevNull)

	work := t.TempDir()
	gitCmd(t, work, "init", "-q", "-b", "main")
	gitCmd(t, work, "config", "user.email", "test@example.com")
	gitCmd(t, work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("# Demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "app.js"), []byte("console.log('hi')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, work, "add", ".")
	gitCmd(t, work, "commit", "-q", "-m", "Initial commit")
	gitCmd(t, work, "remote", "add", "origin", disk)
	gitCmd(t, work, "push", "-q", "origin", "main")

	empty, err = mgr.IsEmpty(ctx, disk)
	if err != nil || empty {
		t.Fatalf("IsEmpty after push: %v, %v", empty, err)
	}

	paths, err := mgr.ListTree(ctx, disk, "main")
	if err != nil {
		t.Fatalf("ListTree: %v", err)
	}
	if len(paths) != 2 || paths[0] != "README.md" || paths[1] != "app.js" {
		t.Fatalf("ListTree = %v, want [README.md app.js]", paths)
	}

	readme, binary, err := mgr.ReadBlob(ctx, disk, "main", "README.md")
	if err != nil || binary {
		t.Fatalf("ReadBlob: %v (binary: %v)", err, binary)
	}
	if string(readme) != "# Demo\n" {
		t.Fatalf("ReadBlob content = %q", readme)
	}

	patch, err := mgr.DiffRange(ctx, disk, "", "main")
	if err != nil {
		t.Fatalf("DiffRange: %v", err)
	}
	if !strings.Contains(string(patch), "console.log('hi')") || !strings.Contains(string(patch), "a/app.js") {
		t.Fatalf("unexpected patch:\n%s", patch)
	}

	gitCmd(t, work, "checkout", "-q", "-b", "feature")
	if err := os.WriteFile(filepath.Join(work, "app.js"), []byte("console.log('bye')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, work, "add", "app.js")
	gitCmd(t, work, "commit", "-q", "-m", "Change app")
	gitCmd(t, work, "push", "-q", "origin", "feature")

	patch, err = mgr.DiffRange(ctx, disk, "main", "feature")
	if err != nil {
		t.Fatalf("DiffRange: %v", err)
	}
	if !strings.Contains(string(patch), "console.log('bye')") || !strings.Contains(string(patch), "a/app.js") {
		t.Fatalf("unexpected patch:\n%s", patch)
	}
}

func TestValidateRef(t *testing.T) {
	valid := []string{"", "HEAD", "main", "refs/heads/main", "refs/federated/mr/1", "a1b2c3", "feature/new-ui_1.0"}
	for _, ref := range valid {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) = %v", ref, err)
		}
	}
	invalid := []string{
		"-x",
		"--upload-pack=cat /etc/passwd",
		"--output=/etc/cron.d/pwn",
		"-c protocol.ext.allow=always",
		"main..dev",
		"main branch",
		"refs/heads/main:evil",
		"a^b",
		"a~1",
		"main@{yesterday}",
		"/starts/slash",
		"ends/slash/",
		"ends/dot.",
		"double//slash",
		"dot/./segment",
		"dot/../segment",
		"nul\x00byte",
		"new\nline",
	}
	for _, ref := range invalid {
		if err := ValidateRef(ref); err == nil {
			t.Errorf("ValidateRef(%q) accepted, want error", ref)
		}
	}
}

func TestValidatePath(t *testing.T) {
	for _, p := range []string{
		"", "/etc/passwd", "../secret", "src/../../secret", "-rf",
		"a/../b", "src/./main.go", "src//main.go", "src/main.go/",
		"nul\x00byte", "new\nline",
	} {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) accepted", p)
		}
	}
	for _, p := range []string{"README.md", "src/main.go", "src/.hidden"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v", p, err)
		}
	}
}

func TestParseGitRequest(t *testing.T) {
	req, ok := parseGitRequest(newRequest("/alice/demo.git/info/refs?service=git-receive-pack"))
	if !ok || req.owner != "alice" || req.repo != "demo" || !req.write {
		t.Fatalf("receive info/refs = %+v, %v", req, ok)
	}
	req, ok = parseGitRequest(newRequest("/alice/demo.git/git-upload-pack"))
	if !ok || req.write || req.endpoint != "git-upload-pack" {
		t.Fatalf("upload-pack = %+v, %v", req, ok)
	}
	if _, ok := parseGitRequest(newRequest("/alice/demo/info/refs")); ok {
		t.Fatal("non-.git path accepted")
	}
	if _, ok := parseGitRequest(newRequest("/alice/demo.git/unknown")); ok {
		t.Fatal("unknown endpoint accepted")
	}
	// Argument injection via path or service
	if _, ok := parseGitRequest(newRequest("/-upload-pack/demo.git/git-upload-pack")); ok {
		t.Fatal("option owner accepted")
	}
	if _, ok := parseGitRequest(newRequest("/alice/-evil.git/git-upload-pack")); ok {
		t.Fatal("option repo accepted")
	}
	if _, ok := parseGitRequest(newRequest("/../../etc/cron.d.git/git-upload-pack")); ok {
		t.Fatal("path traversal repo accepted")
	}
	if _, ok := parseGitRequest(newRequest("/alice/demo.git/info/refs?service=--upload-pack=cmd")); ok {
		t.Fatal("malicious service query accepted")
	}
}

func TestSafeGitEnv(t *testing.T) {
	env := SafeGitEnv("/usr/local/bin/git")
	required := map[string]string{
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_CONFIG_GLOBAL":      "/dev/null",
		"GIT_TERMINAL_PROMPT":    "0",
		"GIT_ALLOW_PROTOCOL":     "http:https",
		"GIT_PROTOCOL_FROM_USER": "0",
	}
	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	for k, want := range required {
		if got := envMap[k]; got != want {
			t.Errorf("env[%q] = %q, want %q", k, got, want)
		}
	}
	if pathVal, ok := envMap["PATH"]; !ok || !strings.Contains(pathVal, "/usr/bin") {
		t.Errorf("PATH is missing or incomplete: %q", pathVal)
	}
}

func TestDiskPathSecurity(t *testing.T) {
	root := t.TempDir()
	mgr, err := NewManager(root, "git", "", filepath.Join(root, "hook.sock"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	valid := []string{"alice/demo", "user-1/my-repo_1", "team/proj"}
	for _, p := range valid {
		disk, err := mgr.DiskPath(p)
		if err != nil {
			t.Errorf("DiskPath(%q) unexpected error: %v", p, err)
		}
		if !strings.HasPrefix(disk, root) {
			t.Errorf("DiskPath(%q) = %q does not start with root %q", p, disk, root)
		}
	}

	invalid := []string{
		"../../etc/cron.d",
		"../secret",
		"alice/../../etc/passwd",
		"-upload-pack/demo",
		"alice/-evil",
		"alice/repo$injection",
		"alice/repo;cmd",
		"",
		".",
		"/absolute/path",
	}
	for _, p := range invalid {
		if _, err := mgr.DiskPath(p); err == nil {
			t.Errorf("DiskPath(%q) should have been rejected", p)
		}
	}
}

func TestInitSecurityConfigs(t *testing.T) {
	root := t.TempDir()
	mgr, err := NewManager(root, "git", "", filepath.Join(root, "hook.sock"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	disk, err := mgr.Init(context.Background(), "alice/secure-repo")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Verify repo directory permissions (0750)
	dirInfo, err := os.Stat(disk)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o750 {
		t.Errorf("repo directory permissions = %o, want 0750", perm)
	}

	// Verify Git configs
	expectedConfigs := map[string]string{
		"receive.fsckobjects":  "true",
		"fetch.fsckobjects":    "true",
		"transfer.fsckobjects": "true",
		"receive.maxinputsize": "104857600",
	}
	for cfgKey, want := range expectedConfigs {
		got := gitCmd(t, disk, "config", cfgKey)
		if !strings.EqualFold(got, want) {
			t.Errorf("git config %s = %q, want %q", cfgKey, got, want)
		}
	}

	// Verify core.hooksPath is set to the centralized hooks directory
	hooksPath := gitCmd(t, disk, "config", "core.hooksPath")
	if hooksPath != mgr.HooksDir {
		t.Errorf("core.hooksPath = %q, want %q", hooksPath, mgr.HooksDir)
	}
}

func TestConcurrencyLimiter(t *testing.T) {
	limiter := NewConcurrencyLimiter(2)
	ctx := context.Background()

	if err := limiter.Acquire(ctx); err != nil {
		t.Fatalf("acquire 1 failed: %v", err)
	}
	if err := limiter.Acquire(ctx); err != nil {
		t.Fatalf("acquire 2 failed: %v", err)
	}

	// Third acquire with canceled context should fail immediately
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := limiter.Acquire(cancelCtx); err == nil {
		t.Fatal("acquire 3 with canceled context should have failed")
	}

	// Third acquire with short timeout should time out
	timeoutCtx, cancelTimeout := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancelTimeout()
	if err := limiter.Acquire(timeoutCtx); err == nil {
		t.Fatal("acquire 3 should time out")
	}

	// Release one and reacquire
	limiter.Release()
	if err := limiter.Acquire(ctx); err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	}
	limiter.Release()
	limiter.Release()
}
