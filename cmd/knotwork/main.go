package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/gitengine"
)

func main() {
	// If executed via direct symlink as "pre-receive", invoke the hook immediately.
	if filepath.Base(os.Args[0]) == "pre-receive" {
		os.Exit(gitengine.RunHook("pre-receive", os.Stdin, os.Stdout, os.Stderr))
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "serve":
		code = runServe(os.Args[2:])
	case "status":
		code = runStatus()
	case "admin":
		code = runAdmin(os.Args[2:])
	case "auth":
		code = runAuth(os.Args[2:])
	case "hook":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: knotwork hook pre-receive")
			code = 2
			break
		}
		code = runHook(os.Args[2])
	case "mcp":
		code = runMCP(os.Args[2:])
	case "version":
		fmt.Println("knotwork 0.1.0")
	default:
		usage()
		code = 2
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprint(os.Stderr, `Knotwork — single-node federated Git collaboration

Usage:
  knotwork serve [flags]             Run the HTTP daemon
    -v, --verbose, --debug           Enable verbose/debug logging
    --log-level <level>              Log level (debug, info, warn, error)
    --log-format <format>            Log format (text, json)
  knotwork status                    Print instance and database status
  knotwork auth login                Authorize Git over HTTPS (device flow)
  knotwork admin grant-role          Grant admin/member/read_only to an OIDC user
  knotwork admin break-glass         Mint a time-bound emergency admin URL
  knotwork admin revoke-sessions     Revoke web/CLI sessions
  knotwork admin scim-token          Mint a SCIM bearer token
  knotwork admin peers list|add|remove
  knotwork hook pre-receive
  knotwork mcp                       Serve MCP on stdio (requires KNOTWORK_MCP_TOKEN)
  knotwork version
`)
}

func loadConfigAndDB(ctx context.Context) (config.Config, *database.DB, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, nil, err
	}
	store, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, store, nil
}

func runStatus() int {
	ctx := context.Background()
	cfg, store, err := loadConfigAndDB(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	defer func() { _ = store.Close() }()
	users, _ := store.CountUsers(ctx)
	repos, _ := store.ListRepos(ctx)
	peers, _ := store.ListPeers(ctx)
	setup, _ := store.SetupCompleted(ctx)
	fmt.Printf("Knotwork %s\n", "0.1.0")
	fmt.Printf("Base URL:  %s\n", cfg.BaseURL)
	fmt.Printf("Database:  %s (%s)\n", store.Driver, cfg.DatabaseURL)
	fmt.Printf("Repo root: %s\n", cfg.RepoRoot)
	fmt.Printf("Users:     %d\n", users)
	fmt.Printf("Repos:     %d\n", len(repos))
	fmt.Printf("Peers:     %d\n", len(peers))
	fmt.Printf("Setup:     %v\n", setup)
	return 0
}

func runHook(kind string) int {
	if kind != "pre-receive" {
		fmt.Fprintln(os.Stderr, "unknown hook", kind)
		return 2
	}
	return gitengine.RunHook(kind, os.Stdin, os.Stdout, os.Stderr)
}

// openBrowser is best-effort: failures are not fatal for CLI login.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(context.Background(), "open", url)
	case "windows":
		cmd = exec.CommandContext(context.Background(), "rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.CommandContext(context.Background(), "xdg-open", url)
	}
	_ = cmd.Start()
}
