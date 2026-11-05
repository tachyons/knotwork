package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"knotwork/internal/auth"
	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/gitengine"
	"knotwork/internal/mcp"
)

func runMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: knotwork mcp")
		return 2
	}
	token := strings.TrimSpace(os.Getenv("KNOTWORK_MCP_TOKEN"))
	if token == "" {
		fmt.Fprintln(os.Stderr, "knotwork: KNOTWORK_MCP_TOKEN is required")
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: create data directory failed")
		return 1
	}
	ctx := context.Background()
	store, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: database open failed")
		return 1
	}
	defer func() { _ = store.Close() }()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	authSvc, err := auth.NewService(ctx, cfg, store, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: auth init failed")
		return 1
	}
	if _, err := authSvc.PrincipalFromBearer(ctx, token); err != nil {
		if errors.Is(err, auth.ErrInvalidBearer) {
			fmt.Fprintln(os.Stderr, "knotwork: MCP token is not valid")
			return 1
		}
		fmt.Fprintln(os.Stderr, "knotwork: MCP token could not be checked")
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: resolve executable failed")
		return 1
	}
	gitMgr, err := gitengine.NewManager(cfg.RepoRoot, cfg.GitBinary, self, cfg.SocketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: git engine init failed")
		return 1
	}
	srv := &mcp.Server{DB: store, Auth: authSvc, Git: gitMgr, Log: log}
	if err := srv.ServeStdio(ctx, token); err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: mcp stopped")
		return 1
	}
	return 0
}
