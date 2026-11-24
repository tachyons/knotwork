package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"knotwork/internal/auth"
	"knotwork/internal/backup"
	"knotwork/internal/ci"
	"knotwork/internal/domain"
	"knotwork/internal/federation"
	"knotwork/internal/gitengine"
	"knotwork/internal/logging"
	"knotwork/internal/mcp"
	"knotwork/internal/web"
)

func runServe(args []string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	verbose := flags.Bool("v", false, "Enable verbose/debug logging")
	verboseLong := flags.Bool("verbose", false, "Enable verbose/debug logging")
	debug := flags.Bool("debug", false, "Enable debug logging")
	logLevel := flags.String("log-level", "", "Log level (debug, info, warn, error)")
	logFormat := flags.String("log-format", "", "Log format (text, json)")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, store, err := loadConfigAndDB(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork: config:", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	if *verbose || *verboseLong || *debug {
		cfg.LogLevel = "debug"
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *logFormat != "" {
		cfg.LogFormat = *logFormat
	}

	log := logging.NewLogger(logging.Config{
		Level:  cfg.LogLevel,
		Format: cfg.LogFormat,
	}, os.Stderr)

	gitMgr, err := gitengine.NewManager(cfg.RepoRoot, cfg.GitBinary, os.Args[0], cfg.SocketPath)
	if err != nil {
		log.Error("git manager init failed", "error", err)
		return 1
	}

	hookServer := gitengine.NewHookServer(store, gitMgr, log)
	if err := hookServer.Start(cfg.SocketPath); err != nil {
		log.Error("hook socket init failed", "error", err)
		return 1
	}
	defer func() { _ = hookServer.Close() }()

	blobStore, err := backup.NewStore(ctx, cfg.S3, filepath.Join(cfg.DataDir, "backups"))
	if err != nil {
		log.Error("backup store init failed", "error", err)
		return 1
	}
	backupMgr := backup.NewManager(blobStore, store, gitMgr, log, cfg.BundleDebounce, cfg.BackupInterval)
	backupMgr.Start()
	defer backupMgr.Close()

	authSvc, err := auth.NewService(ctx, cfg, store, log)
	if err != nil {
		log.Error("auth init failed", "error", err)
		return 1
	}

	hub := ci.NewHub()
	executor := &ci.Executor{
		DB:     store,
		GitBin: cfg.GitBinary,
		Hub:    hub,
		Log:    log,
		Runner: &ci.DockerRunner{Binary: "docker", Host: cfg.DockerHost},
	}

	onPushSuccess := func(ctx context.Context, repo domain.Repository, user domain.User, refs []gitengine.RefUpdate) {
		backupMgr.Trigger(repo)
		seen := map[string]bool{}
		for _, update := range refs {
			if !strings.HasPrefix(update.Ref, "refs/heads/") || isZeroSHA(update.New) || seen[update.New] {
				continue
			}
			seen[update.New] = true
			pipeline, err := store.CreatePipeline(ctx, repo.ID, "", update.New, update.Ref, domain.PipelineQueued, false)
			if err != nil {
				log.Warn("could not create pipeline", "repo", repo.Path, "ref", update.Ref, "error", err)
				continue
			}
			//nolint:gosec // the pipeline must outlive the hook request; cancel is bounded by the timeout.
			go func(p domain.Pipeline) {
				runCtx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				if err := executor.RunPipeline(runCtx, p); err != nil && !errors.Is(err, context.Canceled) {
					log.Error("pipeline failed", "pipeline", p.ID, "error", err)
				}
			}(pipeline)
		}
	}

	fed := &federation.InboxService{
		DB:      store,
		Git:     gitMgr,
		Log:     log,
		BaseURL: cfg.BaseURL,
		Key:     authSvc.Key,
		KeyID:   cfg.BaseURL + "/actor#main-key",
	}
	mcpServer := &mcp.Server{DB: store, Auth: authSvc, Git: gitMgr, Log: log}

	app := &web.Server{
		Cfg: cfg, DB: store, Auth: authSvc, Git: gitMgr, Hook: hookServer,
		CI: executor, Hub: hub, Backup: backupMgr, Fed: fed, MCP: mcpServer, Log: log,
		OnPushSuccess: onPushSuccess,
	}
	handler, err := app.Build()
	if err != nil {
		log.Error("could not build HTTP handler", "error", err)
		return 1
	}

	setupDone, _ := store.SetupCompleted(ctx)
	if !setupDone {
		log.Warn("first run: open /auth/login or run `knotwork admin break-glass` to claim instance")
	}

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("knotwork listening", "addr", cfg.Addr, "base_url", cfg.BaseURL, "db", store.Driver, "log_level", cfg.LogLevel, "log_format", cfg.LogFormat)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return shutdown(shutdownCtx, server)
	case err := <-errCh:
		log.Error("server failed", "error", err)
		return 1
	}
}

func shutdown(ctx context.Context, s *http.Server) int {
	if err := s.Shutdown(ctx); err != nil {
		return 1
	}
	return 0
}

func isZeroSHA(sha string) bool {
	return sha == "" || strings.Trim(sha, "0") == ""
}
