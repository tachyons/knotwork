package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/domain"
	"knotwork/internal/federation"
)

func baseURL() string {
	cfg, err := config.Load()
	if err != nil {
		return "http://localhost:8080"
	}
	return cfg.BaseURL
}

func runAdmin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: knotwork admin <grant-role|break-glass|revoke-sessions|scim-token|peers>")
		return 2
	}
	switch args[0] {
	case "grant-role":
		return adminGrantRole(args[1:])
	case "break-glass":
		return adminBreakGlass(args[1:])
	case "revoke-sessions":
		return adminRevokeSessions(args[1:])
	case "scim-token":
		return adminSCIMToken(args[1:])
	case "peers":
		return adminPeers(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown admin command", args[0])
		return 2
	}
}

func adminStore() (context.Context, func(), *database.DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, store, err := loadConfigAndDB(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	cleanup := func() {
		_ = store.Close()
		cancel()
	}
	return ctx, cleanup, store, nil
}

func adminGrantRole(args []string) int {
	fs := flag.NewFlagSet("admin grant-role", flag.ContinueOnError)
	email := fs.String("email", "", "user email")
	role := fs.String("role", "", "admin, member, or read_only")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *email == "" || *role == "" {
		fmt.Fprintln(os.Stderr, "both --email and --role are required")
		return 2
	}
	switch *role {
	case domain.RoleAdmin, domain.RoleMember, domain.RoleReadOnly:
	default:
		fmt.Fprintln(os.Stderr, "role must be admin, member, or read_only")
		return 2
	}
	ctx, cleanup, store, err := adminStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	defer cleanup()
	user, err := store.GetUserByEmail(ctx, *email)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user not found:", *email)
		return 1
	}
	if err := store.SetUserRole(ctx, user.ID, *role); err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	fmt.Printf("granted %s to %s (%s)\n", *role, user.Username, user.Email)
	return 0
}

func adminBreakGlass(args []string) int {
	fs := flag.NewFlagSet("admin break-glass", flag.ContinueOnError)
	email := fs.String("email", "", "admin user email")
	duration := fs.Duration("duration", 15*time.Minute, "session lifetime")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "--email is required")
		return 2
	}
	if *duration <= 0 || *duration > 24*time.Hour {
		fmt.Fprintln(os.Stderr, "--duration must be between 0 and 24h")
		return 2
	}
	ctx, cleanup, store, err := adminStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	defer cleanup()
	user, err := store.GetUserByEmail(ctx, *email)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user not found:", *email)
		return 1
	}
	if !user.IsAdmin() {
		fmt.Fprintln(os.Stderr, "break-glass requires an existing instance admin; run `knotwork admin grant-role` first")
		return 1
	}
	token, err := store.CreateSession(ctx, user.ID, "break_glass", *duration)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	base := baseURL()
	fmt.Println("=== EMERGENCY ACCESS ===")
	fmt.Printf("Login URL: %s/auth/break-glass?token=%s\n", base, token)
	fmt.Printf("User:      %s\n", user.Email)
	fmt.Printf("Expires:   %s\n", time.Now().Add(*duration).UTC().Format(time.RFC3339))
	fmt.Println("The URL is single-use and grants an admin session for the duration above.")
	return 0
}

func adminRevokeSessions(args []string) int {
	fs := flag.NewFlagSet("admin revoke-sessions", flag.ContinueOnError)
	email := fs.String("email", "", "limit to one user (default: all users)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cleanup, store, err := adminStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	defer cleanup()
	userID := ""
	if *email != "" {
		user, err := store.GetUserByEmail(ctx, *email)
		if err != nil {
			fmt.Fprintln(os.Stderr, "user not found:", *email)
			return 1
		}
		userID = user.ID
	}
	if err := store.RevokeSessions(ctx, userID); err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	fmt.Println("sessions revoked")
	return 0
}

func adminSCIMToken(args []string) int {
	fs := flag.NewFlagSet("admin scim-token", flag.ContinueOnError)
	email := fs.String("email", "", "admin user email")
	duration := fs.Duration("duration", 365*24*time.Hour, "token lifetime")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "--email is required")
		return 2
	}
	ctx, cleanup, store, err := adminStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	defer cleanup()
	user, err := store.GetUserByEmail(ctx, *email)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user not found:", *email)
		return 1
	}
	if !user.IsAdmin() {
		fmt.Fprintln(os.Stderr, "SCIM tokens must belong to an instance admin")
		return 1
	}
	token, err := store.CreateSession(ctx, user.ID, "scim", *duration)
	if err != nil {
		fmt.Fprintln(os.Stderr, "knotwork:", err)
		return 1
	}
	fmt.Printf("SCIM bearer token (expires %s):\n%s\n", time.Now().Add(*duration).UTC().Format(time.RFC3339), token)
	fmt.Println("Use: Authorization: Bearer <token> against /scim/v2/Users")
	return 0
}

func adminPeers(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: knotwork admin peers list|add|remove")
		return 2
	}
	switch args[0] {
	case "list":
		ctx, cleanup, store, err := adminStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "knotwork:", err)
			return 1
		}
		defer cleanup()
		peers, err := store.ListPeers(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "knotwork:", err)
			return 1
		}
		for _, p := range peers {
			fmt.Printf("%-30s %-12s ci=%v inbox=%s\n", p.Domain, p.TrustStatus, p.AllowFederatedCI, p.InboxURL)
		}
		return 0
	case "add":
		fs := flag.NewFlagSet("admin peers add", flag.ContinueOnError)
		domainName := fs.String("domain", "", "peer hostname")
		inbox := fs.String("inbox", "", "https://peer/inbox")
		actor := fs.String("actor", "", "https://peer/actor")
		keyFile := fs.String("key-file", "", "PEM public key file")
		trust := fs.String("trust", domain.PeerPending, "allowlisted, pending, or blocked")
		allowCI := fs.Bool("allow-federated-ci", false, "record peer CI permission (approval is still required)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *domainName == "" {
			fmt.Fprintln(os.Stderr, "--domain is required")
			return 2
		}
		for name, raw := range map[string]string{"inbox": *inbox, "actor": *actor} {
			if raw == "" {
				continue
			}
			if err := federation.ValidateOutboundURL(raw); err != nil {
				fmt.Fprintf(os.Stderr, "invalid %s URL: %v\n", name, err)
				return 2
			}
		}
		key := ""
		if *keyFile != "" {
			body, err := os.ReadFile(*keyFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "knotwork:", err)
				return 1
			}
			if _, err := federation.PublicKeyFromPEM(string(body)); err != nil {
				fmt.Fprintln(os.Stderr, "invalid public key:", err)
				return 1
			}
			key = string(body)
		}
		ctx, cleanup, store, err := adminStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "knotwork:", err)
			return 1
		}
		defer cleanup()
		peer, err := store.UpsertPeer(ctx, domain.Peer{
			Domain: *domainName, InboxURL: *inbox, ActorURL: *actor,
			PublicKeyPEM: key, TrustStatus: *trust, AllowFederatedCI: *allowCI,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "knotwork:", err)
			return 1
		}
		fmt.Printf("peer %s saved with trust=%s\n", peer.Domain, peer.TrustStatus)
		return 0
	case "remove":
		fs := flag.NewFlagSet("admin peers remove", flag.ContinueOnError)
		domainName := fs.String("domain", "", "peer hostname")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *domainName == "" {
			fmt.Fprintln(os.Stderr, "--domain is required")
			return 2
		}
		ctx, cleanup, store, err := adminStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "knotwork:", err)
			return 1
		}
		defer cleanup()
		if err := store.DeletePeer(ctx, *domainName); err != nil {
			fmt.Fprintln(os.Stderr, "knotwork:", err)
			return 1
		}
		fmt.Println("peer removed")
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown peers command", args[0])
		return 2
	}
}
