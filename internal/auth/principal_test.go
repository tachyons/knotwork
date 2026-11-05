package auth

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/domain"
)

func testService(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db := openAuthDB(t)
	key := newTestKey(t)
	const issuer = "https://knot.example"
	return &Service{
		DB:     db,
		Cfg:    config.Config{BaseURL: issuer},
		Tokens: NewTokens(key, issuer, time.Hour),
		Log:    slog.New(slog.DiscardHandler),
		Key:    key,
	}, db
}

func openAuthDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(t.Context(), "sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPrincipalFromBearer(t *testing.T) {
	ctx := context.Background()
	svc, db := testService(t)
	user, err := db.UpsertOIDCUser(ctx, "sub", "alice@example.com", "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := svc.Tokens.Issue(user.ID, user.Username, user.Role, []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.PrincipalFromBearer(ctx, jwt)
	if err != nil || got.User.ID != user.ID {
		t.Fatalf("jwt principal: %+v, %v", got, err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "api" || !got.Expiration.After(time.Now()) {
		t.Fatalf("jwt metadata = %+v", got)
	}

	session, err := db.CreateSession(ctx, user.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err = svc.PrincipalFromBearer(ctx, session)
	if err != nil || got.User.ID != user.ID || !got.Expiration.After(time.Now()) {
		t.Fatalf("session principal: %+v, %v", got, err)
	}
	if len(got.Scopes) != 0 {
		t.Fatalf("session scopes = %v", got.Scopes)
	}

	if _, err := svc.PrincipalFromBearer(ctx, ""); !errors.Is(err, ErrInvalidBearer) {
		t.Fatalf("empty token error = %v", err)
	}
	if _, err := svc.PrincipalFromBearer(ctx, "not-a-token"); !errors.Is(err, ErrInvalidBearer) {
		t.Fatalf("garbage token error = %v", err)
	}

	expired := NewTokens(svc.Key, svc.Cfg.BaseURL, -time.Hour)
	raw, err := expired.Issue(user.ID, user.Username, user.Role, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PrincipalFromBearer(ctx, raw); !errors.Is(err, ErrInvalidBearer) {
		t.Fatalf("expired jwt error = %v", err)
	}

	glass, err := db.CreateSession(ctx, user.ID, "break_glass", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PrincipalFromBearer(ctx, glass); !errors.Is(err, ErrInvalidBearer) {
		t.Fatalf("break-glass error = %v", err)
	}

	if err := db.RevokeSessions(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PrincipalFromBearer(ctx, session); !errors.Is(err, ErrInvalidBearer) {
		t.Fatalf("revoked session error = %v", err)
	}
	// The JWT is not a session, so revocation of sessions does not kill it.
	if _, err := svc.PrincipalFromBearer(ctx, jwt); err != nil {
		t.Fatalf("jwt rejected after session revocation: %v", err)
	}

	if err := db.SetUserActive(ctx, user.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PrincipalFromBearer(ctx, jwt); !errors.Is(err, ErrInvalidBearer) {
		t.Fatalf("inactive user error = %v", err)
	}
	if err := db.SetUserActive(ctx, user.ID, true); err != nil {
		t.Fatal(err)
	}
	recovered, err := svc.PrincipalFromBearer(ctx, jwt)
	if err != nil || recovered.User.ID != user.ID || recovered.User.Role != domain.RoleAdmin {
		t.Fatalf("reactivated jwt: %+v, %v", recovered, err)
	}
}
