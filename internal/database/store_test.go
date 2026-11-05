package database

import (
	"context"
	"testing"
	"time"

	"knotwork/internal/domain"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.Context(), "sqlite::memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOIDCProvisioningMakesFirstUserAdmin(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	first, err := db.UpsertOIDCUser(ctx, "sub-1", "first@example.com", "first", "First")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	if !first.IsAdmin() {
		t.Fatalf("first user role = %q, want admin", first.Role)
	}
	second, err := db.UpsertOIDCUser(ctx, "sub-2", "second@example.com", "second", "Second")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	if second.Role != domain.RoleMember {
		t.Fatalf("second user role = %q, want member", second.Role)
	}

	updated, err := db.UpsertOIDCUser(ctx, "sub-2", "new@example.com", "second", "Renamed")
	if err != nil {
		t.Fatalf("UpsertOIDCUser update: %v", err)
	}
	if updated.Email != "new@example.com" || updated.DisplayName != "Renamed" {
		t.Fatalf("update not applied: %+v", updated)
	}
}

func TestSessionsAndRevocation(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	user, err := db.UpsertOIDCUser(ctx, "sub", "u@example.com", "user", "User")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.CreateSession(ctx, user.ID, "web", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	resolved, err := db.UserForSession(ctx, raw)
	if err != nil || resolved.ID != user.ID {
		t.Fatalf("UserForSession: %+v, %v", resolved, err)
	}
	if err := db.RevokeSessions(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UserForSession(ctx, raw); err == nil {
		t.Fatal("revoked session still resolves")
	}
}

func TestSessionPrincipalExpiryAndBreakGlass(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	user, err := db.UpsertOIDCUser(ctx, "sub", "u@example.com", "user", "User")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.CreateSession(ctx, user.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, expires, err := db.SessionPrincipal(ctx, raw)
	if err != nil || got.ID != user.ID {
		t.Fatalf("SessionPrincipal: %+v, %v", got, err)
	}
	if time.Until(expires) <= 0 {
		t.Fatalf("expiry %v is not in the future", expires)
	}
	glass, err := db.CreateSession(ctx, user.ID, "break_glass", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SessionPrincipal(ctx, glass); err == nil {
		t.Fatal("break-glass token resolved as an API session")
	}
	if err := db.RevokeSessions(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SessionPrincipal(ctx, raw); err == nil {
		t.Fatal("revoked session still resolves")
	}
}

func TestBreakGlassIsSingleUse(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	user, err := db.UpsertOIDCUser(ctx, "sub", "u@example.com", "user", "User")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.CreateSession(ctx, user.ID, "break_glass", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, expires, err := db.ConsumeBreakGlass(ctx, raw)
	if err != nil || got.ID != user.ID {
		t.Fatalf("ConsumeBreakGlass: %+v, %v", got, err)
	}
	if time.Until(expires) <= 0 {
		t.Fatalf("expiry %v is in the past", expires)
	}
	if _, _, err := db.ConsumeBreakGlass(ctx, raw); err == nil {
		t.Fatal("break-glass token was reusable")
	}
}

func TestDeviceFlowApproval(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	user, err := db.UpsertOIDCUser(ctx, "sub", "u@example.com", "user", "User")
	if err != nil {
		t.Fatal(err)
	}
	device, code, err := db.CreateDeviceCode(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateDeviceCode: %v", err)
	}
	status, err := db.DeviceCodeStatus(ctx, device)
	if err != nil || status != "pending" {
		t.Fatalf("status = %q, %v", status, err)
	}
	ok, err := db.ApproveDeviceCode(ctx, code, user.ID)
	if err != nil || !ok {
		t.Fatalf("ApproveDeviceCode: %v, %v", ok, err)
	}
	got, err := db.ConsumeDeviceCode(ctx, device)
	if err != nil || got.ID != user.ID {
		t.Fatalf("ConsumeDeviceCode: %+v, %v", got, err)
	}
	if _, err := db.ConsumeDeviceCode(ctx, device); err == nil {
		t.Fatal("device code was reusable")
	}
}

func TestRepositoryRoles(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	owner, err := db.UpsertOIDCUser(ctx, "owner", "owner@example.com", "owner", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.UpsertOIDCUser(ctx, "other", "other@example.com", "other", "Other")
	if err != nil {
		t.Fatal(err)
	}

	privateRepo, err := db.CreateRepo(ctx, owner.ID, "private", "secret", "owner/private", "/tmp/private.git", true)
	if err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}
	if role, _ := db.RepoRole(ctx, privateRepo, owner); role != "admin" {
		t.Fatalf("owner role = %q", role)
	}
	if role, _ := db.RepoRole(ctx, privateRepo, other); role != "" {
		t.Fatalf("private repo leaked role %q", role)
	}

	publicRepo, err := db.CreateRepo(ctx, owner.ID, "public", "open", "owner/public", "/tmp/public.git", false)
	if err != nil {
		t.Fatal(err)
	}
	if role, _ := db.RepoRole(ctx, publicRepo, other); role != "read" {
		t.Fatalf("public role = %q", role)
	}
	if err := db.SetProtectedBranches(ctx, publicRepo.ID, "main,release"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := db.GetRepoByID(ctx, publicRepo.ID)
	if err != nil || reloaded.ProtectedBranches != "main,release" {
		t.Fatalf("protected branches = %q, %v", reloaded.ProtectedBranches, err)
	}
}

func TestFederationPeerUpsert(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	peer, err := db.UpsertPeer(ctx, domain.Peer{
		Domain: "Peer.Example", InboxURL: "https://peer.example/inbox", TrustStatus: domain.PeerPending,
	})
	if err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	if peer.Domain != "peer.example" || peer.TrustStatus != domain.PeerPending {
		t.Fatalf("peer = %+v", peer)
	}
	if _, err := db.UpsertPeer(ctx, domain.Peer{
		Domain: "peer.example", InboxURL: "https://peer.example/inbox", TrustStatus: domain.PeerAllowlisted,
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := db.GetPeer(ctx, "peer.example")
	if err != nil || updated.TrustStatus != domain.PeerAllowlisted {
		t.Fatalf("updated peer = %+v, %v", updated, err)
	}
	peers, err := db.ListPeers(ctx)
	if err != nil || len(peers) != 1 {
		t.Fatalf("peers = %d, %v", len(peers), err)
	}
	if err := db.DeletePeer(ctx, "peer.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetPeer(ctx, "peer.example"); err == nil {
		t.Fatal("peer not deleted")
	}
}
