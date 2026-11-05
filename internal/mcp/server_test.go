package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"knotwork/internal/auth"
	"knotwork/internal/config"
	"knotwork/internal/database"
	"knotwork/internal/domain"
	"knotwork/internal/gitengine"
)

func TestSDKProtocolVersions(t *testing.T) {
	got := mcp.SupportedProtocolVersions()
	want := []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	if !slices.Equal(got, want) {
		t.Fatalf("github.com/modelcontextprotocol/go-sdk supported protocols = %v, want %v", got, want)
	}
}

func TestStreamableSameEndpoint(t *testing.T) {
	fix := newFixture(t)
	endpoint := fix.server.URL + "/api/mcp"
	legacy := fix.connect(t, endpoint, fix.aliceToken, "2025-03-26")
	modern := fix.connect(t, endpoint, fix.aliceToken, "2026-07-28")
	if got := legacy.InitializeResult().ProtocolVersion; got != "2025-03-26" {
		t.Fatalf("legacy negotiated %q", got)
	}
	if got := modern.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("modern negotiated %q", got)
	}
	t.Logf("client github.com/modelcontextprotocol/go-sdk v1.8.0 streamable HTTP stateless; legacy %s; modern %s",
		legacy.InitializeResult().ProtocolVersion, modern.InitializeResult().ProtocolVersion)

	legacyText := callText(t, legacy, "get_mr_details", map[string]any{"repo": fix.private.Path, "number": fix.mr.Number})
	modernText := callText(t, modern, "get_mr_details", map[string]any{"repo": fix.private.Path, "number": fix.mr.Number})
	if legacyText != modernText {
		t.Fatalf("legacy and modern merge-request text differ:\n%s\n%s", legacyText, modernText)
	}
	if !strings.Contains(legacyText, fix.mr.Title) || !strings.Contains(legacyText, `"number": 1`) {
		t.Fatalf("merge request text = %s", legacyText)
	}
	tools, err := legacy.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	if !slices.Equal(names, []string{"get_mr_details", "create_review_comment"}) && !slices.Contains(names, "get_mr_details") {
		t.Fatalf("tools = %v", names)
	}
	if len(names) != 2 || !slices.Contains(names, "create_review_comment") {
		t.Fatalf("tools = %v", names)
	}

	for _, version := range []string{"2024-11-05", "2025-06-18", "2025-11-25"} {
		cs := fix.connect(t, endpoint, fix.aliceToken, version)
		if got := cs.InitializeResult().ProtocolVersion; got != version {
			t.Fatalf("negotiated %q, want %q", got, version)
		}
		if _, err := cs.ListTools(context.Background(), nil); err != nil {
			t.Fatalf("list tools on %s: %v", version, err)
		}
	}
}

func TestToolRefusalsAndOneWrite(t *testing.T) {
	fix := newFixture(t)
	cs := fix.connect(t, fix.server.URL+"/api/mcp", fix.aliceToken, "2025-03-26")
	bob := fix.connect(t, fix.server.URL+"/api/mcp", fix.bobToken, "2026-07-28")
	before := fix.comments(t)

	_, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "create_review_comment", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number, "line": 1, "body": "missing path",
	}})
	if codeOf(t, err) != jsonrpc.CodeInvalidParams {
		t.Fatalf("bad arguments code = %d, err = %v", codeOf(t, err), err)
	}
	_, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": "missing/repo", "number": 1,
	}})
	if codeOf(t, err) != jsonrpc.CodeInvalidParams || !strings.Contains(err.Error(), "repository not found") {
		t.Fatalf("missing repo: %v", err)
	}
	_, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": 99,
	}})
	if codeOf(t, err) != jsonrpc.CodeInvalidParams || !strings.Contains(err.Error(), "merge request not found") {
		t.Fatalf("missing mr: %v", err)
	}
	_, err = bob.CallTool(t.Context(), &mcp.CallToolParams{Name: "create_review_comment", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number, "path": "README", "line": 1, "body": "no",
	}})
	if codeOf(t, err) != codeAccessDenied {
		t.Fatalf("bob write code = %d, err = %v", codeOf(t, err), err)
	}
	if got := fix.comments(t); got != before {
		t.Fatalf("refusals wrote comments: %d", got)
	}

	var aliceErr, bobErr error
	var aliceRes *mcp.CallToolResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aliceRes, aliceErr = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "create_review_comment", Arguments: map[string]any{
			"repo": fix.private.Path, "number": fix.mr.Number, "path": "README", "line": 3, "body": "one authorized note",
		}})
	}()
	go func() {
		defer wg.Done()
		_, bobErr = bob.CallTool(context.Background(), &mcp.CallToolParams{Name: "create_review_comment", Arguments: map[string]any{
			"repo": fix.private.Path, "number": fix.mr.Number, "path": "README", "line": 4, "body": "not allowed",
		}})
	}()
	wg.Wait()
	if aliceErr != nil {
		t.Fatalf("authorized write: %v", aliceErr)
	}
	if codeOf(t, bobErr) != codeAccessDenied {
		t.Fatalf("concurrent denial: %v", bobErr)
	}
	if got := fix.comments(t); got != before+1 {
		t.Fatalf("comments = %d, want %d", got, before+1)
	}
	text := resultText(t, aliceRes)
	if !strings.Contains(text, `"id"`) {
		t.Fatalf("comment result = %s", text)
	}
	var author string
	if err := fix.db.QueryRowContext(t.Context(), `SELECT author_id FROM review_comments`).Scan(&author); err != nil {
		t.Fatal(err)
	}
	if author != fix.alice.ID {
		t.Fatalf("comment author = %s", author)
	}

	if _, err := fix.db.ExecContext(t.Context(), `INSERT INTO repo_collaborators (repo_id, user_id, role) VALUES (?, ?, ?)`,
		fix.private.ID, fix.bob.ID, "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}}); err != nil {
		t.Fatalf("collaborator read after grant: %v", err)
	}
	if _, err := fix.db.ExecContext(t.Context(), `DELETE FROM repo_collaborators WHERE repo_id = ? AND user_id = ?`,
		fix.private.ID, fix.bob.ID); err != nil {
		t.Fatal(err)
	}
	_, err = bob.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}})
	if codeOf(t, err) != codeAccessDenied {
		t.Fatalf("after collaborator removal: %v", err)
	}
	if got := fix.comments(t); got != before+1 {
		t.Fatalf("permission changes wrote comments: %d", got)
	}
}

func TestResources(t *testing.T) {
	fix := newFixture(t)
	alice := fix.connect(t, fix.server.URL+"/api/mcp", fix.aliceToken, "2025-03-26")
	bob := fix.connect(t, fix.server.URL+"/api/mcp", fix.bobToken, "2025-11-25")
	listed, err := alice.ListResources(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Resources) != 2 {
		t.Fatalf("alice resources = %#v", listed.Resources)
	}
	for _, res := range listed.Resources {
		if res.MIMEType != "text/plain" || res.Description != "Repository tree at HEAD" || !strings.HasSuffix(res.URI, "/tree/HEAD") {
			t.Fatalf("resource = %#v", res)
		}
	}
	bobList, err := bob.ListResources(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Bob may read the public repository and his own private repository.
	// Alice's private repository stays hidden.
	bobURIs := map[string]bool{}
	for _, res := range bobList.Resources {
		bobURIs[res.URI] = true
	}
	if len(bobURIs) != 2 ||
		!bobURIs["knotwork://"+fix.public.Path+"/tree/HEAD"] ||
		!bobURIs["knotwork://"+fix.bobPrivate.Path+"/tree/HEAD"] ||
		bobURIs["knotwork://"+fix.private.Path+"/tree/HEAD"] {
		t.Fatalf("bob resources = %#v", bobList.Resources)
	}

	tree, err := alice.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "knotwork://" + fix.private.Path + "/tree/HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Contents) != 1 || !strings.Contains(tree.Contents[0].Text, "README") {
		t.Fatalf("tree = %#v", tree.Contents)
	}
	slashed, err := alice.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "forge://" + fix.private.Path + "/tree/refs/heads/main"})
	if err != nil {
		t.Fatal(err)
	}
	if slashed.Contents[0].Text != tree.Contents[0].Text {
		t.Fatalf("slashed ref text = %q", slashed.Contents[0].Text)
	}
	diff, err := alice.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "knotwork://" + fix.private.Path + "/diff/1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff.Contents[0].Text, "README") {
		t.Fatalf("diff = %s", diff.Contents[0].Text)
	}
	_, err = bob.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "knotwork://" + fix.private.Path + "/tree/HEAD"})
	if codeOf(t, err) != codeAccessDenied {
		t.Fatalf("bob tree: %v", err)
	}
	_, err = alice.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "knotwork://" + fix.private.Path + "/tree/../HEAD"})
	if codeOf(t, err) != jsonrpc.CodeInvalidParams {
		t.Fatalf("bad ref: %v", err)
	}
	_, err = alice.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "knotwork://" + fix.private.Path + "/diff/99"})
	if codeOf(t, err) != jsonrpc.CodeInvalidParams {
		t.Fatalf("missing diff: %v", err)
	}
	public, err := bob.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "knotwork://" + fix.public.Path + "/tree/HEAD"})
	if err != nil || !strings.Contains(public.Contents[0].Text, "README") {
		t.Fatalf("public tree: %v %#v", err, public)
	}
}

func TestPrincipalBoundary(t *testing.T) {
	fix := newFixture(t)
	endpoint := fix.server.URL + "/api/mcp"
	var tokenMu sync.Mutex
	current := fix.aliceToken
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		tokenMu.Lock()
		token := current
		tokenMu.Unlock()
		clone := r.Clone(r.Context())
		clone.Header.Set("Authorization", "Bearer "+token)
		clone.Header.Set("Mcp-Session-Id", "previous-request")
		return http.DefaultTransport.RoundTrip(clone)
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	alice, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: endpoint, HTTPClient: client,
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-03-26"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alice.Close() })
	if _, err := alice.CallTool(ctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}}); err != nil {
		t.Fatalf("alice private: %v", err)
	}

	tokenMu.Lock()
	current = fix.bobToken
	tokenMu.Unlock()
	bob, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: endpoint, HTTPClient: client,
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bob.Close() })
	if _, err := bob.CallTool(ctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}}); codeOf(t, err) != codeAccessDenied {
		t.Fatalf("session id reused alice authority: %v", err)
	}
	if _, err := bob.CallTool(ctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.public.Path, "number": fix.publicMR.Number,
	}}); err != nil {
		t.Fatalf("bob public after alice: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for range 8 {
		// WaitGroup.Go already adds one. An extra Add leaves Wait blocked.
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint: endpoint, HTTPClient: bearerClient(fix.aliceToken),
			}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-03-26"})
			if err != nil {
				errCh <- err
				return
			}
			defer func() { _ = cs.Close() }()
			if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
				"repo": fix.private.Path, "number": fix.mr.Number,
			}}); err != nil {
				errCh <- err
			}
		})
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint: endpoint, HTTPClient: bearerClient(fix.bobToken),
			}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
			if err != nil {
				errCh <- err
				return
			}
			defer func() { _ = cs.Close() }()
			_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
				"repo": fix.private.Path, "number": fix.mr.Number,
			}})
			var je *jsonrpc.Error
			if !errors.As(err, &je) || je.Code != codeAccessDenied {
				errCh <- err
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("interleaved call: %v", err)
	}
}

func TestHTTPBasicAuth(t *testing.T) {
	fix := newFixture(t)
	endpoint := fix.server.URL + "/api/mcp"

	t.Run("password token lists tools and reads a merge request", func(t *testing.T) {
		cs := fix.connectBasic(t, "knotwork", fix.aliceToken, "2025-03-26")
		tools, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		if !slices.Contains(names, "get_mr_details") || !slices.Contains(names, "create_review_comment") {
			t.Fatalf("tools = %v", names)
		}
		text := callText(t, cs, "get_mr_details", map[string]any{"repo": fix.private.Path, "number": fix.mr.Number})
		if !strings.Contains(text, fix.mr.Title) {
			t.Fatalf("merge request text = %s", text)
		}
	})

	t.Run("username and password", func(t *testing.T) {
		cs := fix.connectBasic(t, "alice", fix.aliceToken, "2026-07-28")
		if _, err := cs.ListTools(t.Context(), nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("token as username", func(t *testing.T) {
		cs := fix.connectBasic(t, fix.aliceToken, "", "2025-06-18")
		text := callText(t, cs, "get_mr_details", map[string]any{"repo": fix.public.Path, "number": fix.publicMR.Number})
		if !strings.Contains(text, fix.publicMR.Title) {
			t.Fatalf("public merge request text = %s", text)
		}
	})

	t.Run("invalid password is refused and not logged", func(t *testing.T) {
		const bad = "not-a-real-basic-token"
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("knotwork", bad)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d body = %s", res.StatusCode, body)
		}
		challenge := strings.Join(res.Header.Values("WWW-Authenticate"), " ")
		if !strings.Contains(challenge, `resource_metadata=`) || !strings.Contains(challenge, `Basic realm="Knotwork"`) {
			t.Fatalf("WWW-Authenticate = %q", res.Header.Values("WWW-Authenticate"))
		}
		if strings.Contains(string(body), bad) || strings.Contains(fix.logs.String(), bad) || strings.Contains(fix.logs.String(), fix.aliceToken) {
			t.Fatal("response or log contains a credential")
		}
		if !strings.Contains(fix.logs.String(), "mcp credential refused") {
			t.Fatalf("refusal log = %s", fix.logs.String())
		}
	})

	t.Run("other user cannot read a private repository", func(t *testing.T) {
		bob := fix.connectBasic(t, "bob", fix.bobToken, "2025-11-25")
		_, err := bob.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
			"repo": fix.private.Path, "number": fix.mr.Number,
		}})
		if codeOf(t, err) != codeAccessDenied {
			t.Fatalf("bob basic auth read alice private: %v", err)
		}
	})
}

func TestCredentialRevocationAndRecovery(t *testing.T) {
	fix := newFixture(t)
	endpoint := fix.server.URL + "/api/mcp"
	res, err := http.DefaultClient.Do(mustReq(t, http.MethodGet, endpoint, http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), `resource_metadata=`) {
		t.Fatalf("missing bearer: %d %q %s", res.StatusCode, res.Header.Get("WWW-Authenticate"), body)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid bearer status = %d", res.StatusCode)
	}
	if strings.Contains(fix.logs.String(), "not-a-real-token") || strings.Contains(fix.logs.String(), fix.aliceToken) {
		t.Fatalf("log contains a bearer: %s", fix.logs.String())
	}

	meta, err := http.DefaultClient.Do(mustReq(t, http.MethodGet, fix.server.URL+"/.well-known/oauth-protected-resource/api/mcp", http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	metaBody, _ := io.ReadAll(meta.Body)
	_ = meta.Body.Close()
	if meta.StatusCode != http.StatusOK || !strings.Contains(string(metaBody), fix.base+"/api/mcp") || strings.Contains(string(metaBody), "authorization_servers") {
		t.Fatalf("metadata %d %s", meta.StatusCode, metaBody)
	}

	cs := fix.connect(t, endpoint, fix.aliceToken, "2025-03-26")
	if err := fix.db.RevokeSessions(t.Context(), fix.alice.ID); err != nil {
		t.Fatal(err)
	}
	_, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}})
	if err == nil {
		t.Fatal("revoked session still called a tool")
	}
	fresh, err := fix.db.CreateSession(t.Context(), fix.alice.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recovered := fix.connect(t, endpoint, fresh, "2026-07-28")
	if _, err := recovered.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}}); err != nil {
		t.Fatalf("recovered token: %v", err)
	}
	if _, err := recovered.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.bobPrivate.Path, "number": fix.bobMR.Number,
	}}); codeOf(t, err) != codeAccessDenied {
		t.Fatalf("recovered token saw bob repo: %v", err)
	}

	if err := fix.db.SetUserActive(t.Context(), fix.alice.ID, false); err != nil {
		t.Fatal(err)
	}
	_, err = recovered.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}})
	if err == nil {
		t.Fatal("deactivated user still called a tool")
	}
	if strings.Contains(fix.logs.String(), fresh) || strings.Contains(fix.logs.String(), fix.aliceToken) {
		t.Fatal("log contains a bearer after revocation")
	}
}

func TestSSEClientAndHijack(t *testing.T) {
	fix := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.SSEClientTransport{
		Endpoint:   fix.server.URL + "/api/mcp/sse",
		HTTPClient: bearerClient(fix.aliceToken),
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-03-26"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	negotiated := cs.InitializeResult().ProtocolVersion
	t.Logf("client github.com/modelcontextprotocol/go-sdk v1.8.0 HTTP+SSE negotiated %s", negotiated)
	if negotiated == "" || negotiated >= "2026-07-28" {
		t.Fatalf("SSE negotiated %q", negotiated)
	}
	if _, err := cs.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_mr_details", Arguments: map[string]any{
		"repo": fix.private.Path, "number": fix.mr.Number,
	}}); err != nil {
		t.Fatal(err)
	}

	modern, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.SSEClientTransport{
		Endpoint:   fix.server.URL + "/api/mcp/sse",
		HTTPClient: bearerClient(fix.aliceToken),
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Logf("SSE client requested 2026-07-28 and connect returned %v", err)
	} else {
		defer func() { _ = modern.Close() }()
		if got := modern.InitializeResult().ProtocolVersion; got >= "2026-07-28" {
			t.Fatalf("SSE served %q", got)
		}
		t.Logf("SSE client requested 2026-07-28 and negotiated %s", modern.InitializeResult().ProtocolVersion)
	}

	getCtx, getCancel := context.WithCancel(ctx)
	defer getCancel()
	req, err := http.NewRequestWithContext(getCtx, http.MethodGet, fix.server.URL+"/api/mcp/sse", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+fix.aliceToken)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 256)
	n, err := resp.Body.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) && n == 0 {
		t.Fatal(err)
	}
	event := string(buf[:n])
	if !strings.Contains(event, "event: endpoint") || !strings.Contains(event, "/api/mcp/messages?session=") {
		t.Fatalf("endpoint event = %q", event)
	}
	sessionURL := fix.server.URL + strings.TrimSpace(strings.TrimPrefix(strings.Split(event, "data:")[1], " "))
	sessionURL = strings.Split(sessionURL, "\n")[0]
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_review_comment","arguments":{"repo":"` + fix.private.Path + `","number":1,"path":"README","line":1,"body":"hijack"}}}`
	post, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sessionURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Authorization", "Bearer "+fix.bobToken)
	post.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(postResp.Body)
	_ = postResp.Body.Close()
	if postResp.StatusCode != http.StatusForbidden {
		t.Fatalf("hijack status = %d", postResp.StatusCode)
	}
	if got := fix.comments(t); got != 0 {
		t.Fatalf("hijack wrote %d comments", got)
	}
}

func TestMismatchedRequestIdentity(t *testing.T) {
	fix := newFixture(t)
	handler := sdkauth.RequireBearerToken(fix.srv.verifyBearer, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fix.srv.principal(r.Context(), &mcp.RequestExtra{TokenInfo: &sdkauth.TokenInfo{
			UserID:     fix.bob.ID,
			Expiration: time.Now().Add(time.Hour),
		}})
		if !errors.Is(err, errNoPrincipal) {
			t.Errorf("mismatched identity error = %v", err)
		}
		_, err = fix.srv.principal(r.Context(), &mcp.RequestExtra{TokenInfo: &sdkauth.TokenInfo{
			UserID:     fix.alice.ID,
			Expiration: time.Now().Add(time.Hour),
		}})
		if err != nil {
			t.Errorf("same identity rejected: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+fix.aliceToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

type fixture struct {
	db         *database.DB
	srv        *Server
	server     *httptest.Server
	logs       *bytes.Buffer
	base       string
	alice      domain.User
	bob        domain.User
	aliceToken string
	bobToken   string
	private    domain.Repository
	public     domain.Repository
	bobPrivate domain.Repository
	mr         domain.MergeRequest
	publicMR   domain.MergeRequest
	bobMR      domain.MergeRequest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := t.Context()
	db, err := database.Open(ctx, "sqlite::memory:")
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
	alice.Role = domain.RoleMember

	dir := t.TempDir()
	gitRun(t, dir, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "README")
	gitRun(t, dir, "commit", "-m", "init")
	sha := gitRun(t, dir, "rev-parse", "HEAD")
	publicDir := filepath.Join(t.TempDir(), "public")
	bobDir := filepath.Join(t.TempDir(), "bob")
	copyTree(t, dir, publicDir)
	copyTree(t, dir, bobDir)
	private, err := db.CreateRepo(ctx, alice.ID, "secret", "secret", "alice/secret", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	public, err := db.CreateRepo(ctx, alice.ID, "open", "open", "alice/open", publicDir, false)
	if err != nil {
		t.Fatal(err)
	}
	bobPrivate, err := db.CreateRepo(ctx, bob.ID, "notes", "notes", "bob/notes", bobDir, true)
	if err != nil {
		t.Fatal(err)
	}
	mr, err := db.CreateFederatedMR(ctx, private.ID, alice.ID, "forge://peer/secret", "feature", "main", "Secret change", "desc", "actor", "peer.example", sha)
	if err != nil {
		t.Fatal(err)
	}
	publicMR, err := db.CreateFederatedMR(ctx, public.ID, alice.ID, "forge://peer/open", "feature", "main", "Open change", "desc", "actor", "peer.example", sha)
	if err != nil {
		t.Fatal(err)
	}
	bobMR, err := db.CreateFederatedMR(ctx, bobPrivate.ID, bob.ID, "forge://peer/notes", "feature", "main", "Bob change", "desc", "actor", "peer.example", sha)
	if err != nil {
		t.Fatal(err)
	}
	aliceToken, err := db.CreateSession(ctx, alice.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bobToken, err := db.CreateSession(ctx, bob.ID, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const base = "http://127.0.0.1:8080"
	var logs bytes.Buffer
	svc := &auth.Service{
		DB:     db,
		Cfg:    config.Config{BaseURL: base},
		Tokens: auth.NewTokens(testKey(t), base, time.Hour),
		Log:    slog.New(slog.DiscardHandler),
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		DB:   db,
		Auth: svc,
		Git:  &gitengine.Manager{GitBinary: gitBin},
		Log:  slog.New(slog.NewTextHandler(&logs, nil)),
	}
	mux := http.NewServeMux()
	srv.Register(mux)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	return &fixture{
		db: db, srv: srv, server: httpServer, logs: &logs, base: base,
		alice: alice, bob: bob, aliceToken: aliceToken, bobToken: bobToken,
		private: private, public: public, bobPrivate: bobPrivate,
		mr: mr, publicMR: publicMR, bobMR: bobMR,
	}
}

func (f *fixture) connectBasic(t *testing.T, username, password, version string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   f.server.URL + "/api/mcp",
		HTTPClient: basicClient(username, password),
	}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("basic connect %s: %v", version, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (f *fixture) connect(t *testing.T, endpoint, token, version string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "knotwork-test", Version: "v1.8.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: bearerClient(token),
	}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("connect %s: %v", version, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (f *fixture) comments(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(t.Context(), `SELECT COUNT(1) FROM review_comments`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustReq(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func basicClient(username, password string) *http.Client {
	return &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.SetBasicAuth(username, password)
		return http.DefaultTransport.RoundTrip(clone)
	})}
}

func bearerClient(token string) *http.Client {
	return &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(clone)
	})}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func callText(t *testing.T, cs *mcp.ClientSession, name string, args any) string {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return resultText(t, res)
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) != 1 {
		t.Fatalf("content = %#v", res)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type %T", res.Content[0])
	}
	return text.Text
}

func codeOf(t *testing.T, err error) int64 {
	t.Helper()
	var je *jsonrpc.Error
	if errors.As(err, &je) {
		return je.Code
	}
	return 0
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "cp", "-a", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp %s: %v\n%s", src, err, out)
	}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Knotwork Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Knotwork Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
