package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"knotwork/internal/auth"
)

func tokenInfoFromContext(ctx context.Context) *sdkauth.TokenInfo {
	return sdkauth.TokenInfoFromContext(ctx)
}

// Register mounts stateless Streamable HTTP, the legacy SSE routes, and the
// RFC 9728 protected-resource metadata document. Every MCP HTTP request must
// carry an existing API token, either as a bearer or as HTTP Basic credentials
// (the password, or the username when the password is empty). That is the same
// token rule as Git Smart HTTP. Knotwork does not advertise an authorization
// server: OIDC access tokens are not API bearers.
func (s *Server) Register(mux *http.ServeMux) {
	base := strings.TrimRight(s.Auth.Cfg.BaseURL, "/")
	resource := base + "/api/mcp"
	metaURL := base + "/.well-known/oauth-protected-resource/api/mcp"
	// Method-specific patterns avoid conflicting with the Git Smart HTTP
	// catch-all "GET /" and "POST /" routes. An unmethoded pattern matches
	// more methods than those catch-alls and is rejected by ServeMux.
	meta := sdkauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               resource,
		ResourceName:           "Knotwork",
		BearerMethodsSupported: []string{"header"},
	})
	mux.Handle("GET /.well-known/oauth-protected-resource/api/mcp", meta)
	mux.Handle("OPTIONS /.well-known/oauth-protected-resource/api/mcp", meta)

	protect := s.requireCredential(metaURL)
	stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return s.protocol()
	}, &mcp.StreamableHTTPOptions{
		Stateless: true,
		Logger:    s.logger(),
	})
	// GET and DELETE are part of the streamable handler. Stateless mode
	// answers them with 405, which is what current clients expect.
	wrapped := protect(stream)
	mux.Handle("POST /api/mcp", wrapped)
	mux.Handle("GET /api/mcp", wrapped)
	mux.Handle("DELETE /api/mcp", wrapped)
	mux.Handle("GET /api/mcp/sse", protect(http.HandlerFunc(s.sseGET)))
	mux.Handle("POST /api/mcp/messages", protect(http.HandlerFunc(s.ssePOST)))
}

// requireCredential accepts an API bearer or the HTTP Basic form of that same
// token. Basic credentials are checked by the bearer verifier so the SDK still
// stores TokenInfo on the request. The raw token is not logged.
func (s *Server) requireCredential(metadataURL string) func(http.Handler) http.Handler {
	bearer := sdkauth.RequireBearerToken(s.verifyBearer, &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: metadataURL,
	})
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok {
				bearer(next).ServeHTTP(w, r)
				return
			}
			token := password
			if token == "" {
				token = username
			}
			if token == "" || strings.ContainsAny(token, "\r\n") {
				s.logger().InfoContext(r.Context(), "mcp credential refused")
				if metadataURL != "" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q", metadataURL))
				}
				w.Header().Add("WWW-Authenticate", `Basic realm="Knotwork"`)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			clone := r.Clone(r.Context())
			clone.Header.Set("Authorization", "Bearer "+token)
			bearer(next).ServeHTTP(&basicChallengeWriter{ResponseWriter: w}, clone)
		})
	}
}

// basicChallengeWriter adds the Git Smart HTTP Basic challenge beside the
// SDK's bearer challenge when this request authenticated with HTTP Basic.
type basicChallengeWriter struct {
	http.ResponseWriter
}

func (w *basicChallengeWriter) WriteHeader(status int) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		w.Header().Add("WWW-Authenticate", `Basic realm="Knotwork"`)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *basicChallengeWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *basicChallengeWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (s *Server) verifyBearer(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
	if s == nil || s.Auth == nil {
		return nil, sdkauth.ErrInvalidToken
	}
	principal, err := s.Auth.PrincipalFromBearer(ctx, token)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidBearer) {
			s.logger().InfoContext(ctx, "mcp credential refused")
			return nil, sdkauth.ErrInvalidToken
		}
		return nil, err
	}
	return &sdkauth.TokenInfo{
		Scopes:     principal.Scopes,
		Expiration: principal.Expiration,
		UserID:     principal.User.ID,
	}, nil
}

func (s *Server) sseGET(w http.ResponseWriter, r *http.Request) {
	info := tokenInfoFromContext(r.Context())
	if info == nil || info.UserID == "" || s.DB == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	user, err := s.DB.GetUserByID(r.Context(), info.UserID)
	if err != nil || !user.IsActive {
		s.logger().InfoContext(r.Context(), "mcp credential refused")
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	id, err := newSessionID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	transport := &mcp.SSEServerTransport{
		Endpoint: "/api/mcp/messages?session=" + id,
		Response: w,
	}
	s.mu.Lock()
	if s.streams == nil {
		s.streams = map[string]*sseStream{}
	}
	s.streams[id] = &sseStream{userID: user.ID, transport: transport}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.streams, id)
		s.mu.Unlock()
	}()

	session, err := s.protocol().Connect(r.Context(), transport, nil)
	if err != nil {
		http.Error(w, "connection failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = session.Close() }()
	<-r.Context().Done()
}

func (s *Server) ssePOST(w http.ResponseWriter, r *http.Request) {
	info := tokenInfoFromContext(r.Context())
	if info == nil || info.UserID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	sessionID := r.URL.Query().Get("session")
	s.mu.Lock()
	stream := s.streams[sessionID]
	s.mu.Unlock()
	if stream == nil || stream.transport == nil {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}
	if stream.userID != info.UserID {
		http.Error(w, "MCP session does not belong to this bearer", http.StatusForbidden)
		return
	}
	stream.transport.ServeHTTP(w, r)
}

func newSessionID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// ServeStdio serves one stdio session bound to token. token must already be an
// existing API bearer. The process does not accept a caller-supplied user id.
func (s *Server) ServeStdio(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" || s.Auth == nil {
		return auth.ErrInvalidBearer
	}
	if _, err := s.Auth.PrincipalFromBearer(ctx, token); err != nil {
		if errors.Is(err, auth.ErrInvalidBearer) {
			return auth.ErrInvalidBearer
		}
		return err
	}
	s.stdioToken = token
	err := s.protocol().Run(ctx, &mcp.StdioTransport{})
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
