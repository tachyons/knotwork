package mcp

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"knotwork/internal/auth"
	"knotwork/internal/database"
	"knotwork/internal/domain"
	"knotwork/internal/gitengine"
)

const (
	serverName    = "knotwork"
	serverVersion = "0.1.0"
)

// errNoPrincipal means this call has no acceptable credential.
// Handlers must not fall back to an administrator.
var errNoPrincipal = errors.New("mcp credential refused")

// Server serves MCP over stateless Streamable HTTP, legacy SSE, and stdio.
// Permissions are loaded from the database on every call. streams records only
// the user id that opened an SSE connection so a later POST cannot hijack it;
// it is not the source of repository permissions.
type Server struct {
	DB   *database.DB
	Auth *auth.Service
	Git  *gitengine.Manager
	Log  *slog.Logger

	// stdioToken is set only by ServeStdio. HTTP leaves it empty. The value is
	// revalidated on every call and is never logged.
	stdioToken string

	mu      sync.Mutex
	streams map[string]*sseStream

	once  sync.Once
	proto *mcp.Server
}

type sseStream struct {
	userID    string
	transport *mcp.SSEServerTransport
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (s *Server) protocol() *mcp.Server {
	s.once.Do(func() {
		srv := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, &mcp.ServerOptions{
			Logger: s.logger(),
		})
		s.addTools(srv)
		s.addResources(srv)
		srv.AddReceivingMiddleware(s.resourceListMiddleware)
		s.proto = srv
	})
	return s.proto
}

// principal resolves the user for this call. A stdio process uses only its
// configured bearer. HTTP uses the credential attached to this request and
// refuses when the transport metadata and the request context name different users.
func (s *Server) principal(ctx context.Context, extra *mcp.RequestExtra) (domain.User, error) {
	if s.stdioToken != "" {
		p, err := s.Auth.PrincipalFromBearer(ctx, s.stdioToken)
		if err != nil {
			return domain.User{}, errNoPrincipal
		}
		return p.User, nil
	}
	var extraID, ctxID string
	if extra != nil && extra.TokenInfo != nil {
		extraID = extra.TokenInfo.UserID
	}
	if info := tokenInfoFromContext(ctx); info != nil {
		ctxID = info.UserID
	}
	if extraID != "" && ctxID != "" && extraID != ctxID {
		return domain.User{}, errNoPrincipal
	}
	id := extraID
	if id == "" {
		id = ctxID
	}
	if id == "" || s.DB == nil {
		return domain.User{}, errNoPrincipal
	}
	user, err := s.DB.GetUserByID(ctx, id)
	if err != nil || !user.IsActive {
		return domain.User{}, errNoPrincipal
	}
	return user, nil
}

func (s *Server) refuse(ctx context.Context, err error) bool {
	if err == nil || !errors.Is(err, errNoPrincipal) {
		return false
	}
	s.logger().InfoContext(ctx, "mcp credential refused")
	return true
}
