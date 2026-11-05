package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"knotwork/internal/database"
	"knotwork/internal/domain"
	"knotwork/internal/gitengine"
)

// codeAccessDenied is the code the previous handwritten server returned for a
// repository permission failure. JSON-RPC reserves -32000 to -32099 for
// implementation-defined server errors.
const codeAccessDenied int64 = -32001

func (s *Server) addTools(srv *mcp.Server) {
	srv.AddTool(&mcp.Tool{
		Name:        "get_mr_details",
		Description: "Get a merge request, including federated origin metadata.",
		InputSchema: objectSchema(map[string]any{
			"repo":   map[string]any{"type": "string", "description": "owner/repo"},
			"number": map[string]any{"type": "integer"},
		}, "repo", "number"),
	}, s.getMRDetails)
	srv.AddTool(&mcp.Tool{
		Name:        "create_review_comment",
		Description: "Create a review comment on a merge request.",
		InputSchema: objectSchema(map[string]any{
			"repo":   map[string]any{"type": "string"},
			"number": map[string]any{"type": "integer"},
			"path":   map[string]any{"type": "string"},
			"line":   map[string]any{"type": "integer"},
			"body":   map[string]any{"type": "string"},
		}, "repo", "number", "path", "line", "body"),
	}, s.createReviewComment)
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": properties,
		"required":   required,
	}
}

type mrArgs struct {
	Repo   string `json:"repo"`
	Number int64  `json:"number"`
}

type commentArgs struct {
	Repo   string `json:"repo"`
	Number int64  `json:"number"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Body   string `json:"body"`
}

func (s *Server) getMRDetails(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user, err := s.principal(ctx, req.GetExtra())
	if s.refuse(ctx, err) {
		return nil, rpcErr(codeAccessDenied, "authentication required")
	}
	var args mrArgs
	if err := decodeArgs(req, &args, "repo", "number"); err != nil {
		return nil, err
	}
	mr, _, err := s.loadMR(ctx, user, args.Repo, args.Number)
	if err != nil {
		return nil, err
	}
	return textResult(mr)
}

func (s *Server) createReviewComment(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user, err := s.principal(ctx, req.GetExtra())
	if s.refuse(ctx, err) {
		return nil, rpcErr(codeAccessDenied, "authentication required")
	}
	var args commentArgs
	if err := decodeArgs(req, &args, "repo", "number", "path", "line", "body"); err != nil {
		return nil, err
	}
	if args.Path == "" || args.Body == "" {
		return nil, rpcErr(jsonrpc.CodeInvalidParams, "path and body are required")
	}
	mr, role, err := s.loadMR(ctx, user, args.Repo, args.Number)
	if err != nil {
		return nil, err
	}
	if role != "admin" && role != "write" {
		return nil, rpcErr(codeAccessDenied, "write access required")
	}
	id, err := s.DB.CreateReviewComment(ctx, mr.ID, user.ID, args.Path, args.Line, args.Body)
	if err != nil {
		s.logger().InfoContext(ctx, "mcp comment write failed")
		return nil, rpcErr(jsonrpc.CodeInternalError, "could not create comment")
	}
	return textResult(map[string]string{"id": id})
}

func decodeArgs(req *mcp.CallToolRequest, dest any, required ...string) error {
	if req == nil || req.Params == nil || len(req.Params.Arguments) == 0 {
		return rpcErr(jsonrpc.CodeInvalidParams, "invalid tool arguments")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(req.Params.Arguments, &raw); err != nil || raw == nil {
		return rpcErr(jsonrpc.CodeInvalidParams, "invalid tool arguments")
	}
	for _, key := range required {
		if _, ok := raw[key]; !ok {
			return rpcErr(jsonrpc.CodeInvalidParams, "invalid tool arguments")
		}
	}
	if err := json.Unmarshal(req.Params.Arguments, dest); err != nil {
		return rpcErr(jsonrpc.CodeInvalidParams, "invalid tool arguments")
	}
	return nil
}

func (s *Server) loadMR(ctx context.Context, user domain.User, repoPath string, number int64) (domain.MergeRequest, string, error) {
	if strings.TrimSpace(repoPath) == "" || number <= 0 {
		return domain.MergeRequest{}, "", rpcErr(jsonrpc.CodeInvalidParams, "invalid tool arguments")
	}
	repo, err := s.DB.GetRepoByPath(ctx, repoPath)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return domain.MergeRequest{}, "", rpcErr(jsonrpc.CodeInvalidParams, "repository not found")
		}
		return domain.MergeRequest{}, "", rpcErr(jsonrpc.CodeInternalError, "could not load repository")
	}
	role, err := s.DB.RepoRole(ctx, repo, user)
	if err != nil {
		return domain.MergeRequest{}, "", rpcErr(jsonrpc.CodeInternalError, "could not resolve permissions")
	}
	if role == "" {
		return domain.MergeRequest{}, "", rpcErr(codeAccessDenied, "repository access denied")
	}
	mr, err := s.DB.GetMRByNumber(ctx, repo.ID, number)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return domain.MergeRequest{}, "", rpcErr(jsonrpc.CodeInvalidParams, "merge request not found")
		}
		return domain.MergeRequest{}, "", rpcErr(jsonrpc.CodeInternalError, "could not load merge request")
	}
	return mr, role, nil
}

func (s *Server) addResources(srv *mcp.Server) {
	templates := []struct {
		name string
		uri  string
	}{
		{name: "knotwork-tree", uri: "knotwork://{owner}/{repo}/tree/{+ref}"},
		{name: "knotwork-diff", uri: "knotwork://{owner}/{repo}/diff/{number}"},
		{name: "forge-tree", uri: "forge://{owner}/{repo}/tree/{+ref}"},
		{name: "forge-diff", uri: "forge://{owner}/{repo}/diff/{number}"},
	}
	for _, tmpl := range templates {
		srv.AddResourceTemplate(&mcp.ResourceTemplate{
			Name:        tmpl.name,
			URITemplate: tmpl.uri,
			MIMEType:    "text/plain",
			Description: "Knotwork repository resource",
		}, s.readResource)
	}
}

func (s *Server) resourceListMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != "resources/list" {
			return next(ctx, method, req)
		}
		user, err := s.principal(ctx, req.GetExtra())
		if s.refuse(ctx, err) {
			return nil, rpcErr(codeAccessDenied, "authentication required")
		}
		repos, err := s.DB.ListRepos(ctx)
		if err != nil {
			return nil, rpcErr(jsonrpc.CodeInternalError, "could not list repositories")
		}
		resources := make([]*mcp.Resource, 0, len(repos))
		for _, repo := range repos {
			role, roleErr := s.DB.RepoRole(ctx, repo, user)
			if roleErr != nil || role == "" {
				continue
			}
			resources = append(resources, &mcp.Resource{
				URI:         "knotwork://" + repo.Path + "/tree/HEAD",
				Name:        repo.Path,
				Description: "Repository tree at HEAD",
				MIMEType:    "text/plain",
			})
		}
		return &mcp.ListResourcesResult{Resources: resources}, nil
	}
}

func (s *Server) readResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	user, err := s.principal(ctx, req.GetExtra())
	if s.refuse(ctx, err) {
		return nil, rpcErr(codeAccessDenied, "authentication required")
	}
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	text, err := s.resourceText(ctx, user, uri)
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI:      uri,
		MIMEType: "text/plain",
		Text:     text,
	}}}, nil
}

func (s *Server) resourceText(ctx context.Context, user domain.User, uri string) (string, error) {
	repoPath, kind, rest, err := parseResourceURI(uri)
	if err != nil {
		return "", rpcErr(jsonrpc.CodeInvalidParams, "invalid resource URI")
	}
	repo, err := s.DB.GetRepoByPath(ctx, repoPath)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return "", rpcErr(jsonrpc.CodeInvalidParams, "repository not found")
		}
		return "", rpcErr(jsonrpc.CodeInternalError, "could not load repository")
	}
	role, err := s.DB.RepoRole(ctx, repo, user)
	if err != nil {
		return "", rpcErr(jsonrpc.CodeInternalError, "could not resolve permissions")
	}
	if role == "" {
		return "", rpcErr(codeAccessDenied, "repository access denied")
	}
	switch kind {
	case "tree":
		if rest == "" || gitengine.ValidateRef(rest) != nil {
			return "", rpcErr(jsonrpc.CodeInvalidParams, "invalid resource URI")
		}
		if s.Git == nil {
			s.logger().InfoContext(ctx, "mcp tree read failed")
			return "", rpcErr(jsonrpc.CodeInternalError, "could not read tree")
		}
		paths, err := s.Git.ListTree(ctx, repo.DiskPath, rest)
		if err != nil {
			if errors.Is(err, gitengine.ErrInvalidRef) {
				return "", rpcErr(jsonrpc.CodeInvalidParams, "invalid resource URI")
			}
			s.logger().InfoContext(ctx, "mcp tree read failed")
			return "", rpcErr(jsonrpc.CodeInternalError, "could not read tree")
		}
		return strings.Join(paths, "\n") + "\n", nil
	case "diff":
		number, err := strconv.ParseInt(rest, 10, 64)
		if err != nil || number <= 0 {
			return "", rpcErr(jsonrpc.CodeInvalidParams, "invalid merge request number")
		}
		mr, err := s.DB.GetMRByNumber(ctx, repo.ID, number)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				return "", rpcErr(jsonrpc.CodeInvalidParams, "merge request not found")
			}
			return "", rpcErr(jsonrpc.CodeInternalError, "could not load merge request")
		}
		if gitengine.ValidateRef(mr.HeadSHA) != nil {
			return "", rpcErr(jsonrpc.CodeInvalidParams, "invalid merge request")
		}
		if s.Git == nil {
			s.logger().InfoContext(ctx, "mcp diff read failed")
			return "", rpcErr(jsonrpc.CodeInternalError, "could not read diff")
		}
		patch, err := s.Git.DiffRange(ctx, repo.DiskPath, "", mr.HeadSHA)
		if err != nil {
			if errors.Is(err, gitengine.ErrInvalidRef) {
				return "", rpcErr(jsonrpc.CodeInvalidParams, "invalid merge request")
			}
			s.logger().InfoContext(ctx, "mcp diff read failed")
			return "", rpcErr(jsonrpc.CodeInternalError, "could not read diff")
		}
		return string(patch), nil
	default:
		return "", rpcErr(jsonrpc.CodeInvalidParams, "unsupported resource")
	}
}

func parseResourceURI(uri string) (repoPath, kind, rest string, err error) {
	var body string
	switch {
	case strings.HasPrefix(uri, "knotwork://"):
		body = strings.TrimPrefix(uri, "knotwork://")
	case strings.HasPrefix(uri, "forge://"):
		body = strings.TrimPrefix(uri, "forge://")
	default:
		return "", "", "", errInvalidURI
	}
	parts := strings.SplitN(body, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", errInvalidURI
	}
	switch {
	case strings.HasPrefix(parts[2], "tree/"):
		return parts[0] + "/" + parts[1], "tree", strings.TrimPrefix(parts[2], "tree/"), nil
	case strings.HasPrefix(parts[2], "diff/"):
		return parts[0] + "/" + parts[1], "diff", strings.TrimPrefix(parts[2], "diff/"), nil
	default:
		return "", "", "", errInvalidURI
	}
}

var errInvalidURI = errors.New("invalid resource URI")

func textResult(v any) (*mcp.CallToolResult, error) {
	text, err := indented(v)
	if err != nil {
		return nil, rpcErr(jsonrpc.CodeInternalError, "could not encode result")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil
}

func indented(v any) (string, error) {
	if text, ok := v.(string); ok {
		return text, nil
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func rpcErr(code int64, message string) error {
	return &jsonrpc.Error{Code: code, Message: message}
}
