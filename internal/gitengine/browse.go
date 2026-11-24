package gitengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	ErrInvalidRef  = errors.New("invalid git ref")
	ErrPathMissing = errors.New("path not found in revision")
	refPattern     = regexp.MustCompile(`^[a-zA-Z0-9_\-./]+$`)
)

// ValidateRef validates branch names, tags, and revisions against a strict
// alphanumeric regex (^[a-zA-Z0-9_\-./]+$), rejecting options (starting with -),
// control characters, path traversals (..), reflog queries (@{), or invalid
// edges. Empty, ".", and ".." path segments are rejected so the value cannot
// be mistaken for a Git option or escape the repository.
func ValidateRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == "HEAD" {
		return nil
	}
	if hasControlChars(ref) {
		return ErrInvalidRef
	}
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") {
		return ErrInvalidRef
	}
	if !refPattern.MatchString(ref) {
		return ErrInvalidRef
	}
	for _, segment := range strings.Split(ref, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrInvalidRef
		}
	}
	return nil
}

// ValidatePath rejects absolute paths, option-like paths, control characters,
// null bytes, and traversal when reading a blob.
func ValidatePath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") || strings.ContainsRune(p, '\x00') {
		return ErrPathMissing
	}
	if hasControlChars(p) {
		return ErrPathMissing
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ErrPathMissing
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrPathMissing
		}
	}
	return nil
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// IsEmpty reports whether diskPath has any commits.
func (m *Manager) IsEmpty(ctx context.Context, diskPath string) (bool, error) {
	cmd := m.Command(ctx, "-C", diskPath, "rev-list", "-n", "1", "--all")
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("git rev-list: %w", err)
	}
	return len(bytes.TrimSpace(out)) == 0, nil
}

// ListTree returns every blob path in ref, sorted by Git.
func (m *Manager) ListTree(ctx context.Context, diskPath, ref string) ([]string, error) {
	if ref == "" {
		ref = "HEAD"
	}
	if err := ValidateRef(ref); err != nil {
		return nil, err
	}
	cmd := m.Command(ctx, "-C", diskPath, "ls-tree", "-r", "-z", "--name-only", "--end-of-options", ref)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if empty, emptyErr := m.IsEmpty(ctx, diskPath); emptyErr == nil && empty {
			return []string{}, nil
		}
		return nil, fmt.Errorf("git ls-tree: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	entries := strings.Split(string(out), "\x00")
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry != "" {
			paths = append(paths, entry)
		}
	}
	return paths, nil
}

// ReadBlob returns the contents of path at ref together with a binary flag
// directly from object storage via plumbing without checkout or host execution.
func (m *Manager) ReadBlob(ctx context.Context, diskPath, ref, filePath string) ([]byte, bool, error) {
	if ref == "" {
		ref = "HEAD"
	}
	if err := ValidateRef(ref); err != nil {
		return nil, false, err
	}
	if err := ValidatePath(filePath); err != nil {
		return nil, false, err
	}
	cmd := m.Command(ctx, "-C", diskPath, "cat-file", "-p", "--end-of-options", ref+":"+filePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "Not a valid object name") || strings.Contains(errStr, "fatal: Not a valid object name") {
			return nil, false, ErrPathMissing
		}
		return nil, false, fmt.Errorf("git cat-file: %w: %s", err, strings.TrimSpace(errStr))
	}
	return out, isBinary(out), nil
}

func isBinary(data []byte) bool {
	sample := data
	if len(sample) > 8000 {
		sample = sample[:8000]
	}
	return bytes.IndexByte(sample, 0) >= 0
}

// DiffRange returns a unified patch between base and head. When base is empty
// the commit itself is shown as a patch.
func (m *Manager) DiffRange(ctx context.Context, diskPath, base, head string) ([]byte, error) {
	if err := ValidateRef(head); err != nil {
		return nil, err
	}
	var args []string
	if base != "" {
		if err := ValidateRef(base); err != nil {
			return nil, err
		}
		args = []string{"-C", diskPath, "diff", "--no-color", "--no-ext-diff", "--end-of-options", base + "..." + head, "--"}
	} else {
		args = []string{"-C", diskPath, "show", "--format=", "--no-color", "--no-ext-diff", "--patch", "--end-of-options", head, "--"}
	}
	cmd := m.Command(ctx, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ResolveCommit returns the first candidate that names a commit in diskPath.
func (m *Manager) ResolveCommit(ctx context.Context, diskPath string, candidates ...string) (string, error) {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if err := ValidateRef(candidate); err != nil {
			continue
		}
		cmd := m.Command(ctx, "-C", diskPath, "rev-parse", "--verify", "--quiet", "--end-of-options", candidate+"^{commit}")
		out, err := cmd.Output()
		if err == nil {
			if sha := strings.TrimSpace(string(out)); sha != "" {
				return sha, nil
			}
		}
	}
	return "", errors.New("no matching revision")
}
