package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"knotwork/internal/domain"
)

var ErrNotFound = sql.ErrNoRows

const userCols = `id, COALESCE(external_id, ''), COALESCE(scim_id, ''), username, email, display_name,
	role, is_active, COALESCE(public_key, ''), created_at, updated_at`

const prefixedUserCols = `u.id, COALESCE(u.external_id, ''), COALESCE(u.scim_id, ''), u.username, u.email, u.display_name,
	u.role, u.is_active, COALESCE(u.public_key, ''), u.created_at, u.updated_at`

func scanUser(row interface{ Scan(...any) error }) (domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.ExternalID, &u.SCIMID, &u.Username, &u.Email, &u.DisplayName,
		&u.Role, &u.IsActive, &u.PublicKey, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

// UpsertOIDCUser provisions a user just-in-time. The first user on a fresh
// instance becomes the instance admin; deactivated users stay deactivated.
func (d *DB) UpsertOIDCUser(ctx context.Context, externalID, email, username, displayName string) (domain.User, error) {
	now := Now()
	first, err := d.CountUsers(ctx)
	if err != nil {
		return domain.User{}, err
	}
	role := domain.RoleMember
	if first == 0 {
		role = domain.RoleAdmin
	}
	_, err = d.ExecContext(ctx, d.q(`INSERT INTO users
		(id, external_id, username, email, display_name, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT (external_id) DO UPDATE SET
			username = excluded.username,
			email = excluded.email,
			display_name = excluded.display_name,
			updated_at = excluded.updated_at`),
		NewID(), externalID, username, email, displayName, role, now, now)
	if err != nil {
		return domain.User{}, err
	}
	return d.GetUserByExternalID(ctx, externalID)
}

func (d *DB) GetUserByExternalID(ctx context.Context, externalID string) (domain.User, error) {
	return scanUser(d.QueryRowContext(ctx, d.q(`SELECT `+userCols+` FROM users WHERE external_id = ?`), externalID))
}

func (d *DB) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	return scanUser(d.QueryRowContext(ctx, d.q(`SELECT `+userCols+` FROM users WHERE id = ?`), id))
}

func (d *DB) GetUserBySCIMID(ctx context.Context, scimID string) (domain.User, error) {
	return scanUser(d.QueryRowContext(ctx, d.q(`SELECT `+userCols+` FROM users WHERE scim_id = ?`), scimID))
}

func (d *DB) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	return scanUser(d.QueryRowContext(ctx, d.q(`SELECT `+userCols+` FROM users WHERE lower(email) = lower(?)`), email))
}

func (d *DB) UpdateSCIMUser(ctx context.Context, scimID, email, username, displayName string) error {
	_, err := d.ExecContext(ctx, d.q(`UPDATE users SET email = ?, username = ?, display_name = ?, updated_at = ?
		WHERE scim_id = ?`), email, username, displayName, Now(), scimID)
	return err
}

func (d *DB) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) SetUserRole(ctx context.Context, id, role string) error {
	_, err := d.ExecContext(ctx, d.q(`UPDATE users SET role = ?, updated_at = ? WHERE id = ?`), role, Now(), id)
	return err
}

func (d *DB) CreateSCIMUser(ctx context.Context, scimID, email, username, displayName string) (domain.User, error) {
	now := Now()
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO users
		(id, scim_id, username, email, display_name, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`), NewID(), scimID, username, email, displayName, domain.RoleMember, now, now)
	if err != nil {
		return domain.User{}, err
	}
	return d.GetUserBySCIMID(ctx, scimID)
}

// SetUserActive deactivates a user and revokes every live session immediately.
func (d *DB) SetUserActive(ctx context.Context, id string, active bool) error {
	now := Now()
	if _, err := d.ExecContext(ctx, d.q(`UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?`), boolInt(active), now, id); err != nil {
		return err
	}
	if !active {
		return d.RevokeSessions(ctx, id)
	}
	return nil
}

func (d *DB) CreateSession(ctx context.Context, userID, kind string, ttl time.Duration) (string, error) {
	raw := NewToken()
	now := time.Now().UTC()
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO sessions
		(id, user_id, token_hash, kind, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
		NewID(), userID, hashToken(raw), kind, now.Add(ttl).Format(TimeLayout), now.Format(TimeLayout))
	if err != nil {
		return "", err
	}
	return raw, nil
}

func (d *DB) UserForSession(ctx context.Context, rawToken string) (domain.User, error) {
	return scanUser(d.QueryRowContext(ctx, d.q(`SELECT `+prefixedUserCols+` FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.kind <> 'break_glass' AND u.is_active = 1`),
		hashToken(rawToken), Now()))
}

// SessionPrincipal resolves a live, non-break-glass session and its expiry.
// Callers that must reject a missing expiration (MCP bearer checks) use this
// instead of UserForSession, which does not return expires_at.
func (d *DB) SessionPrincipal(ctx context.Context, rawToken string) (domain.User, time.Time, error) {
	var user domain.User
	var expires string
	err := d.QueryRowContext(ctx, d.q(`SELECT `+prefixedUserCols+`, s.expires_at FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.kind <> 'break_glass' AND u.is_active = 1`),
		hashToken(rawToken), Now()).Scan(
		&user.ID, &user.ExternalID, &user.SCIMID, &user.Username, &user.Email, &user.DisplayName,
		&user.Role, &user.IsActive, &user.PublicKey, &user.CreatedAt, &user.UpdatedAt, &expires)
	if err != nil {
		return domain.User{}, time.Time{}, err
	}
	expiresAt, err := time.ParseInLocation(TimeLayout, expires, time.UTC)
	if err != nil {
		return domain.User{}, time.Time{}, err
	}
	return user, expiresAt, nil
}

// UserForBreakGlass resolves a still-valid, single-use break-glass token.
func (d *DB) UserForBreakGlass(ctx context.Context, rawToken string) (domain.User, error) {
	return scanUser(d.QueryRowContext(ctx, d.q(`SELECT `+prefixedUserCols+` FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.kind = 'break_glass' AND u.is_active = 1`),
		hashToken(rawToken), Now()))
}

// RevokeSessions revokes all sessions for userID, or every session when userID is empty.
func (d *DB) RevokeSessions(ctx context.Context, userID string) error {
	now := Now()
	if userID == "" {
		_, err := d.ExecContext(ctx, d.q(`UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL`), now)
		return err
	}
	_, err := d.ExecContext(ctx, d.q(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`), now, userID)
	return err
}

func (d *DB) DeleteSession(ctx context.Context, rawToken string) error {
	_, err := d.ExecContext(ctx, d.q(`DELETE FROM sessions WHERE token_hash = ?`), hashToken(rawToken))
	return err
}

// ConsumeBreakGlass atomically resolves and deletes a break-glass token.
func (d *DB) ConsumeBreakGlass(ctx context.Context, rawToken string) (domain.User, time.Time, error) {
	var userID, expires string
	err := d.QueryRowContext(ctx, d.q(`SELECT user_id, expires_at FROM sessions
		WHERE token_hash = ? AND kind = 'break_glass' AND revoked_at IS NULL AND expires_at > ?`),
		hashToken(rawToken), Now()).Scan(&userID, &expires)
	if err != nil {
		return domain.User{}, time.Time{}, err
	}
	if _, err := d.ExecContext(ctx, d.q(`DELETE FROM sessions WHERE token_hash = ?`), hashToken(rawToken)); err != nil {
		return domain.User{}, time.Time{}, err
	}
	expiresAt, err := time.ParseInLocation(TimeLayout, expires, time.UTC)
	if err != nil {
		return domain.User{}, time.Time{}, err
	}
	user, err := d.GetUserByID(ctx, userID)
	return user, expiresAt, err
}

func (d *DB) CreateDeviceCode(ctx context.Context, ttl time.Duration) (deviceCode, userCode string, err error) {
	now := time.Now().UTC()
	expires := now.Add(ttl).Format(TimeLayout)
	for attempt := 0; attempt < 5; attempt++ {
		deviceCode = NewToken()
		userCode = NewUserCode()
		_, err = d.ExecContext(ctx, d.q(`INSERT INTO device_codes
			(device_code, user_code, status, expires_at, created_at) VALUES (?, ?, 'pending', ?, ?)`),
			deviceCode, userCode, expires, now.Format(TimeLayout))
		if err == nil {
			return deviceCode, userCode, nil
		}
	}
	return "", "", err
}

func (d *DB) ApproveDeviceCode(ctx context.Context, userCode, userID string) (bool, error) {
	res, err := d.ExecContext(ctx, d.q(`UPDATE device_codes SET status = 'approved', user_id = ?
		WHERE user_code = ? AND status = 'pending' AND expires_at > ?`),
		userID, strings.ToUpper(strings.TrimSpace(userCode)), Now())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (d *DB) DeviceCodeStatus(ctx context.Context, deviceCode string) (status string, err error) {
	err = d.QueryRowContext(ctx, d.q(`SELECT status FROM device_codes WHERE device_code = ? AND expires_at > ?`),
		deviceCode, Now()).Scan(&status)
	return status, err
}

// ConsumeDeviceCode returns the approved user and deletes the code.
func (d *DB) ConsumeDeviceCode(ctx context.Context, deviceCode string) (domain.User, error) {
	var userID string
	err := d.QueryRowContext(ctx, d.q(`SELECT COALESCE(user_id, '') FROM device_codes
		WHERE device_code = ? AND status = 'approved' AND expires_at > ?`), deviceCode, Now()).Scan(&userID)
	if err != nil {
		return domain.User{}, err
	}
	if userID == "" {
		return domain.User{}, errors.New("device code has no user")
	}
	if _, err := d.ExecContext(ctx, d.q(`DELETE FROM device_codes WHERE device_code = ?`), deviceCode); err != nil {
		return domain.User{}, err
	}
	return d.GetUserByID(ctx, userID)
}

func (d *DB) CreateRepo(ctx context.Context, ownerID, name, description, path, diskPath string, private bool) (domain.Repository, error) {
	now := Now()
	id := NewID()
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO repositories
		(id, owner_id, name, description, path, disk_path, is_private, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		id, ownerID, name, description, path, diskPath, boolInt(private), now, now)
	if err != nil {
		return domain.Repository{}, err
	}
	return d.GetRepoByID(ctx, id)
}

const repoCols = `id, owner_id, name, description, path, disk_path, is_private, default_branch,
	protected_branches, COALESCE(last_bundle_at, ''), created_at, updated_at`

func scanRepo(row interface{ Scan(...any) error }) (domain.Repository, error) {
	var r domain.Repository
	err := row.Scan(&r.ID, &r.OwnerID, &r.Name, &r.Description, &r.Path, &r.DiskPath, &r.IsPrivate,
		&r.DefaultBranch, &r.ProtectedBranches, &r.LastBundleAt, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

func (d *DB) GetRepoByID(ctx context.Context, id string) (domain.Repository, error) {
	return scanRepo(d.QueryRowContext(ctx, d.q(`SELECT `+repoCols+` FROM repositories WHERE id = ?`), id))
}

func (d *DB) GetRepoByPath(ctx context.Context, path string) (domain.Repository, error) {
	return scanRepo(d.QueryRowContext(ctx, d.q(`SELECT `+repoCols+` FROM repositories WHERE path = ?`), path))
}

func (d *DB) GetRepoByDiskPath(ctx context.Context, diskPath string) (domain.Repository, error) {
	return scanRepo(d.QueryRowContext(ctx, d.q(`SELECT `+repoCols+` FROM repositories WHERE disk_path = ?`), diskPath))
}

func (d *DB) ListRepos(ctx context.Context) ([]domain.Repository, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+repoCols+` FROM repositories ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []domain.Repository
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) SetProtectedBranches(ctx context.Context, repoID, branches string) error {
	_, err := d.ExecContext(ctx, d.q(`UPDATE repositories SET protected_branches = ?, updated_at = ? WHERE id = ?`), branches, Now(), repoID)
	return err
}

func (d *DB) MarkBundled(ctx context.Context, repoID string) error {
	_, err := d.ExecContext(ctx, d.q(`UPDATE repositories SET last_bundle_at = ? WHERE id = ?`), Now(), repoID)
	return err
}

// RepoRole returns "admin", "write" or "read" for a user. The owner and
// instance admins are always "admin"; public repos grant "read" to everyone.
func (d *DB) RepoRole(ctx context.Context, repo domain.Repository, user domain.User) (string, error) {
	if user.IsAdmin() || repo.OwnerID == user.ID {
		return "admin", nil
	}
	var role string
	err := d.QueryRowContext(ctx, d.q(`SELECT role FROM repo_collaborators WHERE repo_id = ? AND user_id = ?`),
		repo.ID, user.ID).Scan(&role)
	if err == nil {
		return role, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	if !repo.IsPrivate {
		return "read", nil
	}
	return "", nil
}

func (d *DB) CreateFederatedMR(ctx context.Context, repoID, authorID, sourceRepoURI, sourceBranch, target, title, description, actorID, originDomain, headSHA string) (domain.MergeRequest, error) {
	var maxNum sql.NullInt64
	if err := d.QueryRowContext(ctx, d.q(`SELECT MAX(number) FROM merge_requests WHERE target_repo_id = ?`), repoID).Scan(&maxNum); err != nil {
		return domain.MergeRequest{}, err
	}
	now := Now()
	id := NewID()
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO merge_requests
		(id, target_repo_id, number, author_id, source_repo_uri, source_branch, target_branch, title, description,
		 state, is_federated, federated_actor_id, origin_domain, head_sha, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?, ?, ?, ?)`),
		id, repoID, maxNum.Int64+1, nullString(authorID), sourceRepoURI, sourceBranch, target, title, description,
		actorID, originDomain, headSHA, now, now)
	if err != nil {
		return domain.MergeRequest{}, err
	}
	return d.GetMRByID(ctx, id)
}

const mrCols = `id, target_repo_id, number, COALESCE(author_id, ''), source_repo_uri, source_branch, target_branch,
	title, description, state, is_federated, federated_actor_id, origin_domain, head_sha, created_at, updated_at`

func scanMR(row interface{ Scan(...any) error }) (domain.MergeRequest, error) {
	var m domain.MergeRequest
	err := row.Scan(&m.ID, &m.RepoID, &m.Number, &m.AuthorID, &m.SourceRepoURI, &m.SourceBranch, &m.TargetBranch,
		&m.Title, &m.Description, &m.State, &m.IsFederated, &m.FederatedActor, &m.OriginDomain, &m.HeadSHA, &m.CreatedAt, &m.UpdatedAt)
	return m, err
}

func (d *DB) GetMRByID(ctx context.Context, id string) (domain.MergeRequest, error) {
	return scanMR(d.QueryRowContext(ctx, d.q(`SELECT `+mrCols+` FROM merge_requests WHERE id = ?`), id))
}

func (d *DB) GetMRByNumber(ctx context.Context, repoID string, number int64) (domain.MergeRequest, error) {
	return scanMR(d.QueryRowContext(ctx, d.q(`SELECT `+mrCols+` FROM merge_requests WHERE target_repo_id = ? AND number = ?`), repoID, number))
}

func (d *DB) ListMRs(ctx context.Context, repoID string) ([]domain.MergeRequest, error) {
	rows, err := d.QueryContext(ctx, d.q(`SELECT `+mrCols+` FROM merge_requests WHERE target_repo_id = ? ORDER BY number DESC`), repoID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []domain.MergeRequest
	for rows.Next() {
		m, err := scanMR(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) CreateReviewComment(ctx context.Context, mrID, authorID, path string, line int, body string) (string, error) {
	id := NewID()
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO review_comments (id, mr_id, author_id, path, line, body, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`), id, mrID, nullString(authorID), path, line, body, Now())
	return id, err
}

func (d *DB) CreatePipeline(ctx context.Context, repoID, mrID, sha, ref, status string, requiresApproval bool) (domain.Pipeline, error) {
	id := NewID()
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO pipelines
		(id, repo_id, mr_id, commit_sha, ref_name, status, requires_approval, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		id, repoID, nullString(mrID), sha, ref, status, boolInt(requiresApproval), Now())
	if err != nil {
		return domain.Pipeline{}, err
	}
	return d.GetPipeline(ctx, id)
}

const pipelineCols = `id, repo_id, COALESCE(mr_id, ''), commit_sha, ref_name, status, requires_approval,
	COALESCE(approved_by, ''), COALESCE(approved_at, ''), created_at, COALESCE(finished_at, '')`

func (d *DB) GetPipeline(ctx context.Context, id string) (domain.Pipeline, error) {
	var p domain.Pipeline
	err := d.QueryRowContext(ctx, d.q(`SELECT `+pipelineCols+` FROM pipelines WHERE id = ?`), id).
		Scan(&p.ID, &p.RepoID, &p.MRID, &p.CommitSHA, &p.RefName, &p.Status, &p.RequiresApproval,
			&p.ApprovedBy, &p.ApprovedAt, &p.CreatedAt, &p.FinishedAt)
	return p, err
}

func (d *DB) ApprovePipeline(ctx context.Context, id, approverID string) (bool, error) {
	res, err := d.ExecContext(ctx, d.q(`UPDATE pipelines SET status = ?, approved_by = ?, approved_at = ?
		WHERE id = ? AND status = ?`), domain.PipelineQueued, approverID, Now(), id, domain.PipelinePendingApproval)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (d *DB) SetPipelineStatus(ctx context.Context, id, status string) error {
	finished := any(nil)
	if status == domain.PipelineSuccess || status == domain.PipelineFailed {
		finished = Now()
	}
	_, err := d.ExecContext(ctx, d.q(`UPDATE pipelines SET status = ?, finished_at = ? WHERE id = ?`), status, finished, id)
	return err
}

func (d *DB) ListPipelines(ctx context.Context, repoID string) ([]domain.Pipeline, error) {
	rows, err := d.QueryContext(ctx, d.q(`SELECT `+pipelineCols+` FROM pipelines WHERE repo_id = ? ORDER BY created_at DESC`), repoID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []domain.Pipeline
	for rows.Next() {
		var p domain.Pipeline
		if err := rows.Scan(&p.ID, &p.RepoID, &p.MRID, &p.CommitSHA, &p.RefName, &p.Status, &p.RequiresApproval,
			&p.ApprovedBy, &p.ApprovedAt, &p.CreatedAt, &p.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) UpsertPeer(ctx context.Context, p domain.Peer) (domain.Peer, error) {
	domainName := strings.ToLower(strings.TrimSpace(p.Domain))
	trust := p.TrustStatus
	if trust == "" {
		trust = domain.PeerPending
	}
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO federation_peers
		(id, domain, inbox_url, actor_url, public_key_pem, trust_status, allow_federated_ci, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (domain) DO UPDATE SET
			inbox_url = excluded.inbox_url,
			actor_url = excluded.actor_url,
			public_key_pem = excluded.public_key_pem,
			trust_status = excluded.trust_status,
			allow_federated_ci = excluded.allow_federated_ci`),
		NewID(), domainName, p.InboxURL, p.ActorURL, p.PublicKeyPEM, trust, boolInt(p.AllowFederatedCI), Now())
	if err != nil {
		return domain.Peer{}, err
	}
	return d.GetPeer(ctx, domainName)
}

func (d *DB) GetPeer(ctx context.Context, domainName string) (domain.Peer, error) {
	var p domain.Peer
	err := d.QueryRowContext(ctx, d.q(`SELECT id, domain, inbox_url, actor_url, public_key_pem, trust_status,
		allow_federated_ci, COALESCE(last_verified_at, ''), created_at FROM federation_peers WHERE domain = ?`),
		strings.ToLower(domainName)).Scan(&p.ID, &p.Domain, &p.InboxURL, &p.ActorURL, &p.PublicKeyPEM,
		&p.TrustStatus, &p.AllowFederatedCI, &p.LastVerifiedAt, &p.CreatedAt)
	return p, err
}

func (d *DB) ListPeers(ctx context.Context) ([]domain.Peer, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, domain, inbox_url, actor_url, public_key_pem, trust_status,
		allow_federated_ci, COALESCE(last_verified_at, ''), created_at FROM federation_peers ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []domain.Peer
	for rows.Next() {
		var p domain.Peer
		if err := rows.Scan(&p.ID, &p.Domain, &p.InboxURL, &p.ActorURL, &p.PublicKeyPEM,
			&p.TrustStatus, &p.AllowFederatedCI, &p.LastVerifiedAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) DeletePeer(ctx context.Context, domainName string) error {
	_, err := d.ExecContext(ctx, d.q(`DELETE FROM federation_peers WHERE domain = ?`), strings.ToLower(domainName))
	return err
}

func (d *DB) SetupCompleted(ctx context.Context) (bool, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT setup_completed FROM instance_state WHERE id = 1`).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return n == 1, err
}

func (d *DB) CompleteSetup(ctx context.Context) error {
	_, err := d.ExecContext(ctx, d.q(`INSERT INTO instance_state (id, setup_completed, updated_at) VALUES (1, 1, ?)
		ON CONFLICT (id) DO UPDATE SET setup_completed = 1, updated_at = excluded.updated_at`), Now())
	return err
}

// NewID returns a random 128-bit hex identifier.
func NewID() string { return NewToken()[:32] }

// NewToken returns a random 256-bit hex token.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func NewUserCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, v := range b {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	return sb.String()
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
