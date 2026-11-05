package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"knotwork/internal/database"
	"knotwork/internal/domain"
)

// ErrInvalidBearer is returned when a bearer cannot be resolved to an active
// principal. It is not wrapped around parser errors, so callers can refuse the
// credential without logging or echoing the token.
var ErrInvalidBearer = errors.New("invalid bearer")

// Principal is the user an existing API bearer authorizes, plus the expiry and
// scopes the token already carries. It is not a new credential.
type Principal struct {
	User       domain.User
	Expiration time.Time
	Scopes     []string
}

// PrincipalFromBearer resolves an existing instance JWT or opaque session
// bearer. Break-glass tokens are not API bearers. A failure is ErrInvalidBearer
// or a database error; the raw token is never attached to the error.
func (s *Service) PrincipalFromBearer(ctx context.Context, raw string) (Principal, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || s == nil || s.Tokens == nil || s.DB == nil {
		return Principal{}, ErrInvalidBearer
	}
	if claims, err := s.Tokens.Parse(raw); err == nil {
		if claims.ExpiresAt == nil || claims.UserID == "" {
			return Principal{}, ErrInvalidBearer
		}
		user, err := s.DB.GetUserByID(ctx, claims.UserID)
		if err != nil || !user.IsActive {
			return Principal{}, ErrInvalidBearer
		}
		return Principal{User: user, Expiration: claims.ExpiresAt.Time, Scopes: claims.Scopes}, nil
	}
	user, expires, err := s.DB.SessionPrincipal(ctx, raw)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return Principal{}, ErrInvalidBearer
		}
		return Principal{}, err
	}
	if !user.IsActive || expires.IsZero() {
		return Principal{}, ErrInvalidBearer
	}
	return Principal{User: user, Expiration: expires}, nil
}
