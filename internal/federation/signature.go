// Package federation implements the opt-in ActivityPub/ForgeFed boundary:
// Ed25519 HTTP signatures, allowlisted peers, and isolated MR ingestion.
package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/superseriousbusiness/httpsig"
)

const signatureMaxSkew = 5 * time.Minute

// requiredSignedHeaders binds a signature to the request target, authority,
// freshness, and body. Verification requires all of them even when the sender
// advertises a different header list.
var requiredSignedHeaders = []string{"(request-target)", "host", "date", "digest"}

// Sign adds a draft-cavage HTTP Signature to req. body must match req.Body.
func Sign(req *http.Request, body []byte, key ed25519.PrivateKey, keyID string) error {
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Del("Signature")
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	// Go stores the authority in req.Host and strips the Host header, but the
	// signer reads every signed value from req.Header. Mirror the authority so
	// the verifier, which restores Host from req.Host, sees the same string.
	req.Header.Set("Host", req.Host)
	signer, _, err := httpsig.NewSigner([]httpsig.Algorithm{httpsig.ED25519}, httpsig.DigestSha256, requiredSignedHeaders, httpsig.Signature, 0)
	if err != nil {
		return err
	}
	return signer.SignRequest(key, keyID, req, body)
}

// Verify checks that the request covers the required headers, has a fresh
// Date, has a matching Digest, and carries a valid Ed25519 signature.
func Verify(req *http.Request, body []byte, pub ed25519.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("missing peer public key")
	}
	if err := requireSignedHeaders(req); err != nil {
		return err
	}
	date, err := http.ParseTime(req.Header.Get("Date"))
	if err != nil {
		return fmt.Errorf("invalid date: %w", err)
	}
	if time.Since(date).Abs() > signatureMaxSkew {
		return fmt.Errorf("signature date outside allowed skew")
	}
	if err := verifyDigest(req.Header.Get("Digest"), body); err != nil {
		return err
	}
	verifier, err := httpsig.NewVerifier(req)
	if err != nil {
		return err
	}
	if err := verifier.Verify(pub, httpsig.ED25519); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func requireSignedHeaders(req *http.Request) error {
	headers, err := signatureHeaderNames(req.Header.Get("Signature"))
	if err != nil {
		return err
	}
	for _, required := range requiredSignedHeaders {
		if !contains(headers, required) {
			return fmt.Errorf("signature does not cover %s", required)
		}
	}
	return nil
}

func signatureHeaderNames(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing Signature header")
	}
	raw = strings.TrimPrefix(raw, "Signature ")
	for _, part := range splitParams(raw) {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "headers") {
			value = strings.Trim(strings.TrimSpace(value), `"`)
			if value == "" {
				return nil, errors.New("empty signature headers parameter")
			}
			return strings.Fields(value), nil
		}
	}
	return nil, errors.New("signature header has no headers parameter")
}

func splitParams(raw string) []string {
	var out []string
	var current strings.Builder
	inQuote := false
	escaped := false
	for _, r := range raw {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			current.WriteRune(r)
			if inQuote {
				escaped = true
			}
		case '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case ',':
			if inQuote {
				current.WriteRune(r)
				continue
			}
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

func verifyDigest(header string, body []byte) error {
	if header == "" {
		return errors.New("missing Digest header")
	}
	sum := sha256.Sum256(body)
	want := base64.StdEncoding.EncodeToString(sum[:])
	for _, part := range strings.Split(header, ",") {
		algorithm, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(algorithm), "SHA-256") {
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(value)), []byte(want)) == 1 {
				return nil
			}
			return errors.New("digest mismatch")
		}
	}
	return errors.New("unsupported Digest algorithm")
}

func contains(list []string, want string) bool {
	for _, value := range list {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

// ReplayCache records recently verified signatures for a bounded window.
// Entries are keyed by the full Signature header, which includes the key ID and
// signature value.
type ReplayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

// maxReplayEntries bounds cache memory. Only peers holding allowlisted keys can
// add entries, but a compromised peer must not be able to exhaust the process.
const maxReplayEntries = 4096

// NewReplayCache returns a cache that remembers signatures for ttl.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	if ttl <= 0 {
		ttl = 2 * signatureMaxSkew
	}
	return &ReplayCache{ttl: ttl, seen: make(map[string]time.Time)}
}

// Seen reports whether key was already observed within the TTL, recording it
// when it is new. A nil cache never reports a replay.
func (c *ReplayCache) Seen(key string, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if observed, ok := c.seen[key]; ok && now.Sub(observed) <= c.ttl {
		return true
	}
	if len(c.seen) >= maxReplayEntries {
		c.evict(now)
	}
	c.seen[key] = now
	return false
}

// evict drops expired entries and, if the cache is still full, the oldest one.
func (c *ReplayCache) evict(now time.Time) {
	for candidate, observed := range c.seen {
		if now.Sub(observed) > c.ttl {
			delete(c.seen, candidate)
		}
	}
	if len(c.seen) < maxReplayEntries {
		return
	}
	oldestKey := ""
	var oldest time.Time
	for candidate, observed := range c.seen {
		if oldestKey == "" || observed.Before(oldest) {
			oldestKey, oldest = candidate, observed
		}
	}
	delete(c.seen, oldestKey)
}

// VerifyWithReplay verifies a signature and then rejects a replay of the same
// Signature header within the cache window.
func VerifyWithReplay(req *http.Request, body []byte, pub ed25519.PublicKey, cache *ReplayCache) error {
	if err := Verify(req, body, pub); err != nil {
		return err
	}
	if cache == nil {
		return nil
	}
	sum := sha256.Sum256([]byte(req.Header.Get("Signature")))
	if cache.Seen(hex.EncodeToString(sum[:]), time.Now()) {
		return errors.New("replayed http signature")
	}
	return nil
}

// PublicKeyFromPEM parses either a SubjectPublicKeyInfo PEM block (the form
// emitted by auth.PublicKeyPEM) or the legacy raw Ed25519 key bytes in a PEM
// wrapper.
func PublicKeyFromPEM(value string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PEM contains %T, want an Ed25519 public key", key)
		}
		return pub, nil
	}
	if len(block.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(block.Bytes), nil
	}
	return nil, fmt.Errorf("invalid Ed25519 public key length")
}

// Deliver signs and posts an activity to a remote inbox.
func Deliver(ctx context.Context, client *http.Client, inbox string, activity []byte, key ed25519.PrivateKey, keyID string) error {
	u, err := url.Parse(inbox)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("inbox must be an https URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inbox, bytes.NewReader(activity))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/activity+json")
	if err := Sign(req, activity, key, keyID); err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("peer returned %s", resp.Status)
	}
	return nil
}
