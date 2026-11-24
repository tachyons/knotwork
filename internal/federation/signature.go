// Package federation implements the opt-in ActivityPub/ForgeFed boundary:
// Ed25519 HTTP signatures, allowlisted peers, and isolated MR ingestion.
package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const signatureMaxSkew = 5 * time.Minute

// Sign adds a draft-cavage HTTP Signature to req. body must match req.Body.
func Sign(req *http.Request, body []byte, key ed25519.PrivateKey, keyID string) error {
	digest := sha256.Sum256(body)
	req.Header.Set("Digest", "SHA-256="+base64.StdEncoding.EncodeToString(digest[:]))
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	headers := []string{"(request-target)", "host", "date", "digest"}
	signing, err := signingString(req, headers)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, []byte(signing))
	req.Header.Set("Signature", fmt.Sprintf(
		`keyId=%q,algorithm=%q,headers=%q,signature=%q`,
		keyID, "ed25519", strings.Join(headers, " "), base64.StdEncoding.EncodeToString(sig)))
	return nil
}

// Verify checks the Digest, Date, and Ed25519 signature using the peer key.
func Verify(req *http.Request, body []byte, pub ed25519.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("missing peer public key")
	}
	params, err := parseSignatureHeader(req.Header.Get("Signature"))
	if err != nil {
		return err
	}
	if params.algorithm != "" && params.algorithm != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", params.algorithm)
	}
	headers := strings.Fields(params.headers)
	if len(headers) == 0 {
		headers = []string{"date"}
	}
	if !contains(headers, "digest") {
		return fmt.Errorf("signature does not cover digest")
	}
	date, err := http.ParseTime(req.Header.Get("Date"))
	if err != nil {
		return fmt.Errorf("invalid date: %w", err)
	}
	if time.Since(date).Abs() > signatureMaxSkew {
		return fmt.Errorf("signature date outside allowed skew")
	}
	digest := sha256.Sum256(body)
	want := "SHA-256=" + base64.StdEncoding.EncodeToString(digest[:])
	if req.Header.Get("Digest") != want {
		return fmt.Errorf("digest mismatch")
	}
	signing, err := signingString(req, headers)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(params.signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(signing), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

type signatureParams struct {
	keyID     string
	algorithm string
	headers   string
	signature string
}

func parseSignatureHeader(raw string) (signatureParams, error) {
	var out signatureParams
	if raw == "" {
		return out, fmt.Errorf("missing Signature header")
	}
	for _, part := range splitParams(raw) {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		switch key {
		case "keyId":
			out.keyID = val
		case "algorithm":
			out.algorithm = val
		case "headers":
			out.headers = val
		case "signature":
			out.signature = val
		}
	}
	if out.keyID == "" || out.signature == "" {
		return out, fmt.Errorf("incomplete Signature header")
	}
	return out, nil
}

func splitParams(raw string) []string {
	var out []string
	var current strings.Builder
	inQuote := false
	for _, r := range raw {
		switch r {
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

func signingString(req *http.Request, headers []string) (string, error) {
	var lines []string
	for _, h := range headers {
		switch h {
		case "(request-target)":
			lines = append(lines, "(request-target): "+strings.ToLower(req.Method)+" "+req.URL.RequestURI())
		case "(created)":
			lines = append(lines, "(created): "+req.Header.Get("Date"))
		case "host":
			host := req.Host
			if host == "" {
				host = req.URL.Host
			}
			lines = append(lines, "host: "+host)
		default:
			val := req.Header.Get(h)
			if val == "" {
				return "", fmt.Errorf("signature header %q is missing", h)
			}
			lines = append(lines, strings.ToLower(h)+": "+val)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// PublicKeyFromPEM parses the PEM form emitted by auth.PublicKeyPEM.
func PublicKeyFromPEM(value string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length")
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// Deliver signs and posts an activity to a remote inbox. A nil client uses
// NewDeliveryClient, which blocks loopback, private, and link-local targets.
func Deliver(ctx context.Context, client *http.Client, inbox string, activity []byte, key ed25519.PrivateKey, keyID string) error {
	if err := ValidateOutboundURL(inbox); err != nil {
		return fmt.Errorf("invalid inbox: %w", err)
	}
	if client == nil {
		client = NewDeliveryClient()
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
