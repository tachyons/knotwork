package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreateKey returns the instance's Ed25519 key, creating it on first
// boot. The key signs session JWTs and outbound federation activities.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parseKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func parseKey(data []byte) (ed25519.PrivateKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	raw, err := base64.StdEncoding.DecodeString(string(trimSpaceBytes(data)))
	if err != nil {
		return nil, fmt.Errorf("decode instance key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("invalid instance key length %d", len(raw))
	}
}

func trimSpaceBytes(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// PublicKeyPEM returns the SubjectPublicKeyInfo PEM encoding of the instance's
// Ed25519 public key. Peers expect the same format that TLS and SSH tools emit,
// and federation.PublicKeyFromPEM still accepts the legacy raw-key block.
func PublicKeyPEM(priv ed25519.PrivateKey) string {
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}
