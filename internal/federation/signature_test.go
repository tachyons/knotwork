package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/superseriousbusiness/httpsig"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedRequest(t *testing.T, body []byte) (*http.Request, ed25519.PublicKey) {
	t.Helper()
	pub, priv := testKey(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://peer.example/inbox", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(req, body, priv, "https://knot.example/actor#main-key"); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return req, pub
}

// asServerRequest mimics net/http: the Host header is moved into req.Host and
// removed from the header map before handlers run.
func asServerRequest(req *http.Request) {
	req.Host = req.Header.Get("Host")
	req.Header.Del("Host")
}

func TestSignVerifyRoundTrip(t *testing.T) {
	body := []byte(`{"type":"Offer"}`)
	req, pub := signedRequest(t, body)
	asServerRequest(req)
	if err := Verify(req, body, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	body := []byte(`{"type":"Offer"}`)
	req, pub := signedRequest(t, body)
	asServerRequest(req)
	if err := Verify(req, []byte(`{"type":"Reject"}`), pub); err == nil {
		t.Fatal("expected digest mismatch")
	}
}

func TestVerifyRejectsStaleDate(t *testing.T) {
	body := []byte(`{}`)
	req, pub := signedRequest(t, body)
	asServerRequest(req)
	req.Header.Set("Date", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	if err := Verify(req, body, pub); err == nil || !strings.Contains(err.Error(), "skew") {
		t.Fatalf("err = %v, want skew rejection", err)
	}
}

func TestVerifyRejectsMissingSignedHeaders(t *testing.T) {
	for _, missing := range []string{"(request-target)", "host", "date", "digest"} {
		missing := missing
		t.Run(missing, func(t *testing.T) {
			body := []byte(`{}`)
			_, priv := testKey(t)
			pub := priv.Public().(ed25519.PublicKey)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://peer.example/inbox", strings.NewReader(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
			req.Header.Set("Host", req.URL.Host)
			headers := make([]string, 0, len(requiredSignedHeaders))
			for _, header := range requiredSignedHeaders {
				if header != missing {
					headers = append(headers, header)
				}
			}
			signer, _, err := httpsig.NewSigner([]httpsig.Algorithm{httpsig.ED25519}, httpsig.DigestSha256, headers, httpsig.Signature, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := signer.SignRequest(priv, "key", req, body); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			asServerRequest(req)
			err = Verify(req, body, pub)
			if err == nil || !strings.Contains(err.Error(), "does not cover "+missing) {
				t.Fatalf("err = %v, want %s coverage rejection", err, missing)
			}
		})
	}
}

func TestVerifyAcceptsExternalCavageSignature(t *testing.T) {
	// A GoToSocial-style actor signs the draft-cavage-12 canonical string
	// directly. This pins the exact wire format our verifier must accept,
	// independently of our own Sign helper.
	seed := sha256.Sum256([]byte("knotwork federation fixture key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	body := []byte(`{"type":"Offer","actor":"https://gts.example/users/alice"}`)
	sum := sha256.Sum256(body)
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	date := time.Now().UTC().Format(http.TimeFormat)
	signing := "(request-target): post /inbox\n" +
		"host: gts.example\n" +
		"date: " + date + "\n" +
		"digest: " + digest
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(signing)))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://gts.example/inbox", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "gts.example"
	req.Header.Set("Date", date)
	req.Header.Set("Digest", digest)
	req.Header.Set("Signature", `keyId="https://gts.example/users/alice#main-key",algorithm="hs2019",headers="(request-target) host date digest",signature="`+signature+`"`)
	if err := Verify(req, body, pub); err != nil {
		t.Fatalf("Verify external cavage signature: %v", err)
	}
}

func TestVerifyRejectsDifferentRequestTarget(t *testing.T) {
	body := []byte(`{}`)
	req, pub := signedRequest(t, body)
	req.URL.Path = "/other-inbox"
	asServerRequest(req)
	if err := Verify(req, body, pub); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("err = %v, want signature binding rejection", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	body := []byte(`{}`)
	req, pub := signedRequest(t, body)
	asServerRequest(req)
	cache := NewReplayCache(time.Minute)
	if err := VerifyWithReplay(req, body, pub, cache); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	if err := VerifyWithReplay(req, body, pub, cache); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("second verification err = %v, want replay rejection", err)
	}
}

func TestReplayCacheExpires(t *testing.T) {
	cache := NewReplayCache(time.Minute)
	now := time.Now()
	if cache.Seen("key", now) {
		t.Fatal("first Seen reported a replay")
	}
	if !cache.Seen("key", now.Add(30*time.Second)) {
		t.Fatal("second Seen did not report a replay")
	}
	if cache.Seen("key", now.Add(2*time.Minute)) {
		t.Fatal("expired entry still reported as replay")
	}
}

func TestReplayCacheIsBounded(t *testing.T) {
	cache := NewReplayCache(time.Hour)
	now := time.Now()
	for i := 0; i < maxReplayEntries+128; i++ {
		cache.Seen(strconv.Itoa(i), now)
	}
	cache.mu.Lock()
	size := len(cache.seen)
	cache.mu.Unlock()
	if size > maxReplayEntries {
		t.Fatalf("cache holds %d entries, want at most %d", size, maxReplayEntries)
	}
}

func TestPublicKeyPEMRoundTrip(t *testing.T) {
	pub, _ := testKey(t)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	spki := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	parsed, err := PublicKeyFromPEM(spki)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM(SPKI): %v", err)
	}
	if !parsed.Equal(pub) {
		t.Fatal("parsed SPKI key differs")
	}

	legacy := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	parsed, err = PublicKeyFromPEM(legacy)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM(legacy): %v", err)
	}
	if !parsed.Equal(pub) {
		t.Fatal("parsed legacy key differs")
	}

	if _, err := PublicKeyFromPEM("not a key"); err == nil {
		t.Fatal("expected invalid PEM error")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	body := []byte(`{}`)
	req, _ := signedRequest(t, body)
	other, _ := testKey(t)
	asServerRequest(req)
	if err := Verify(req, body, other); err == nil {
		t.Fatal("expected wrong-key rejection")
	}
}

func TestSignSetsDigest(t *testing.T) {
	body := []byte(`{"type":"Offer"}`)
	req, _ := signedRequest(t, body)
	sum := sha256.Sum256(body)
	want := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	if got := req.Header.Get("Digest"); got != want {
		t.Fatalf("Digest = %q, want %q", got, want)
	}
}

func TestDeliverRejectsPlainHTTP(t *testing.T) {
	_, priv := testKey(t)
	err := Deliver(t.Context(), http.DefaultClient, "http://peer.example/inbox", []byte(`{}`), priv, "key")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want https rejection", err)
	}
}
