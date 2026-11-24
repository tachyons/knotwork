package federation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateOutboundURL(t *testing.T) {
	valid := []string{
		"https://peer.example/inbox",
		"https://peer.example:8443/inbox?x=1",
		"https://203.0.113.10/inbox",
	}
	for _, raw := range valid {
		if err := ValidateOutboundURL(raw); err != nil {
			t.Errorf("ValidateOutboundURL(%q) = %v", raw, err)
		}
	}
	invalid := []string{
		"http://peer.example/inbox",
		"https://user:pass@peer.example/inbox",
		"https://peer.example/inbox#fragment",
		"https:///inbox",
		"https://127.0.0.1/inbox",
		"https://127.1.2.3/inbox",
		"https://[::1]/inbox",
		"https://[::ffff:127.0.0.1]/inbox",
		"https://10.0.0.1/inbox",
		"https://172.16.0.1/inbox",
		"https://192.168.1.1/inbox",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/inbox",
		"https://198.18.0.1/inbox",
		"https://240.0.0.1/inbox",
		"https://localhost/inbox",
		"https://localhost./inbox",
		"https://metadata.google.internal/inbox",
	}
	for _, raw := range invalid {
		if err := ValidateOutboundURL(raw); err == nil {
			t.Errorf("ValidateOutboundURL(%q) accepted, want error", raw)
		}
	}
}

func TestDeliveryClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewDeliveryClient().Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("Get(%q) error = %v, want blocked address", srv.URL, err)
	}
}

func TestDeliverRejectsPrivateInbox(t *testing.T) {
	_, priv := testKey(t)
	err := Deliver(t.Context(), nil, "https://127.0.0.1/inbox", []byte(`{}`), priv, "key")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v, want blocked address", err)
	}
}
