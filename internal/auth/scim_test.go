package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knotwork/internal/database"
	"knotwork/internal/domain"
)

type scimTestServer struct {
	server *httptest.Server
	db     *database.DB
	token  string
	admin  domain.User
}

func newSCIMTestServer(t *testing.T) *scimTestServer {
	t.Helper()
	ctx := t.Context()
	db, err := database.Open(ctx, "sqlite::memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	admin, err := db.UpsertOIDCUser(ctx, "admin-sub", "admin@example.com", "admin", "Admin")
	if err != nil {
		t.Fatalf("UpsertOIDCUser: %v", err)
	}
	token, err := db.CreateSession(ctx, admin.ID, "scim", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	svc := &Service{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	mux := http.NewServeMux()
	svc.RegisterSCIM(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &scimTestServer{server: server, db: db, token: token, admin: admin}
}

func (s *scimTestServer) createUser(t *testing.T, scimID, email, username, display string) domain.User {
	t.Helper()
	user, err := s.db.CreateSCIMUser(t.Context(), scimID, email, username, display)
	if err != nil {
		t.Fatalf("CreateSCIMUser(%q): %v", username, err)
	}
	return user
}

func (s *scimTestServer) request(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, s.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, payload
}

func TestSCIMListFilter(t *testing.T) {
	s := newSCIMTestServer(t)
	s.createUser(t, "alice-ext", "alice@example.com", "alice", "Alice")
	s.createUser(t, "bob-ext", "bob@example.com", "bob", "Bob")

	tests := []struct {
		name       string
		query      string
		wantStatus int
		wantTotal  int
		wantUsers  []string
		wantType   string
	}{
		{name: "no filter", query: "", wantStatus: http.StatusOK, wantTotal: 3, wantUsers: []string{"admin", "alice", "bob"}},
		{name: "eq", query: `?filter=userName%20eq%20%22alice%22`, wantStatus: http.StatusOK, wantTotal: 1, wantUsers: []string{"alice"}},
		{name: "and", query: `?filter=userName%20co%20%22li%22%20and%20active%20eq%20true`, wantStatus: http.StatusOK, wantTotal: 1, wantUsers: []string{"alice"}},
		{name: "or", query: `?filter=userName%20eq%20%22alice%22%20or%20userName%20eq%20%22bob%22`, wantStatus: http.StatusOK, wantTotal: 2, wantUsers: []string{"alice", "bob"}},
		{name: "sw", query: `?filter=userName%20sw%20%22b%22`, wantStatus: http.StatusOK, wantTotal: 1, wantUsers: []string{"bob"}},
		{name: "emails.value", query: `?filter=emails.value%20eq%20%22bob@example.com%22`, wantStatus: http.StatusOK, wantTotal: 1, wantUsers: []string{"bob"}},
		{name: "present", query: `?filter=emails%20pr`, wantStatus: http.StatusOK, wantTotal: 3, wantUsers: []string{"admin", "alice", "bob"}},
		{name: "unknown attribute", query: `?filter=nickname%20eq%20%22a%22`, wantStatus: http.StatusBadRequest, wantType: "invalidFilter"},
		{name: "malformed", query: `?filter=userName%20eq`, wantStatus: http.StatusBadRequest, wantType: "invalidFilter"},
		{name: "unsupported operator", query: `?filter=userName%20gt%20%22a%22`, wantStatus: http.StatusBadRequest, wantType: "invalidFilter"},
		{name: "value path", query: `?filter=emails[type%20eq%20%22work%22].value%20eq%20%22a%22`, wantStatus: http.StatusBadRequest, wantType: "invalidFilter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, body := s.request(t, http.MethodGet, "/scim/v2/Users"+tc.query, "")
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", status, tc.wantStatus, body)
			}
			if tc.wantStatus != http.StatusOK {
				var scimErr struct {
					SCIMType string `json:"scimType"`
				}
				if err := json.Unmarshal(body, &scimErr); err != nil {
					t.Fatalf("decode error: %v", err)
				}
				if scimErr.SCIMType != tc.wantType {
					t.Fatalf("scimType = %q, want %q", scimErr.SCIMType, tc.wantType)
				}
				return
			}
			var list scimList
			if err := json.Unmarshal(body, &list); err != nil {
				t.Fatalf("decode list: %v", err)
			}
			if list.TotalResults != tc.wantTotal {
				t.Fatalf("totalResults = %d, want %d", list.TotalResults, tc.wantTotal)
			}
			if len(list.Resources) != len(tc.wantUsers) {
				t.Fatalf("resources = %d, want %d", len(list.Resources), len(tc.wantUsers))
			}
			for i, want := range tc.wantUsers {
				if list.Resources[i].UserName != want {
					t.Errorf("resource[%d] = %q, want %q", i, list.Resources[i].UserName, want)
				}
			}
		})
	}
}

func TestSCIMListPaginationAndSort(t *testing.T) {
	s := newSCIMTestServer(t)
	s.createUser(t, "alice-ext", "alice@example.com", "alice", "Alice")
	s.createUser(t, "bob-ext", "bob@example.com", "bob", "Bob")
	s.createUser(t, "carol-ext", "carol@example.com", "carol", "Carol")

	status, body := s.request(t, http.MethodGet, "/scim/v2/Users?startIndex=2&count=1", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var list scimList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.TotalResults != 4 || list.ItemsPerPage != 1 || list.StartIndex != 2 {
		t.Fatalf("pagination = %+v", list)
	}
	if len(list.Resources) != 1 || list.Resources[0].UserName != "alice" {
		t.Fatalf("resources = %+v", list.Resources)
	}

	status, body = s.request(t, http.MethodGet, "/scim/v2/Users?sortBy=userName&sortOrder=descending", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Resources) != 4 || list.Resources[0].UserName != "carol" {
		t.Fatalf("sorted resources = %+v", list.Resources)
	}

	status, body = s.request(t, http.MethodGet, "/scim/v2/Users?count=nope", "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalidValue") {
		t.Fatalf("invalid count = %d: %s", status, body)
	}
}

func TestSCIMPatchUser(t *testing.T) {
	s := newSCIMTestServer(t)
	user := s.createUser(t, "alice-ext", "alice@example.com", "alice", "Alice")

	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"active","value":false},
		{"op":"replace","path":"name.formatted","value":"Alice Cooper"},
		{"op":"replace","path":"emails","value":[{"value":"alice.cooper@example.com","primary":true}]},
		{"op":"replace","path":"externalId","value":"alice-2"}
	]}`
	status, payload := s.request(t, http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, payload)
	}
	var updated scimUser
	if err := json.Unmarshal(payload, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Active {
		t.Error("active = true, want false")
	}
	if updated.Name.Formatted != "Alice Cooper" {
		t.Errorf("name = %q", updated.Name.Formatted)
	}
	if len(updated.Emails) != 1 || updated.Emails[0].Value != "alice.cooper@example.com" {
		t.Errorf("emails = %+v", updated.Emails)
	}
	if updated.ExternalID != "alice-2" {
		t.Errorf("externalId = %q", updated.ExternalID)
	}

	stored, err := s.db.GetUserByID(t.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IsActive || stored.DisplayName != "Alice Cooper" || stored.Email != "alice.cooper@example.com" || stored.SCIMID != "alice-2" {
		t.Fatalf("stored = %+v", stored)
	}

	// A pathless replace applies an object of attributes.
	body = `{"Operations":[{"op":"replace","value":{
		"active":true,
		"name":{"formatted":"Alice A."},
		"emails":[{"value":"alice@example.com"}],
		"externalId":"alice-3"
	}}]}`
	status, payload = s.request(t, http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, payload)
	}
	updated = scimUser{}
	if err := json.Unmarshal(payload, &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.Active || updated.Name.Formatted != "Alice A." || updated.ExternalID != "alice-3" {
		t.Fatalf("updated = %+v", updated)
	}

	// remove externalId stores NULL so other users can also omit it.
	status, payload = s.request(t, http.MethodPatch, "/scim/v2/Users/"+user.ID, `{"Operations":[{"op":"remove","path":"externalId"}]}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, payload)
	}
	updated = scimUser{}
	if err := json.Unmarshal(payload, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ExternalID != "" {
		t.Fatalf("externalId = %q, want empty", updated.ExternalID)
	}
}

func TestSCIMPatchRejectsInvalidOperations(t *testing.T) {
	s := newSCIMTestServer(t)
	user := s.createUser(t, "alice-ext", "alice@example.com", "alice", "Alice")

	tests := []struct {
		name     string
		body     string
		wantType string
	}{
		{name: "unsupported op", body: `{"Operations":[{"op":"move","path":"active","value":true}]}`, wantType: "invalidSyntax"},
		{name: "unsupported path", body: `{"Operations":[{"op":"replace","path":"title","value":"x"}]}`, wantType: "invalidPath"},
		{name: "value path", body: `{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"x@example.com"}]}`, wantType: "invalidPath"},
		{name: "remove email", body: `{"Operations":[{"op":"remove","path":"emails"}]}`, wantType: "invalidValue"},
		{name: "bad active", body: `{"Operations":[{"op":"replace","path":"active","value":"maybe"}]}`, wantType: "invalidValue"},
		{name: "empty operations", body: `{"Operations":[]}`, wantType: "invalidValue"},
		{name: "remove without path", body: `{"Operations":[{"op":"remove","value":{}}]}`, wantType: "noTarget"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := s.request(t, http.MethodPatch, "/scim/v2/Users/"+user.ID, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, payload)
			}
			var scimErr struct {
				SCIMType string `json:"scimType"`
			}
			if err := json.Unmarshal(payload, &scimErr); err != nil {
				t.Fatal(err)
			}
			if scimErr.SCIMType != tc.wantType {
				t.Fatalf("scimType = %q, want %q", scimErr.SCIMType, tc.wantType)
			}
		})
	}
}

func TestSCIMGroupsAreExplicitlyUnsupported(t *testing.T) {
	s := newSCIMTestServer(t)
	status, body := s.request(t, http.MethodGet, "/scim/v2/Groups", "")
	if status != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501: %s", status, body)
	}
	if !strings.Contains(string(body), "SCIM groups are not stored") {
		t.Fatalf("body = %s", body)
	}
}
