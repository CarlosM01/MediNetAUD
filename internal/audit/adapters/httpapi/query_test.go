package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
	"github.com/medinetcore/aud/internal/jwtauth"
)

const storedEventID = "0b0e5f8e-6a4c-4f7e-9d3a-2f1c8b7a6e5d"

// testKeys is generated once: RSA key generation is slow.
var testKeys = sync.OnceValues(func() (*jwtauth.Issuer, *jwtauth.Verifier) {
	priv, pub, err := jwtauth.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	iss, err := jwtauth.NewIssuer(priv, "medinet-iam", "aud")
	if err != nil {
		panic(err)
	}
	v, err := jwtauth.NewVerifier(pub, "medinet-iam", "aud")
	if err != nil {
		panic(err)
	}
	return iss, v
})

func token(t *testing.T, roles ...string) string {
	t.Helper()
	iss, _ := testKeys()
	tok, err := iss.Mint("auditor-1", roles, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// fakeReader serves one stored event; err, when set, is returned by every call.
type fakeReader struct {
	err error
}

func (f *fakeReader) FindEvent(_ context.Context, eventID string) (ports.StoredEvent, error) {
	if f.err != nil {
		return ports.StoredEvent{}, f.err
	}
	if eventID != storedEventID {
		return ports.StoredEvent{}, ports.ErrEventNotFound
	}
	return storedEvent(), nil
}

func storedEvent() ports.StoredEvent {
	occurred := time.Date(2026, 10, 25, 14, 3, 11, 123456000, time.UTC)
	r := domain.Record{
		Event: domain.Event{
			EventID:        storedEventID,
			SourceModule:   "IAM",
			EventType:      "auth.login_failed",
			Severity:       domain.SeverityMedium,
			OccurredAt:     occurred,
			ActorID:        "user-77",
			ActorType:      "user",
			TargetResource: "session/abc",
			SourceIP:       "10.1.2.3",
			Payload:        json.RawMessage(`{"attempt": 3, "big": 12345678901234567890}`),
		},
		ClientID:   "iam-service",
		ReceivedAt: occurred.Add(time.Second),
	}
	r.Seal(domain.GenesisHash)
	return ports.StoredEvent{ID: 7, Record: r}
}

func newQueryRouter(reader ports.EventReader) http.Handler {
	_, v := testKeys()
	return NewRouter(Dependencies{Tokens: v, Query: application.NewQuery(reader)})
}

func get(t *testing.T, h http.Handler, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem %q: %v", rec.Body, err)
	}
	if p.Status != rec.Code || p.Title != http.StatusText(rec.Code) {
		t.Errorf("problem = %+v, want status %d and title %q", p, rec.Code, http.StatusText(rec.Code))
	}
	return p
}

func TestQueryRequiresValidBearerToken(t *testing.T) {
	iss, _ := testKeys()
	expired, err := iss.Mint("auditor-1", []string{jwtauth.RoleAuditor}, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, _ := jwtauth.GenerateKeyPair()
	other, _ := jwtauth.NewIssuer(priv, "medinet-iam", "aud")
	forged, _ := other.Mint("auditor-1", []string{jwtauth.RoleAdmin}, time.Hour)

	tests := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"empty bearer", "Bearer "},
		{"basic scheme", "Basic dXNlcjpwYXNz"},
		{"token without scheme", token(t, jwtauth.RoleAuditor)},
		{"expired", "Bearer " + expired},
		{"signed with another key", "Bearer " + forged},
		{"garbage", "Bearer not-a-token"},
	}
	h := newQueryRouter(&fakeReader{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/events/"+storedEventID, nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body)
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
				t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", got)
			}
			if p := decodeProblem(t, rec); p.Detail != bearerDetail {
				t.Errorf("detail = %q, want the same %q for every failure", p.Detail, bearerDetail)
			}
		})
	}
}

func TestQueryRejectsTokenWithoutRole(t *testing.T) {
	h := newQueryRouter(&fakeReader{})
	for _, roles := range [][]string{nil, {"viewer"}, {"AUDITOR"}} {
		rec := get(t, h, "/api/v1/events/"+storedEventID, token(t, roles...))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("roles %q: status = %d, want 403; body %s", roles, rec.Code, rec.Body)
		}
		decodeProblem(t, rec)
	}
}

func TestQueryAuthenticatesBeforeValidatingParameters(t *testing.T) {
	rec := get(t, newQueryRouter(&fakeReader{}), "/api/v1/events/not-a-uuid", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestGetEventReturnsStoredEvent(t *testing.T) {
	h := newQueryRouter(&fakeReader{})
	for _, role := range []string{jwtauth.RoleAuditor, jwtauth.RoleAdmin} {
		rec := get(t, h, "/api/v1/events/"+storedEventID, token(t, role))
		if rec.Code != http.StatusOK {
			t.Fatalf("role %s: status = %d, want 200; body %s", role, rec.Code, rec.Body)
		}
	}

	rec := get(t, h, "/api/v1/events/"+strings.ToUpper(storedEventID), token(t, jwtauth.RoleAuditor))
	if rec.Code != http.StatusOK {
		t.Errorf("uppercase id: status = %d, want 200 (UUIDs compare case-insensitively)", rec.Code)
	}

	rec = get(t, h, "/api/v1/events/"+storedEventID, token(t, jwtauth.RoleAuditor))
	want := storedEvent()
	var got map[string]any
	dec := json.NewDecoder(rec.Body)
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	expect := map[string]any{
		"id":              json.Number("7"),
		"event_id":        storedEventID,
		"client_id":       "iam-service",
		"source_module":   "IAM",
		"event_type":      "auth.login_failed",
		"severity":        "MEDIUM",
		"actor_id":        "user-77",
		"actor_type":      "user",
		"target_resource": "session/abc",
		"source_ip":       "10.1.2.3",
		"occurred_at":     "2026-10-25T14:03:11.123456Z",
		"received_at":     "2026-10-25T14:03:12.123456Z",
		"prev_hash":       strings.Repeat("0", 64),
		"hash":            hex.EncodeToString(want.Hash[:]),
	}
	for k, v := range expect {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	if _, ok := got["user_agent"]; ok {
		t.Errorf("absent user_agent should be omitted, got %#v", got["user_agent"])
	}
	payload, _ := got["payload"].(map[string]any)
	if payload["big"] != json.Number("12345678901234567890") || payload["attempt"] != json.Number("3") {
		t.Errorf("payload = %#v, want numbers preserved verbatim", got["payload"])
	}
}

func TestGetEventErrors(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		reader *fakeReader
		status int
		field  string
	}{
		{"unknown id", "/api/v1/events/11111111-2222-4333-8444-555555555555", &fakeReader{}, http.StatusNotFound, ""},
		{"not a uuid", "/api/v1/events/abc", &fakeReader{}, http.StatusBadRequest, "id"},
		{"sql injection", "/api/v1/events/%27%20OR%201=1--", &fakeReader{}, http.StatusBadRequest, "id"},
		{"uuid with braces", "/api/v1/events/%7B" + storedEventID + "%7D", &fakeReader{}, http.StatusBadRequest, "id"},
		{"store failure", "/api/v1/events/" + storedEventID, &fakeReader{err: errors.New("connection refused to 10.0.0.5")}, http.StatusInternalServerError, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, newQueryRouter(tt.reader), tt.path, token(t, jwtauth.RoleAuditor))
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			p := decodeProblem(t, rec)
			if tt.field != "" && (len(p.Errors) == 0 || p.Errors[0].Field != tt.field) {
				t.Errorf("errors = %+v, want field %q", p.Errors, tt.field)
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Errorf("body leaks the internal error: %s", rec.Body)
			}
		})
	}
}

func TestQueryRoutesAbsentWithoutVerifier(t *testing.T) {
	h := NewRouter(Dependencies{Query: application.NewQuery(&fakeReader{})})
	rec := get(t, h, "/api/v1/events/"+storedEventID, token(t, jwtauth.RoleAdmin))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when no token verifier is configured", rec.Code)
	}
}
