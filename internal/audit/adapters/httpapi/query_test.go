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

// fakeReader serves one stored event; err, when set, is returned by every call. ListEvents
// records its filter and returns n copies of the stored event.
type fakeReader struct {
	err    error
	n      int
	filter ports.EventFilter
}

func (f *fakeReader) ListEvents(_ context.Context, filter ports.EventFilter) ([]ports.StoredEvent, error) {
	f.filter = filter
	if f.err != nil {
		return nil, f.err
	}
	out := make([]ports.StoredEvent, min(f.n, filter.Limit))
	for i := range out {
		out[i] = storedEvent()
		out[i].ID = int64(100 - i)
	}
	return out, nil
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

func (f *fakeReader) SuspiciousStats(_ context.Context, from, to time.Time, top int) (ports.SuspiciousStats, error) {
	f.filter = ports.EventFilter{From: from, To: to, Limit: top}
	if f.err != nil {
		return ports.SuspiciousStats{}, f.err
	}
	return ports.SuspiciousStats{
		FailedLoginsPerHour: []ports.HourCount{{Hour: time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC), Count: 3}},
		DeniedByActor:       []ports.ActorCount{{ActorID: "user-a", Count: 3}, {ActorID: "", Count: 2}},
		TopIPs:              []ports.IPCount{{IP: "203.0.113.5", Count: 3}},
	}, nil
}

// VerifyChain reports the chain broken at id 3 when the range includes it.
func (f *fakeReader) VerifyChain(_ context.Context, fromID, toID int64) (ports.ChainReport, error) {
	f.filter = ports.EventFilter{After: &ports.Cursor{ID: fromID}, Limit: int(min(toID, 1<<30))}
	if f.err != nil {
		return ports.ChainReport{}, f.err
	}
	if fromID <= 3 && toID >= 3 {
		return ports.ChainReport{Checked: 4 - fromID, FirstBrokenID: 3}, nil
	}
	return ports.ChainReport{OK: true, Checked: 2, LastID: 5, LastHash: domain.Hash{0xab}}, nil
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

func TestListEventsPassesEveryFilter(t *testing.T) {
	r := &fakeReader{n: 3}
	path := "/api/v1/events?event_type=access.denied&severity=HIGH&source_module=HCE" +
		"&actor_id=%27%20OR%201%3D1--&from=2026-10-20T00:00:00Z&to=2026-10-25T12:30:00-03:00&limit=2"
	rec := get(t, newQueryRouter(r), path, token(t, jwtauth.RoleAuditor))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	f := r.filter
	wantTo := time.Date(2026, 10, 25, 15, 30, 0, 0, time.UTC)
	if f.EventType != "access.denied" || f.SourceModule != "HCE" || f.ActorID != "' OR 1=1--" ||
		f.Severity == nil || *f.Severity != domain.SeverityHigh || f.Limit != 3 ||
		!f.From.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) || !f.To.Equal(wantTo) {
		t.Errorf("filter = %+v", f)
	}

	var body struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 2 || body.NextCursor == "" || body.Items[0]["event_id"] != storedEventID {
		t.Fatalf("body = %+v, want 2 items and a next_cursor", body)
	}

	rec = get(t, newQueryRouter(r), "/api/v1/events?limit=2&cursor="+body.NextCursor, token(t, jwtauth.RoleAuditor))
	if rec.Code != http.StatusOK || r.filter.After == nil || r.filter.After.ID != 99 {
		t.Errorf("second page: status %d, After = %+v; want 200 and the position of id 99", rec.Code, r.filter.After)
	}
}

func TestListEventsLastPageHasNoCursor(t *testing.T) {
	rec := get(t, newQueryRouter(&fakeReader{n: 0}), "/api/v1/events", token(t, jwtauth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"items":[]}` {
		t.Errorf("body = %s, want {\"items\":[]}", got)
	}
}

func TestListEventsRejectsInvalidParameters(t *testing.T) {
	tests := []struct {
		query string
		field string
	}{
		{"event_type=%27%20OR%201%3D1--", "event_type"},
		{"event_type=auth.unknown", "event_type"},
		{"source_module=XYZ", "source_module"},
		{"source_module=iam", "source_module"},
		{"severity=high", "severity"},
		{"severity=1", "severity"},
		{"from=2026-13-01T00:00:00Z", "from"},
		{"from=yesterday", "from"},
		{"to=2026-10-25", "to"},
		{"from=%27%20OR%201%3D1--", "from"},
		{"from=2026-10-25T00:00:00Z&to=2026-10-24T00:00:00Z", "from"},
		{"from=2026-08-01T00:00:00Z&to=2026-10-01T00:00:00Z", "to"},
		{"limit=0", "limit"},
		{"limit=101", "limit"},
		{"limit=abc", "limit"},
		{"limit=-5", "limit"},
		{"cursor=not-a-cursor", "cursor"},
		{"cursor=%27%20OR%201%3D1--", "cursor"},
		{"cursor=LTMwMDAwMDAwMDAwMDAwMDAwMC41", "cursor"},
		{"actor_id=%00", "actor_id"},
		{"actor_id=a%00b", "actor_id"},
		{"actor_id=%FF%FE", "actor_id"},
		{"actor_id=%C3%28", "actor_id"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			r := &fakeReader{n: 1}
			rec := get(t, newQueryRouter(r), "/api/v1/events?"+tt.query, token(t, jwtauth.RoleAuditor))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if len(p.Errors) == 0 || p.Errors[0].Field != tt.field {
				t.Errorf("errors = %+v, want field %q", p.Errors, tt.field)
			}
			if r.filter.Limit != 0 {
				t.Error("the store was queried for an invalid request")
			}
		})
	}
}

func TestListEventsRequiresRole(t *testing.T) {
	h := newQueryRouter(&fakeReader{})
	if rec := get(t, h, "/api/v1/events", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := get(t, h, "/api/v1/events", token(t, "viewer")); rec.Code != http.StatusForbidden {
		t.Errorf("no role: status = %d, want 403", rec.Code)
	}
}

func TestSuspiciousStatsResponse(t *testing.T) {
	r := &fakeReader{}
	rec := get(t, newQueryRouter(r), "/api/v1/stats/suspicious?from=2026-10-25T10:00:00Z&to=2026-10-25T13:00:00Z", token(t, jwtauth.RoleAuditor))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	want := `{"from":"2026-10-25T10:00:00Z","to":"2026-10-25T13:00:00Z",` +
		`"failed_logins_per_hour":[{"hour":"2026-10-25T10:00:00Z","count":3}],` +
		`"denied_by_actor":[{"actor_id":"user-a","count":3},{"count":2}],` +
		`"top_ips_high_critical":[{"source_ip":"203.0.113.5","count":3}]}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
	if r.filter.Limit != application.StatsTop {
		t.Errorf("top = %d, want %d", r.filter.Limit, application.StatsTop)
	}
}

func TestSuspiciousStatsErrors(t *testing.T) {
	tests := []struct {
		name, query, bearer string
		status              int
	}{
		{"no token", "", "", http.StatusUnauthorized},
		{"no role", "", token(t, "viewer"), http.StatusForbidden},
		{"invalid date", "?from=25-10-2026", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"injection", "?to=%27%20OR%201%3D1--", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"from after to", "?from=2026-10-25T13:00:00Z&to=2026-10-25T10:00:00Z", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"range too long", "?from=2026-01-01T00:00:00Z&to=2026-10-25T00:00:00Z", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"year before 1", "?to=0000-01-05T00:00:00Z", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, newQueryRouter(&fakeReader{}), "/api/v1/stats/suspicious"+tt.query, tt.bearer)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			decodeProblem(t, rec)
		})
	}
	rec := get(t, newQueryRouter(&fakeReader{err: errors.New("pg down")}), "/api/v1/stats/suspicious", token(t, jwtauth.RoleAuditor))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "pg down") {
		t.Errorf("store failure: status %d body %s, want 500 without the cause", rec.Code, rec.Body)
	}
}

func TestVerifyIntegrity(t *testing.T) {
	admin := token(t, jwtauth.RoleAdmin)
	tests := []struct {
		query string
		want  string
	}{
		{"?from_id=4&to_id=5", `{"status":"ok","checked":2,"from_id":4,"to_id":5,"last_id":5,"last_hash":"ab` + strings.Repeat("0", 62) + `"}`},
		{"", `{"status":"broken","checked":3,"from_id":1,"first_broken_id":3}`},
		{"?from_id=2", `{"status":"broken","checked":2,"from_id":2,"first_broken_id":3}`},
	}
	for _, tt := range tests {
		rec := get(t, newQueryRouter(&fakeReader{}), "/api/v1/integrity/verify"+tt.query, admin)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body %s", tt.query, rec.Code, rec.Body)
		}
		if got := strings.TrimSpace(rec.Body.String()); got != tt.want {
			t.Errorf("%s: body =\n%s\nwant\n%s", tt.query, got, tt.want)
		}
	}
}

func TestVerifyIntegrityErrors(t *testing.T) {
	tests := []struct {
		name, query, bearer string
		status              int
	}{
		{"no token", "", "", http.StatusUnauthorized},
		{"auditor is not enough", "", token(t, jwtauth.RoleAuditor), http.StatusForbidden},
		{"from after to", "?from_id=5&to_id=4", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"zero id", "?from_id=0", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"not a number", "?to_id=abc", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
		{"injection", "?from_id=1%20OR%201%3D1", token(t, jwtauth.RoleAdmin), http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, newQueryRouter(&fakeReader{}), "/api/v1/integrity/verify"+tt.query, tt.bearer)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.status, rec.Body)
			}
			decodeProblem(t, rec)
		})
	}
}
