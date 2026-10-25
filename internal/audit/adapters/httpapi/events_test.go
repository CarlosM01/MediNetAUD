package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

type fakeQueue struct {
	records []domain.Record
	err     error
}

func (q *fakeQueue) Enqueue(r []domain.Record) error {
	if q.err != nil {
		return q.err
	}
	q.records = append(q.records, r...)
	return nil
}

func newTestRouter(q ports.Queue) http.Handler {
	auth := NewAuthenticator(testClients())
	auth.now = func() time.Time { return vectorNow }
	ingest := application.NewIngest(q)
	return NewRouter(Dependencies{Auth: auth, Ingest: ingest})
}

func post(t *testing.T, h http.Handler, path, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(headerClientID, vectorClient)
	req.Header.Set(headerTimestamp, vectorTimestamp)
	req.Header.Set(headerSignature, sign(vectorSecret, vectorTimestamp, body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func eventJSON(i int, module string) string {
	return fmt.Sprintf(`{"event_id":"00000000-0000-4000-8000-%012d","source_module":%q,"event_type":"auth.login_failed","severity":"LOW","occurred_at":"2026-10-25T14:03:11Z"}`, i, module)
}

func batchJSON(n int) string {
	events := make([]string, n)
	for i := range events {
		events[i] = eventJSON(i, "IAM")
	}
	return `{"events":[` + strings.Join(events, ",") + `]}`
}

func TestPostEventAccepted(t *testing.T) {
	q := &fakeQueue{}
	rec := post(t, newTestRouter(q), "/api/v1/events", vectorBody, "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "accepted" || body["event_id"] != "0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e8f" {
		t.Fatalf("body = %v, want status accepted and the event_id", body)
	}
	if len(q.records) != 1 || q.records[0].ClientID != vectorClient || q.records[0].ActorID != "user-1042" {
		t.Fatalf("queued %+v, want the event from %s", q.records, vectorClient)
	}
}

func TestPostEventAcceptsCharsetParameter(t *testing.T) {
	rec := post(t, newTestRouter(&fakeQueue{}), "/api/v1/events", vectorBody, "application/json; charset=utf-8")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}

func TestPostBatchAccepted(t *testing.T) {
	q := &fakeQueue{}
	rec := post(t, newTestRouter(q), "/api/v1/events/batch", batchJSON(maxBatchEvents), "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
	var body struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "accepted" || body.Count != maxBatchEvents || len(q.records) != maxBatchEvents {
		t.Fatalf("body = %+v, queued %d; want %d accepted", body, len(q.records), maxBatchEvents)
	}
}

func TestPostEventErrors(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		body        string
		contentType string
		queueErr    error
		status      int
		field       string
		retryAfter  bool
	}{
		{name: "malformed JSON", path: "/api/v1/events", body: `{"event_id":`, status: 400},
		{name: "trailing data", path: "/api/v1/events", body: eventJSON(1, "IAM") + `{}`, status: 400},
		{name: "unknown field", path: "/api/v1/events", body: strings.Replace(eventJSON(1, "IAM"), `{`, `{"sevrity":"LOW",`, 1), status: 400, field: "sevrity"},
		{name: "wrong type", path: "/api/v1/events", body: strings.Replace(eventJSON(1, "IAM"), `"LOW"`, `3`, 1), status: 400, field: "severity"},
		{name: "invalid field", path: "/api/v1/events", body: strings.Replace(eventJSON(1, "IAM"), `"LOW"`, `"SEVERE"`, 1), status: 400, field: "severity"},
		{name: "body is an array", path: "/api/v1/events", body: `[]`, status: 400},
		{name: "other module", path: "/api/v1/events", body: eventJSON(1, "FAR"), status: 403},
		{name: "not JSON content type", path: "/api/v1/events", body: eventJSON(1, "IAM"), contentType: "text/plain", status: 415},
		{name: "missing content type", path: "/api/v1/events", body: eventJSON(1, "IAM"), contentType: "-", status: 415},
		{name: "queue full", path: "/api/v1/events", body: eventJSON(1, "IAM"), queueErr: ports.ErrQueueFull, status: 503, retryAfter: true},
		{name: "shutting down", path: "/api/v1/events", body: eventJSON(1, "IAM"), queueErr: ports.ErrQueueClosed, status: 503, retryAfter: true},
		{name: "event body over 64 KiB", path: "/api/v1/events", body: `{"x":"` + strings.Repeat("a", maxEventBody) + `"}`, status: 413},
		{name: "empty batch", path: "/api/v1/events/batch", body: `{"events":[]}`, status: 400, field: "events"},
		{name: "batch without events", path: "/api/v1/events/batch", body: `{}`, status: 400, field: "events"},
		{name: "batch over 100 events", path: "/api/v1/events/batch", body: batchJSON(maxBatchEvents + 1), status: 400, field: "events"},
		{name: "batch with unknown top-level field", path: "/api/v1/events/batch", body: `{"events":[` + eventJSON(1, "IAM") + `],"extra":1}`, status: 400, field: "extra"},
		{name: "batch with an invalid event", path: "/api/v1/events/batch", body: `{"events":[` + eventJSON(1, "IAM") + `,` + strings.Replace(eventJSON(2, "IAM"), `"LOW"`, `"x"`, 1) + `]}`, status: 400, field: "events[1].severity"},
		{name: "batch with an unknown field in an event", path: "/api/v1/events/batch", body: `{"events":[{"bogus":1}]}`, status: 400, field: "events[0].bogus"},
		{name: "batch with an event of another module", path: "/api/v1/events/batch", body: `{"events":[` + eventJSON(1, "IAM") + `,` + eventJSON(2, "LAB") + `]}`, status: 403},
		{name: "batch body over 1 MiB", path: "/api/v1/events/batch", body: `{"x":"` + strings.Repeat("a", maxBatchBody) + `"}`, status: 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := tt.contentType
			switch ct {
			case "":
				ct = "application/json"
			case "-":
				ct = ""
			}
			q := &fakeQueue{err: tt.queueErr}
			rec := post(t, newTestRouter(q), tt.path, tt.body, ct)
			p := assertProblem(t, rec, tt.status)
			if tt.field != "" && (len(p.Errors) == 0 || p.Errors[0].Field != tt.field) {
				t.Errorf("errors = %+v, want a field error on %q", p.Errors, tt.field)
			}
			if tt.retryAfter {
				if s, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || s < 1 {
					t.Errorf("Retry-After = %q, want a positive number of seconds", rec.Header().Get("Retry-After"))
				}
			}
			if tt.status != http.StatusServiceUnavailable && len(q.records) != 0 {
				t.Errorf("a rejected request queued %d records", len(q.records))
			}
		})
	}
}

func TestIngestRoutesRequireASignature(t *testing.T) {
	h := newTestRouter(&fakeQueue{})
	for _, path := range []string{"/api/v1/events", "/api/v1/events/batch"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(eventJSON(1, "IAM")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assertProblem(t, rec, http.StatusUnauthorized)
	}
}
