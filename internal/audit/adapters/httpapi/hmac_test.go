package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/ports"
)

// Test vector of docs/CONTRATO_INGESTA.md §3.
const (
	vectorSecret    = "ejemplo-secreto-no-usar-en-produccion"
	vectorTimestamp = "1792936991"
	vectorBody      = `{"event_id":"0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e8f","source_module":"IAM","event_type":"auth.login_failed","severity":"LOW","actor_id":"user-1042","actor_type":"user","source_ip":"203.0.113.24","occurred_at":"2026-10-25T14:03:11Z","payload":{"reason":"invalid_password","attempt":3}}`
	vectorSignature = "sha256=8bfc6b22344c1172da861ecd04ba336baff71b9b5a342e87a3df55f07ea5f5c8"
	vectorClient    = "iam-service"
)

var vectorNow = time.Unix(1792936991, 0)

type fakeClients map[string]ports.Client

func (f fakeClients) FindClient(_ context.Context, id string) (ports.Client, error) {
	c, ok := f[id]
	if !ok {
		return ports.Client{}, ports.ErrClientNotFound
	}
	return c, nil
}

func testClients() fakeClients {
	return fakeClients{vectorClient: {ID: vectorClient, Module: "IAM", Secret: []byte(vectorSecret)}}
}

func sign(secret, ts, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "." + body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// echoAuthenticated answers 200 with the authenticated client id and the body it received.
var echoAuthenticated = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	c, ok := clientFrom(r.Context())
	body, _ := io.ReadAll(r.Body)
	if !ok {
		http.Error(w, "no client in context", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"client": c.ID, "body": string(body)})
})

type signedRequest struct {
	clientID, timestamp, signature, body string
	omit                                 string // header to leave out
}

func vectorRequest() signedRequest {
	return signedRequest{clientID: vectorClient, timestamp: vectorTimestamp, signature: vectorSignature, body: vectorBody}
}

func doSigned(t *testing.T, h http.Handler, sr signedRequest) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(sr.body))
	req.Header.Set("Content-Type", "application/json")
	for name, v := range map[string]string{
		headerClientID:  sr.clientID,
		headerTimestamp: sr.timestamp,
		headerSignature: sr.signature,
	} {
		if name != sr.omit {
			req.Header.Set(name, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newTestAuth(now time.Time) *Authenticator {
	a := NewAuthenticator(testClients())
	a.now = func() time.Time { return now }
	return a
}

func TestSignatureValidForContractVector(t *testing.T) {
	h := newTestAuth(vectorNow).Middleware(maxEventBody, echoAuthenticated)
	rec := doSigned(t, h, vectorRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	var got map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["client"] != vectorClient || got["body"] != vectorBody {
		t.Fatalf("handler got %v, want the client and the exact body", got)
	}
}

func TestSignatureWindowEdgesAreAccepted(t *testing.T) {
	for _, offset := range []time.Duration{-SignatureWindow, SignatureWindow} {
		h := newTestAuth(vectorNow.Add(offset)).Middleware(maxEventBody, echoAuthenticated)
		if rec := doSigned(t, h, vectorRequest()); rec.Code != http.StatusOK {
			t.Errorf("clock offset %v: status = %d, want 200", offset, rec.Code)
		}
	}
}

func TestSignatureRejections(t *testing.T) {
	tests := []struct {
		name  string
		now   time.Time
		edit  func(*signedRequest)
		extra string
	}{
		{name: "invalid signature", edit: func(sr *signedRequest) { sr.signature = sign("other-secret", sr.timestamp, sr.body) }},
		{name: "altered body", edit: func(sr *signedRequest) { sr.body = strings.Replace(sr.body, `"LOW"`, `"INFO"`, 1) }},
		{name: "old timestamp", now: vectorNow.Add(SignatureWindow + time.Second)},
		{name: "timestamp from the future", now: vectorNow.Add(-SignatureWindow - time.Second)},
		{name: "replay of an old request re-signed with a new timestamp header only", edit: func(sr *signedRequest) {
			sr.timestamp = strconv.FormatInt(vectorNow.Unix()+1, 10)
		}},
		{name: "unknown client", edit: func(sr *signedRequest) { sr.clientID = "ghost-service" }},
		{name: "missing client id", edit: func(sr *signedRequest) { sr.omit = headerClientID }},
		{name: "missing timestamp", edit: func(sr *signedRequest) { sr.omit = headerTimestamp }},
		{name: "missing signature", edit: func(sr *signedRequest) { sr.omit = headerSignature }},
		{name: "timestamp not an integer", edit: func(sr *signedRequest) { sr.timestamp = "1792936991.0" }},
		{name: "timestamp with sign", edit: func(sr *signedRequest) { sr.timestamp = "+1792936991" }},
		{name: "signature without prefix", edit: func(sr *signedRequest) { sr.signature = strings.TrimPrefix(sr.signature, "sha256=") }},
		{name: "signature in uppercase hex", edit: func(sr *signedRequest) {
			sr.signature = "sha256=" + strings.ToUpper(strings.TrimPrefix(sr.signature, "sha256="))
		}},
		{name: "truncated signature", edit: func(sr *signedRequest) { sr.signature = sr.signature[:len(sr.signature)-2] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := tt.now
			if now.IsZero() {
				now = vectorNow
			}
			sr := vectorRequest()
			if tt.edit != nil {
				tt.edit(&sr)
			}
			rec := doSigned(t, newTestAuth(now).Middleware(maxEventBody, echoAuthenticated), sr)
			assertProblem(t, rec, http.StatusUnauthorized)
			if !strings.Contains(rec.Body.String(), "invalid request signature") {
				t.Errorf("body %s does not use the single 401 message", rec.Body)
			}
		})
	}
}

func TestBodyOverTheLimitIsRejected(t *testing.T) {
	body := `{"payload":"` + strings.Repeat("x", maxEventBody) + `"}`
	sr := vectorRequest()
	sr.body = body
	sr.signature = sign(vectorSecret, sr.timestamp, body)
	rec := doSigned(t, newTestAuth(vectorNow).Middleware(maxEventBody, echoAuthenticated), sr)
	assertProblem(t, rec, http.StatusRequestEntityTooLarge)
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int) problem {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Status != status || p.Type != "about:blank" || p.Title != http.StatusText(status) {
		t.Fatalf("problem = %+v, want status %d", p, status)
	}
	return p
}
