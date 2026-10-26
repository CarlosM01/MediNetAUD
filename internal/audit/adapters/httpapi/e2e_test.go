package httpapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres"
	"github.com/medinetcore/aud/internal/audit/adapters/postgres/pgtest"
	"github.com/medinetcore/aud/internal/audit/adapters/queue"
	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/secretbox"
)

// Roadmap 3.5: "al enviar 1.000 eventos, los 1.000 quedan en la BD, ordenados y con la cadena válida".
func TestThousandEventsReachTheChainInOrder(t *testing.T) {
	db := pgtest.Start(t)
	ctx := context.Background()

	box, err := secretbox.New([]byte(strings.Repeat("k", secretbox.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := postgres.NewClientStore(pgtest.Pool(t, db.OwnerURL), box).CreateClient(ctx, "iam-service", "IAM")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	app := pgtest.Pool(t, db.AppURL)
	store := postgres.NewEventStore(app)
	q := queue.New(store, 2000, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(NewRouter(Dependencies{
		Auth:   NewAuthenticator(postgres.NewClientStore(app, box)),
		Ingest: application.NewIngest(q),
	}))
	defer srv.Close()

	send := func(path, body string) {
		t.Helper()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(headerClientID, "iam-service")
		req.Header.Set(headerTimestamp, ts)
		req.Header.Set(headerSignature, sign(secret, ts, body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST %s: status %d, want 202", path, resp.StatusCode)
		}
	}

	const singles, batches = 500, 5
	for i := range singles {
		send("/api/v1/events", eventJSON(i, "IAM"))
	}
	for b := range batches {
		events := make([]string, maxBatchEvents)
		for i := range events {
			events[i] = eventJSON(singles+b*maxBatchEvents+i, "IAM")
		}
		send("/api/v1/events/batch", `{"events":[`+strings.Join(events, ",")+`]}`)
	}
	// A retry of an event already accepted must not add a row.
	send("/api/v1/events", eventJSON(0, "IAM"))

	closeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := q.Close(closeCtx); err != nil {
		t.Fatalf("drain queue: %v", err)
	}

	report, err := store.VerifyChain(ctx, 1, math.MaxInt64)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	const total = singles + batches*maxBatchEvents
	if !report.OK || report.Checked != total {
		t.Fatalf("VerifyChain = %+v, want %d rows and a valid chain", report, total)
	}

	rows, err := app.Query(ctx, "SELECT event_id::text FROM audit_logs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("00000000-0000-4000-8000-%012d", i); id != want {
			t.Fatalf("row %d is %s, want %s", i, id, want)
		}
		i++
	}
}
