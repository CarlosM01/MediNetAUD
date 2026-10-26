package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres"
	"github.com/medinetcore/aud/internal/audit/adapters/postgres/pgtest"
	"github.com/medinetcore/aud/internal/audit/adapters/queue"
	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/jwtauth"
	"github.com/medinetcore/aud/internal/secretbox"
)

// Events ingested over signed HTTP can be read back, counted and verified through the query
// API, on a real database.
func TestQueryAPIReadsWhatIngestWrote(t *testing.T) {
	db := pgtest.Start(t)
	ctx := context.Background()
	box, err := secretbox.New([]byte(strings.Repeat("k", secretbox.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := postgres.NewClientStore(pgtest.Pool(t, db.OwnerURL), box).CreateClient(ctx, "iam-service", "IAM")
	if err != nil {
		t.Fatal(err)
	}
	app := pgtest.Pool(t, db.AppURL)
	store := postgres.NewEventStore(app)
	q := queue.New(store, 100, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, tokens := testKeys()
	srv := httptest.NewServer(NewRouter(Dependencies{
		Auth:   NewAuthenticator(postgres.NewClientStore(app, box)),
		Ingest: application.NewIngest(q),
		Tokens: tokens,
		Query:  application.NewQuery(store),
	}))
	defer srv.Close()

	const total = 120
	for i := range total {
		body := eventJSON(i, "IAM")
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(headerClientID, "iam-service")
		req.Header.Set(headerTimestamp, ts)
		req.Header.Set(headerSignature, sign(secret, ts, body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusAccepted {
			t.Fatalf("ingest %d: %v %v", i, err, resp)
		}
		_ = resp.Body.Close()
	}
	closeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := q.Close(closeCtx); err != nil {
		t.Fatal(err)
	}

	call := func(path string, roles []string, out any) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token(t, roles...))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if out != nil && resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode
	}
	auditor, admin := []string{jwtauth.RoleAuditor}, []string{jwtauth.RoleAdmin}
	rng := "from=" + url.QueryEscape("2026-10-25T00:00:00Z") + "&to=" + url.QueryEscape("2026-10-26T00:00:00Z")

	// Every event shares occurred_at, so the pages are cut by id alone.
	seen := map[int64]bool{}
	last := int64(total + 1)
	for cursor := ""; ; {
		var page struct {
			Items []struct {
				ID      int64  `json:"id"`
				EventID string `json:"event_id"`
			} `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		if code := call("/api/v1/events?limit=50&"+rng+"&cursor="+cursor, auditor, &page); code != http.StatusOK {
			t.Fatalf("list: status %d", code)
		}
		for _, it := range page.Items {
			if seen[it.ID] || it.ID >= last {
				t.Fatalf("id %d repeated or out of order (previous %d)", it.ID, last)
			}
			seen[it.ID], last = true, it.ID
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != total {
		t.Fatalf("listed %d events, want %d", len(seen), total)
	}

	var one struct {
		EventID string `json:"event_id"`
	}
	if code := call("/api/v1/events/00000000-0000-4000-8000-000000000007", auditor, &one); code != http.StatusOK || one.EventID != "00000000-0000-4000-8000-000000000007" {
		t.Errorf("get event: status %d, %+v", code, one)
	}

	var stats struct {
		Logins []struct {
			Hour  time.Time `json:"hour"`
			Count int64     `json:"count"`
		} `json:"failed_logins_per_hour"`
	}
	if code := call("/api/v1/stats/suspicious?"+rng, auditor, &stats); code != http.StatusOK ||
		len(stats.Logins) != 1 || stats.Logins[0].Count != total || !stats.Logins[0].Hour.Equal(time.Date(2026, 10, 25, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("stats: status %d, %+v; want %d failed logins at 14:00", code, stats, total)
	}

	var verify struct {
		Status  string `json:"status"`
		Checked int64  `json:"checked"`
		LastID  int64  `json:"last_id"`
	}
	if code := call("/api/v1/integrity/verify", admin, &verify); code != http.StatusOK || verify.Status != "ok" || verify.Checked != total || verify.LastID != total {
		t.Errorf("verify: status %d, %+v", code, verify)
	}
	if code := call("/api/v1/integrity/verify", auditor, nil); code != http.StatusForbidden {
		t.Errorf("verify as auditor: status %d, want 403", code)
	}
}
