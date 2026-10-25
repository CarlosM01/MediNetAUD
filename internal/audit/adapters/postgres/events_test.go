package postgres

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres/pgtest"
	"github.com/medinetcore/aud/internal/audit/domain"
)

const testClient = "iam-service"

func setupStore(t *testing.T) (*EventStore, *pgxpool.Pool) {
	t.Helper()
	db := pgtest.Start(t)
	owner := pgtest.Pool(t, db.OwnerURL)
	if _, err := owner.Exec(context.Background(),
		`INSERT INTO api_clients (client_id, module_code, secret_enc) VALUES ($1, 'IAM', '\x00')`, testClient); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	app := pgtest.Pool(t, db.AppURL)
	return NewEventStore(app), app
}

func record(t *testing.T, i int, edit func(*domain.EventInput)) domain.Record {
	t.Helper()
	in := domain.EventInput{
		EventID:      fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
		SourceModule: "IAM",
		EventType:    "auth.login_failed",
		Severity:     "LOW",
		OccurredAt:   "2026-10-25T14:03:11.123456Z",
		ActorID:      fmt.Sprintf("user-%d", i),
		ActorType:    "user",
		SourceIP:     "203.0.113.24",
		Payload:      []byte(fmt.Sprintf(`{"attempt":%d}`, i)),
	}
	if edit != nil {
		edit(&in)
	}
	e, err := domain.NewEvent(in, time.Now())
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}
	return domain.Record{Event: e, ClientID: testClient, ReceivedAt: time.Now()}
}

// assertValidChain reads the whole table and recomputes every hash from the stored columns.
func assertValidChain(t *testing.T, pool *pgxpool.Pool, wantRows int) []domain.Record {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, "SELECT "+recordColumns+" FROM audit_logs ORDER BY id")
	if err != nil {
		t.Fatalf("query chain: %v", err)
	}
	defer rows.Close()

	var got []domain.Record
	prev := domain.GenesisHash
	for rows.Next() {
		_, r, err := scanRecord(rows)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if r.PrevHash != prev {
			t.Fatalf("row %d: prev_hash does not point to the previous row", len(got)+1)
		}
		if want := domain.ComputeHash(r.PrevHash, r); r.Hash != want {
			t.Fatalf("row %d (%s): stored hash %x, recomputed %x", len(got)+1, r.EventID, r.Hash, want)
		}
		prev = r.Hash
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != wantRows {
		t.Fatalf("chain has %d rows, want %d", len(got), wantRows)
	}
	return got
}

func TestAppendBuildsAValidChain(t *testing.T) {
	store, pool := setupStore(t)
	ctx := context.Background()

	const batches, perBatch = 5, 20
	for b := range batches {
		var recs []domain.Record
		for i := range perBatch {
			recs = append(recs, record(t, b*perBatch+i, nil))
		}
		n, err := store.Append(ctx, recs)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		if n != perBatch {
			t.Fatalf("Append inserted %d, want %d", n, perBatch)
		}
	}

	got := assertValidChain(t, pool, batches*perBatch)
	for i, r := range got {
		if want := fmt.Sprintf("00000000-0000-4000-8000-%012d", i); r.EventID != want {
			t.Fatalf("row %d is %s, want %s: insertion order lost", i, r.EventID, want)
		}
	}
}

func TestAppendSkipsRepeatedEventIDWithoutAdvancingTheChain(t *testing.T) {
	store, pool := setupStore(t)
	ctx := context.Background()

	if _, err := store.Append(ctx, []domain.Record{record(t, 1, nil)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := assertValidChain(t, pool, 1)

	changed := record(t, 1, func(in *domain.EventInput) { in.Severity = "CRITICAL" })
	n, err := store.Append(ctx, []domain.Record{changed})
	if err != nil {
		t.Fatalf("Append duplicate: %v", err)
	}
	if n != 0 {
		t.Fatalf("Append inserted %d duplicates, want 0", n)
	}
	after := assertValidChain(t, pool, 1)
	if after[0].Hash != before[0].Hash || after[0].Severity != domain.SeverityLow {
		t.Fatal("the first event was replaced by the duplicate")
	}

	// The chain still extends from the original tail.
	if _, err := store.Append(ctx, []domain.Record{record(t, 2, nil)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	assertValidChain(t, pool, 2)
}

func TestAppendSkipsDuplicatesInsideOneCall(t *testing.T) {
	store, pool := setupStore(t)
	n, err := store.Append(context.Background(), []domain.Record{record(t, 1, nil), record(t, 2, nil), record(t, 1, nil)})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if n != 2 {
		t.Fatalf("Append inserted %d, want 2", n)
	}
	assertValidChain(t, pool, 2)
}

func TestStoredFormsStillVerify(t *testing.T) {
	store, pool := setupStore(t)
	edits := []func(*domain.EventInput){
		// jsonb reorders keys by length and adds spaces.
		func(in *domain.EventInput) { in.Payload = []byte(`{"bbb":{"z":1,"a":[1.50,"x"]},"a":true,"cc":null}`) },
		func(in *domain.EventInput) {
			in.Payload = []byte(`{"big":12345678901234567890123,"exp":1e3,"uni":"ñ é <tag>"}`)
		},
		func(in *domain.EventInput) { in.SourceIP = "2001:DB8::0:1" },
		func(in *domain.EventInput) { in.SourceIP = "::ffff:192.0.2.1" },
		func(in *domain.EventInput) { in.SourceIP = ""; in.ActorID = ""; in.ActorType = "anonymous" },
		func(in *domain.EventInput) { in.OccurredAt = "2026-10-25T11:03:11.999999-03:00" },
		func(in *domain.EventInput) {
			in.TargetResource = "patient/8812"
			in.UserAgent = "Mozilla/5.0 (X11; Linux) ñ"
		},
	}
	var recs []domain.Record
	for i, edit := range edits {
		recs = append(recs, record(t, i, edit))
	}
	if _, err := store.Append(context.Background(), recs); err != nil {
		t.Fatalf("Append: %v", err)
	}
	assertValidChain(t, pool, len(edits))
}

func TestConcurrentAppendsKeepOneChain(t *testing.T) {
	store, pool := setupStore(t)
	const writers, perWriter = 4, 25

	recs := make([]domain.Record, writers*perWriter)
	for i := range recs {
		recs[i] = record(t, i, nil)
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(recs))
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, r := range recs[w*perWriter : (w+1)*perWriter] {
				if _, err := store.Append(context.Background(), []domain.Record{r}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Append: %v", err)
	}
	assertValidChain(t, pool, writers*perWriter)
}
