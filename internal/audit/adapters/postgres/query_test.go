package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

func TestFindEvent(t *testing.T) {
	store, _ := setupStore(t)
	ctx := context.Background()
	recs := []domain.Record{record(t, 1, nil), record(t, 2, func(in *domain.EventInput) {
		in.SourceIP, in.ActorID, in.ActorType = "", "", ""
		in.Payload = []byte(`{"n": 12345678901234567890, "a": [1, 2]}`)
	})}
	if _, err := store.Append(ctx, recs); err != nil {
		t.Fatal(err)
	}

	got, err := store.FindEvent(ctx, recs[1].EventID)
	if err != nil {
		t.Fatalf("FindEvent: %v", err)
	}
	if got.ID != 2 || got.EventID != recs[1].EventID || got.ActorID != "" || got.SourceIP != "" {
		t.Errorf("FindEvent = %+v, want the second record with no actor or IP", got)
	}
	if string(got.Payload) != `{"a": [1, 2], "n": 12345678901234567890}` {
		t.Errorf("payload = %s, want the stored jsonb text", got.Payload)
	}
	if got.Hash != domain.ComputeHash(got.PrevHash, got.Record) {
		t.Error("returned record does not match its own hash")
	}

	_, err = store.FindEvent(ctx, "11111111-2222-4333-8444-555555555555")
	if !errors.Is(err, ports.ErrEventNotFound) {
		t.Errorf("FindEvent(unknown) error = %v, want ErrEventNotFound", err)
	}
}

// listFixture stores 12 events spread over three hours, with several sharing occurred_at so
// pagination has to break ties by id.
func listFixture(t *testing.T) (*EventStore, time.Time) {
	t.Helper()
	store, _ := setupStore(t)
	base := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	types := []string{"auth.login_failed", "access.denied", "data.export"}
	sevs := []string{"LOW", "HIGH", "CRITICAL", "INFO"}
	var recs []domain.Record
	for i := 1; i <= 12; i++ {
		recs = append(recs, record(t, i, func(in *domain.EventInput) {
			in.EventType = types[i%3]
			in.Severity = sevs[i%4]
			in.ActorID = fmt.Sprintf("user-%d", i%2)
			in.OccurredAt = base.Add(time.Duration(i/3) * time.Hour).Format(time.RFC3339Nano)
		}))
	}
	if _, err := store.Append(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	return store, base
}

func eventNumbers(events []ports.StoredEvent) []int64 {
	ids := make([]int64, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	return ids
}

func TestListEventsFilters(t *testing.T) {
	store, base := listFixture(t)
	ctx := context.Background()
	high := domain.SeverityHigh
	all := ports.EventFilter{From: base.Add(-time.Hour), To: base.Add(5 * time.Hour), Limit: 100}
	with := func(edit func(*ports.EventFilter)) ports.EventFilter {
		f := all
		edit(&f)
		return f
	}

	tests := []struct {
		name string
		f    ports.EventFilter
		want []int64
	}{
		// Order is occurred_at DESC, id DESC. Event i occurs at base + i/3 hours.
		{"everything", all, []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
		{"event_type", with(func(f *ports.EventFilter) { f.EventType = "access.denied" }), []int64{10, 7, 4, 1}},
		{"severity", with(func(f *ports.EventFilter) { f.Severity = &high }), []int64{9, 5, 1}},
		{"actor_id", with(func(f *ports.EventFilter) { f.ActorID = "user-0" }), []int64{12, 10, 8, 6, 4, 2}},
		{"source_module", with(func(f *ports.EventFilter) { f.SourceModule = "IAM" }), []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
		{"other source_module", with(func(f *ports.EventFilter) { f.SourceModule = "LAB" }), []int64{}},
		{"from inclusive", with(func(f *ports.EventFilter) { f.From = base.Add(3 * time.Hour) }), []int64{12, 11, 10, 9}},
		{"to inclusive", with(func(f *ports.EventFilter) { f.To = base }), []int64{2, 1}},
		{"combined", with(func(f *ports.EventFilter) {
			f.EventType, f.ActorID, f.From = "access.denied", "user-0", base.Add(time.Hour)
		}), []int64{10, 4}},
		{"injection in actor_id", with(func(f *ports.EventFilter) { f.ActorID = "' OR 1=1--" }), []int64{}},
		{"injection in event_type", with(func(f *ports.EventFilter) { f.EventType = "x' OR '1'='1" }), []int64{}},
		{"limit", with(func(f *ports.EventFilter) { f.Limit = 2 }), []int64{12, 11}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.ListEvents(ctx, tt.f)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			if ids := eventNumbers(got); !slices.Equal(ids, tt.want) {
				t.Errorf("ids = %v, want %v", ids, tt.want)
			}
		})
	}
}

func TestListEventsKeysetWalksEveryEventOnce(t *testing.T) {
	store, base := listFixture(t)
	ctx := context.Background()
	f := ports.EventFilter{From: base.Add(-time.Hour), To: base.Add(5 * time.Hour), Limit: 5}

	var walked []int64
	for page := 0; page < 10; page++ {
		got, err := store.ListEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		walked = append(walked, eventNumbers(got)...)
		if len(got) < f.Limit {
			break
		}
		last := got[len(got)-1]
		f.After = &ports.Cursor{OccurredAt: last.OccurredAt, ID: last.ID}
	}
	if want := []int64{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}; !slices.Equal(walked, want) {
		t.Errorf("walked %v, want %v", walked, want)
	}
}
