package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

// fakeReader records the filter it receives and returns n events.
type fakeReader struct {
	got ports.EventFilter
	n   int
}

func (f *fakeReader) FindEvent(context.Context, string) (ports.StoredEvent, error) {
	return ports.StoredEvent{}, ports.ErrEventNotFound
}

func (f *fakeReader) ListEvents(_ context.Context, filter ports.EventFilter) ([]ports.StoredEvent, error) {
	f.got = filter
	out := make([]ports.StoredEvent, min(f.n, filter.Limit))
	for i := range out {
		out[i] = ports.StoredEvent{ID: int64(100 - i)}
		out[i].OccurredAt = testNow.Add(-time.Duration(i) * time.Minute).Truncate(time.Microsecond)
	}
	return out, nil
}

func (f *fakeReader) SuspiciousStats(_ context.Context, from, to time.Time, top int) (ports.SuspiciousStats, error) {
	f.got = ports.EventFilter{From: from, To: to, Limit: top}
	return ports.SuspiciousStats{TopIPs: []ports.IPCount{{IP: "203.0.113.5", Count: 2}}}, nil
}

func (f *fakeReader) VerifyChain(_ context.Context, fromID, toID int64) (ports.ChainReport, error) {
	f.got = ports.EventFilter{After: &ports.Cursor{ID: fromID}, Limit: int(min(toID, 1<<30))}
	return ports.ChainReport{OK: true, Checked: 3, LastID: 3}, nil
}

func newTestQuery(r ports.EventReader) *Query {
	q := NewQuery(r)
	q.now = func() time.Time { return testNow }
	return q
}

func TestListEventsDefaults(t *testing.T) {
	r := &fakeReader{}
	if _, err := newTestQuery(r).ListEvents(context.Background(), ListRequest{}); err != nil {
		t.Fatal(err)
	}
	want := ports.EventFilter{From: testNow.Add(-DefaultQueryRange), To: testNow, Limit: DefaultLimit + 1}
	if r.got.From != want.From || r.got.To != want.To || r.got.Limit != want.Limit || r.got.Severity != nil || r.got.After != nil {
		t.Errorf("filter = %+v, want %+v", r.got, want)
	}
}

func TestListEventsPassesFilters(t *testing.T) {
	r := &fakeReader{}
	from := testNow.Add(-48 * time.Hour)
	req := ListRequest{
		EventType: "access.denied", SourceModule: "HCE", ActorID: "' OR 1=1--", Severity: "HIGH",
		From: from, To: testNow.Add(-time.Hour), Limit: 10,
	}
	if _, err := newTestQuery(r).ListEvents(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	g := r.got
	if g.EventType != "access.denied" || g.SourceModule != "HCE" || g.ActorID != "' OR 1=1--" ||
		g.Severity == nil || *g.Severity != domain.SeverityHigh || !g.From.Equal(from) || !g.To.Equal(req.To) || g.Limit != 11 {
		t.Errorf("filter = %+v", g)
	}
}

func TestListEventsOnlyFromOrOnlyTo(t *testing.T) {
	r := &fakeReader{}
	q := newTestQuery(r)
	from := testNow.Add(-24 * time.Hour)
	if _, err := q.ListEvents(context.Background(), ListRequest{From: from}); err != nil {
		t.Fatal(err)
	}
	if !r.got.From.Equal(from) || !r.got.To.Equal(testNow) {
		t.Errorf("only from: filter = %v..%v, want %v..now", r.got.From, r.got.To, from)
	}

	to := testNow.Add(-24 * time.Hour)
	if _, err := q.ListEvents(context.Background(), ListRequest{To: to}); err != nil {
		t.Fatal(err)
	}
	if !r.got.From.Equal(to.Add(-DefaultQueryRange)) || !r.got.To.Equal(to) {
		t.Errorf("only to: filter = %v..%v, want to-%v..to", r.got.From, r.got.To, DefaultQueryRange)
	}
}

func TestListEventsPagination(t *testing.T) {
	r := &fakeReader{n: 50}
	q := newTestQuery(r)
	page, err := q.ListEvents(context.Background(), ListRequest{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 3 || page.NextCursor == "" {
		t.Fatalf("page = %d events, cursor %q; want 3 and a cursor", len(page.Events), page.NextCursor)
	}

	if _, err := q.ListEvents(context.Background(), ListRequest{Limit: 3, Cursor: page.NextCursor}); err != nil {
		t.Fatal(err)
	}
	last := page.Events[2]
	if a := r.got.After; a == nil || a.ID != last.ID || !a.OccurredAt.Equal(last.OccurredAt) {
		t.Errorf("After = %+v, want the position of the last event (%d, %v)", r.got.After, last.ID, last.OccurredAt)
	}

	r.n = 2
	page, err = q.ListEvents(context.Background(), ListRequest{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 || page.NextCursor != "" {
		t.Errorf("last page = %d events, cursor %q; want 2 and no cursor", len(page.Events), page.NextCursor)
	}
}

func TestListEventsRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name  string
		req   ListRequest
		field string
	}{
		{"unknown event_type", ListRequest{EventType: "' OR 1=1--"}, "event_type"},
		{"unknown source_module", ListRequest{SourceModule: "XYZ"}, "source_module"},
		{"lowercase severity", ListRequest{Severity: "high"}, "severity"},
		{"from after to", ListRequest{From: testNow.Add(-time.Hour), To: testNow.Add(-2 * time.Hour)}, "from"},
		{"range too long", ListRequest{From: testNow.Add(-MaxQueryRange - time.Second), To: testNow}, "to"},
		{"limit negative", ListRequest{Limit: -1}, "limit"},
		{"limit above max", ListRequest{Limit: MaxLimit + 1}, "limit"},
		{"cursor not base64", ListRequest{Cursor: "%%%"}, "cursor"},
		{"cursor wrong shape", ListRequest{Cursor: "aGVsbG8"}, "cursor"},
		{"cursor negative id", ListRequest{Cursor: encodeCursor(ports.Cursor{OccurredAt: testNow, ID: -1})}, "cursor"},
		{"cursor time out of range", ListRequest{Cursor: "LTMwMDAwMDAwMDAwMDAwMDAwMC41"}, "cursor"},
		{"actor_id with NUL", ListRequest{ActorID: "a\x00b"}, "actor_id"},
		{"actor_id invalid UTF-8", ListRequest{ActorID: "\xff\xfe"}, "actor_id"},
		{"to before year 1", ListRequest{To: time.Date(0, 1, 5, 0, 0, 0, 0, time.UTC)}, "from"},
		{"to after year 9999", ListRequest{From: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), To: time.Date(10000, 1, 2, 0, 0, 0, 0, time.UTC)}, "to"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeReader{}
			_, err := newTestQuery(r).ListEvents(context.Background(), tt.req)
			var verr *domain.ValidationError
			if !errors.As(err, &verr) || len(verr.Fields) == 0 || verr.Fields[0].Field != tt.field {
				t.Fatalf("err = %v, want a validation error on %q", err, tt.field)
			}
			if r.got.Limit != 0 {
				t.Error("reader was called for an invalid request")
			}
		})
	}
}

func TestListEventsAcceptsBoundaries(t *testing.T) {
	for _, req := range []ListRequest{
		{From: testNow.Add(-MaxQueryRange), To: testNow},
		{From: testNow, To: testNow},
		{Limit: MaxLimit},
		{Limit: 1},
	} {
		if _, err := newTestQuery(&fakeReader{}).ListEvents(context.Background(), req); err != nil {
			t.Errorf("ListEvents(%+v) = %v, want nil", req, err)
		}
	}
}

func TestSuspiciousStatsUsesResolvedRange(t *testing.T) {
	r := &fakeReader{}
	from := testNow.Add(-3 * time.Hour)
	report, err := newTestQuery(r).SuspiciousStats(context.Background(), StatsRequest{From: from})
	if err != nil {
		t.Fatal(err)
	}
	if !r.got.From.Equal(from) || !r.got.To.Equal(testNow) || r.got.Limit != StatsTop {
		t.Errorf("reader got %v..%v top %d, want %v..now top %d", r.got.From, r.got.To, r.got.Limit, from, StatsTop)
	}
	if !report.From.Equal(from) || !report.To.Equal(testNow) || len(report.TopIPs) != 1 {
		t.Errorf("report = %+v", report)
	}
}

func TestSuspiciousStatsRejectsInvalidRange(t *testing.T) {
	for _, req := range []StatsRequest{
		{From: testNow, To: testNow.Add(-time.Second)},
		{From: testNow.Add(-MaxQueryRange - time.Hour), To: testNow},
	} {
		r := &fakeReader{}
		_, err := newTestQuery(r).SuspiciousStats(context.Background(), req)
		var verr *domain.ValidationError
		if !errors.As(err, &verr) {
			t.Errorf("SuspiciousStats(%+v) = %v, want a validation error", req, err)
		}
		if r.got.Limit != 0 {
			t.Error("reader was called for an invalid range")
		}
	}
}

func TestVerifyChainRange(t *testing.T) {
	tests := []struct {
		req      VerifyRequest
		from, to int64
	}{
		{VerifyRequest{}, 1, 1 << 30},
		{VerifyRequest{FromID: 5}, 5, 1 << 30},
		{VerifyRequest{ToID: 9}, 1, 9},
		{VerifyRequest{FromID: 4, ToID: 4}, 4, 4},
	}
	for _, tt := range tests {
		r := &fakeReader{}
		report, err := newTestQuery(r).VerifyChain(context.Background(), tt.req)
		if err != nil {
			t.Fatalf("VerifyChain(%+v): %v", tt.req, err)
		}
		if r.got.After.ID != tt.from || int64(r.got.Limit) != tt.to {
			t.Errorf("VerifyChain(%+v) walked %d..%d, want %d..%d", tt.req, r.got.After.ID, r.got.Limit, tt.from, tt.to)
		}
		if report.FromID != tt.from || report.ToID != tt.req.ToID || !report.OK {
			t.Errorf("report = %+v", report)
		}
	}
}

func TestVerifyChainRejectsInvalidRange(t *testing.T) {
	for _, req := range []VerifyRequest{{FromID: 5, ToID: 4}, {FromID: -1}, {ToID: -3}} {
		r := &fakeReader{}
		_, err := newTestQuery(r).VerifyChain(context.Background(), req)
		var verr *domain.ValidationError
		if !errors.As(err, &verr) {
			t.Errorf("VerifyChain(%+v) = %v, want a validation error", req, err)
		}
		if r.got.After != nil {
			t.Error("reader was called for an invalid range")
		}
	}
}

func TestSuspiciousStatsRejectsYearsOutOfRange(t *testing.T) {
	r := &fakeReader{}
	_, err := newTestQuery(r).SuspiciousStats(context.Background(), StatsRequest{To: time.Date(0, 1, 5, 0, 0, 0, 0, time.UTC)})
	var verr *domain.ValidationError
	if !errors.As(err, &verr) || r.got.Limit != 0 {
		t.Fatalf("err = %v, reader called = %v; want a validation error before the store", err, r.got.Limit != 0)
	}
}
