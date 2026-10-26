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
