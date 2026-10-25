package queue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

// fakeStore records appended event ids. It can block until released and fail on demand.
type fakeStore struct {
	mu      sync.Mutex
	ids     []string
	calls   int
	release chan struct{} // when non-nil, Append waits for it
	failFor func(r []domain.Record) error
}

func (s *fakeStore) Append(_ context.Context, recs []domain.Record) (int, error) {
	if s.release != nil {
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failFor != nil {
		if err := s.failFor(recs); err != nil {
			return 0, err
		}
	}
	for _, r := range recs {
		s.ids = append(s.ids, r.EventID)
	}
	return len(recs), nil
}

func (s *fakeStore) stored() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ids...)
}

func rec(i int) domain.Record {
	return domain.Record{Event: domain.Event{EventID: fmt.Sprintf("e%04d", i)}}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestQueue(store ports.EventStore, capacity int) *Queue {
	q := New(store, capacity, quietLogger())
	q.retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	return q
}

func TestQueueKeepsOrderAndDrainsOnClose(t *testing.T) {
	store := &fakeStore{}
	q := newTestQueue(store, 2000)
	for i := range 1000 {
		if err := q.Enqueue([]domain.Record{rec(i)}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ids := store.stored()
	if len(ids) != 1000 {
		t.Fatalf("stored %d records, want 1000", len(ids))
	}
	for i, id := range ids {
		if id != rec(i).EventID {
			t.Fatalf("position %d holds %s, want %s", i, id, rec(i).EventID)
		}
	}
}

func TestQueueRejectsWhenFull(t *testing.T) {
	store := &fakeStore{release: make(chan struct{})}
	q := newTestQueue(store, 1)

	// The writer takes the first submission and blocks in Append; the second fills the buffer.
	if err := q.Enqueue([]domain.Record{rec(0)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(q.ch) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := q.Enqueue([]domain.Record{rec(1)}); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue([]domain.Record{rec(2)}); !errors.Is(err, ports.ErrQueueFull) {
		t.Fatalf("Enqueue on a full queue: err = %v, want ErrQueueFull", err)
	}

	close(store.release)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.stored(); len(got) != 2 {
		t.Fatalf("stored %v, want the two accepted records", got)
	}
}

func TestQueueRejectsAfterClose(t *testing.T) {
	q := newTestQueue(&fakeStore{}, 10)
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue([]domain.Record{rec(0)}); !errors.Is(err, ports.ErrQueueClosed) {
		t.Fatalf("err = %v, want ErrQueueClosed", err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestQueueCloseHonorsTheDeadline(t *testing.T) {
	store := &fakeStore{release: make(chan struct{})}
	defer close(store.release)
	q := newTestQueue(store, 10)
	if err := q.Enqueue([]domain.Record{rec(0)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := q.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close err = %v, want DeadlineExceeded", err)
	}
}

func TestQueueRetriesTransientStoreErrors(t *testing.T) {
	failures := 2
	store := &fakeStore{failFor: func([]domain.Record) error {
		if failures > 0 {
			failures--
			return errors.New("connection reset")
		}
		return nil
	}}
	q := newTestQueue(store, 10)
	if err := q.Enqueue([]domain.Record{rec(0), rec(1)}); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.stored(); len(got) != 2 {
		t.Fatalf("stored %v, want both records after the retries", got)
	}
}

func TestQueueIsolatesARecordThatAlwaysFails(t *testing.T) {
	store := &fakeStore{failFor: func(r []domain.Record) error {
		for _, x := range r {
			if x.EventID == rec(1).EventID {
				return fmt.Errorf("%w: invalid input syntax", ports.ErrRejectedRecord)
			}
		}
		return nil
	}}
	q := newTestQueue(store, 10)
	if err := q.Enqueue([]domain.Record{rec(0), rec(1), rec(2)}); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.stored()
	if len(got) != 2 || got[0] != rec(0).EventID || got[1] != rec(2).EventID {
		t.Fatalf("stored %v, want e0000 and e0002 in order", got)
	}
}
