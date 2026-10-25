package queue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

const (
	// maxWriteBatch caps how many queued records the writer appends in one transaction.
	maxWriteBatch = 500
	// appendTimeout bounds one Append call so a hung connection cannot stall the writer.
	appendTimeout = 30 * time.Second
)

// Queue is a buffered channel drained by a single writer goroutine. One writer means records
// reach the store in the order they were accepted, which is the order of the hash chain.
type Queue struct {
	ch    chan []domain.Record
	store ports.EventStore
	log   *slog.Logger
	done  chan struct{}

	mu     sync.RWMutex
	closed bool

	// retryDelays is the backoff between attempts after a temporary store error; the last
	// delay repeats until the store recovers.
	retryDelays []time.Duration
}

var _ ports.Queue = (*Queue)(nil)

// New starts a queue that holds up to capacity submissions and writes them to store.
func New(store ports.EventStore, capacity int, log *slog.Logger) *Queue {
	q := &Queue{
		ch:          make(chan []domain.Record, capacity),
		store:       store,
		log:         log,
		done:        make(chan struct{}),
		retryDelays: []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second, 5 * time.Second},
	}
	go q.run()
	return q
}

// Enqueue implements ports.Queue. It never blocks: a full buffer returns ports.ErrQueueFull.
func (q *Queue) Enqueue(records []domain.Record) error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return ports.ErrQueueClosed
	}
	select {
	case q.ch <- records:
		return nil
	default:
		return ports.ErrQueueFull
	}
}

// Close stops accepting records and waits until the writer has stored every queued one, or
// until ctx ends.
func (q *Queue) Close(ctx context.Context) error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()

	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *Queue) run() {
	defer close(q.done)
	for first := range q.ch {
		batch := append([]domain.Record(nil), first...)
	drain:
		for len(batch) < maxWriteBatch {
			select {
			case more, ok := <-q.ch:
				if !ok {
					break drain
				}
				batch = append(batch, more...)
			default:
				break drain
			}
		}
		q.write(batch)
	}
}

// write stores batch. If the store rejects it because of its data, each record is retried on
// its own so one bad record does not take the others down with it.
func (q *Queue) write(batch []domain.Record) {
	err := q.appendWithRetry(batch)
	if err == nil {
		return
	}
	if len(batch) == 1 {
		q.log.Error("event dropped: rejected by the store", "event_id", batch[0].EventID, "client_id", batch[0].ClientID, "error", err)
		return
	}
	for _, r := range batch {
		if err := q.appendWithRetry([]domain.Record{r}); err != nil {
			q.log.Error("event dropped: rejected by the store", "event_id", r.EventID, "client_id", r.ClientID, "error", err)
		}
	}
}

// appendWithRetry retries temporary errors until they succeed and returns only errors that
// wrap ports.ErrRejectedRecord. While it waits the buffer fills and Enqueue answers 503,
// which pushes the backpressure to the emitters.
func (q *Queue) appendWithRetry(batch []domain.Record) error {
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), appendTimeout)
		_, err := q.store.Append(ctx, batch)
		cancel()
		if err == nil || errors.Is(err, ports.ErrRejectedRecord) {
			return err
		}
		delay := q.retryDelays[min(attempt, len(q.retryDelays)-1)]
		q.log.Warn("event store unavailable, retrying", "records", len(batch), "attempt", attempt+1, "retry_in", delay, "error", err)
		time.Sleep(delay)
	}
}
