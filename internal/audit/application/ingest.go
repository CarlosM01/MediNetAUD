package application

import (
	"errors"
	"fmt"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

// ErrModuleMismatch means an event names a source_module other than the client's own.
var ErrModuleMismatch = errors.New("client is not allowed to emit events for this source_module")

// Ingest validates events from an authenticated client and queues them for the chain.
type Ingest struct {
	queue ports.Queue
	now   func() time.Time
}

// NewIngest returns the ingest use case writing to queue.
func NewIngest(queue ports.Queue) *Ingest {
	return &Ingest{queue: queue, now: time.Now}
}

// Submit accepts every event or none. Validation errors come first (*domain.ValidationError,
// with fields prefixed by events[i]. when batch is true), then ErrModuleMismatch, then the
// queue errors (ports.ErrQueueFull, ports.ErrQueueClosed).
func (s *Ingest) Submit(client ports.Client, inputs []domain.EventInput, batch bool) error {
	now := s.now()
	receivedAt := now.UTC().Truncate(time.Microsecond)

	records := make([]domain.Record, 0, len(inputs))
	var fields []domain.FieldError
	mismatch := false
	for i, in := range inputs {
		e, err := domain.NewEvent(in, now)
		var verr *domain.ValidationError
		if errors.As(err, &verr) {
			for _, f := range verr.Fields {
				if batch {
					f.Field = fmt.Sprintf("events[%d].%s", i, f.Field)
				}
				fields = append(fields, f)
			}
			continue
		}
		if err != nil {
			return err
		}
		if e.SourceModule != client.Module {
			mismatch = true
		}
		records = append(records, domain.Record{Event: e, ClientID: client.ID, ReceivedAt: receivedAt})
	}

	switch {
	case len(fields) > 0:
		return &domain.ValidationError{Fields: fields}
	case mismatch:
		return ErrModuleMismatch
	}
	return s.queue.Enqueue(records)
}
