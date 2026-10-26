package ports

import (
	"context"
	"errors"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
)

// ErrClientNotFound means the client does not exist or is inactive.
var ErrClientNotFound = errors.New("client not found")

// Client is an emitter allowed to ingest events, with its HMAC secret in clear text.
type Client struct {
	ID     string
	Module string
	Secret []byte
}

// ClientStore looks up active ingest clients.
type ClientStore interface {
	FindClient(ctx context.Context, clientID string) (Client, error)
}

// EventStore persists records in the append-only hash chain.
type EventStore interface {
	// Append seals the records in order and stores them in one transaction. A record whose
	// event_id already exists is skipped and does not advance the chain. It returns how many
	// records were inserted.
	Append(ctx context.Context, records []domain.Record) (int, error)
}

// ErrRejectedRecord wraps store errors caused by the data itself: retrying the same records
// fails again. Any other store error is treated as temporary.
var ErrRejectedRecord = errors.New("record rejected by the store")

// Queue errors. Both are temporary: the emitter should retry later.
var (
	ErrQueueFull   = errors.New("event queue is full")
	ErrQueueClosed = errors.New("event queue is closed")
)

// Queue accepts records for asynchronous persistence.
type Queue interface {
	// Enqueue accepts every record or none. Records keep their order.
	Enqueue(records []domain.Record) error
}

// ErrEventNotFound means no stored event has the requested event_id.
var ErrEventNotFound = errors.New("event not found")

// StoredEvent is a record read back from the chain, with its position (audit_logs.id).
type StoredEvent struct {
	ID int64
	domain.Record
}

// Cursor is a position in the listing order (occurred_at DESC, id DESC).
type Cursor struct {
	OccurredAt time.Time
	ID         int64
}

// EventFilter selects events for a listing. Empty strings and nil pointers match anything.
type EventFilter struct {
	From, To     time.Time // inclusive bounds on occurred_at
	EventType    string
	SourceModule string
	ActorID      string
	Severity     *domain.Severity
	After        *Cursor // only events strictly after this position
	Limit        int
}

// EventReader reads the append-only chain for the query API.
type EventReader interface {
	// FindEvent returns the event with eventID (a valid UUID) or ErrEventNotFound.
	FindEvent(ctx context.Context, eventID string) (StoredEvent, error)
	// ListEvents returns at most f.Limit events matching f, newest first
	// (occurred_at DESC, id DESC).
	ListEvents(ctx context.Context, f EventFilter) ([]StoredEvent, error)
}
