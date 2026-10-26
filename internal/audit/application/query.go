package application

import (
	"context"

	"github.com/medinetcore/aud/internal/audit/ports"
)

// Query reads the audit log for auditors and administrators.
type Query struct {
	events ports.EventReader
}

// NewQuery returns the query use case reading from events.
func NewQuery(events ports.EventReader) *Query {
	return &Query{events: events}
}

// FindEvent returns one event by its event_id, or ports.ErrEventNotFound.
func (q *Query) FindEvent(ctx context.Context, eventID string) (ports.StoredEvent, error) {
	return q.events.FindEvent(ctx, eventID)
}
