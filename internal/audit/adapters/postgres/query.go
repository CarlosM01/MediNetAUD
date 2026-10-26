package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/medinetcore/aud/internal/audit/ports"
)

var _ ports.EventReader = (*EventStore)(nil)

// FindEvent implements ports.EventReader.
func (s *EventStore) FindEvent(ctx context.Context, eventID string) (ports.StoredEvent, error) {
	row := s.pool.QueryRow(ctx, "SELECT "+recordColumns+" FROM audit_logs WHERE event_id = $1::uuid", eventID)
	id, r, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.StoredEvent{}, ports.ErrEventNotFound
	}
	if err != nil {
		return ports.StoredEvent{}, fmt.Errorf("find event: %w", err)
	}
	return ports.StoredEvent{ID: id, Record: r}, nil
}
