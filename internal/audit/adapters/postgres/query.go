package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

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

// ListEvents implements ports.EventReader. Every value travels as a query parameter; only
// the fixed condition texts are concatenated.
func (s *EventStore) ListEvents(ctx context.Context, f ports.EventFilter) ([]ports.StoredEvent, error) {
	conds := []string{"occurred_at >= $1", "occurred_at <= $2"}
	args := []any{f.From, f.To}
	// add appends a condition, numbering each ? placeholder after the arguments so far.
	add := func(cond string, vals ...any) {
		for _, v := range vals {
			args = append(args, v)
			cond = strings.Replace(cond, "?", "$"+strconv.Itoa(len(args)), 1)
		}
		conds = append(conds, cond)
	}
	if f.EventType != "" {
		add("event_type = ?", f.EventType)
	}
	if f.SourceModule != "" {
		add("source_module = ?", f.SourceModule)
	}
	if f.ActorID != "" {
		add("actor_id = ?", f.ActorID)
	}
	if f.Severity != nil {
		add("severity = ?", int16(*f.Severity))
	}
	if f.After != nil {
		add("(occurred_at, id) < (?, ?)", f.After.OccurredAt, f.After.ID)
	}
	args = append(args, f.Limit)
	sql := "SELECT " + recordColumns + " FROM audit_logs WHERE " + strings.Join(conds, " AND ") +
		" ORDER BY occurred_at DESC, id DESC LIMIT $" + strconv.Itoa(len(args))

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()
	events := []ports.StoredEvent{}
	for rows.Next() {
		id, r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("list events: %w", err)
		}
		events = append(events, ports.StoredEvent{ID: id, Record: r})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return events, nil
}
