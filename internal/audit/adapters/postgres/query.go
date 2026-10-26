package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/medinetcore/aud/internal/audit/domain"
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

const (
	failedLoginsPerHour = `SELECT date_trunc('hour', occurred_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour, count(*)
		FROM audit_logs
		WHERE event_type = 'auth.login_failed' AND occurred_at BETWEEN $1 AND $2
		GROUP BY hour ORDER BY hour`
	deniedByActor = `SELECT actor_id, count(*)
		FROM audit_logs
		WHERE event_type = 'access.denied' AND occurred_at BETWEEN $1 AND $2
		GROUP BY actor_id ORDER BY count(*) DESC, actor_id NULLS LAST LIMIT $3`
	topIPs = `SELECT host(source_ip) AS ip, count(*)
		FROM audit_logs
		WHERE severity >= $4 AND source_ip IS NOT NULL AND occurred_at BETWEEN $1 AND $2
		GROUP BY ip ORDER BY count(*) DESC, ip LIMIT $3`
)

// SuspiciousStats implements ports.EventReader. The three aggregates read one snapshot.
func (s *EventStore) SuspiciousStats(ctx context.Context, from, to time.Time, top int) (ports.SuspiciousStats, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ports.SuspiciousStats{}, fmt.Errorf("suspicious stats: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var stats ports.SuspiciousStats
	rows, _ := tx.Query(ctx, failedLoginsPerHour, from, to)
	stats.FailedLoginsPerHour, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ports.HourCount])
	if err != nil {
		return ports.SuspiciousStats{}, fmt.Errorf("failed logins per hour: %w", err)
	}
	for i := range stats.FailedLoginsPerHour {
		stats.FailedLoginsPerHour[i].Hour = stats.FailedLoginsPerHour[i].Hour.UTC()
	}

	rows, _ = tx.Query(ctx, deniedByActor, from, to, top)
	stats.DeniedByActor, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ports.ActorCount, error) {
		var actor *string
		var c ports.ActorCount
		err := row.Scan(&actor, &c.Count)
		c.ActorID = deref(actor)
		return c, err
	})
	if err != nil {
		return ports.SuspiciousStats{}, fmt.Errorf("denied by actor: %w", err)
	}

	rows, _ = tx.Query(ctx, topIPs, from, to, top, int16(domain.SeverityHigh))
	stats.TopIPs, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ports.IPCount])
	if err != nil {
		return ports.SuspiciousStats{}, fmt.Errorf("top ips: %w", err)
	}
	return stats, nil
}
