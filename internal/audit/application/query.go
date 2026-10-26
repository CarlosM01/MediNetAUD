package application

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

// Limits of the query API.
const (
	// DefaultQueryRange is the window used when from or to is missing.
	DefaultQueryRange = 7 * 24 * time.Hour
	// MaxQueryRange is the widest window one request may cover.
	MaxQueryRange = 31 * 24 * time.Hour
	// DefaultLimit and MaxLimit bound the events per page.
	DefaultLimit = 50
	MaxLimit     = 100
	// StatsTop is how many actors and IPs the suspicious activity report ranks.
	StatsTop = 10
)

// Query reads the audit log for auditors and administrators.
type Query struct {
	events ports.EventReader
	now    func() time.Time
}

// NewQuery returns the query use case reading from events.
func NewQuery(events ports.EventReader) *Query {
	return &Query{events: events, now: time.Now}
}

// FindEvent returns one event by its event_id, or ports.ErrEventNotFound.
func (q *Query) FindEvent(ctx context.Context, eventID string) (ports.StoredEvent, error) {
	return q.events.FindEvent(ctx, eventID)
}

// ListRequest is a listing as the caller sent it. Zero values mean "not sent".
type ListRequest struct {
	EventType    string
	SourceModule string
	ActorID      string
	Severity     string
	From, To     time.Time
	Cursor       string
	Limit        int
}

// EventPage is one page of a listing. NextCursor is empty on the last page.
type EventPage struct {
	Events     []ports.StoredEvent
	NextCursor string
}

// ListEvents returns the events matching req, newest first. Invalid requests return a
// *domain.ValidationError naming every wrong parameter.
func (q *Query) ListEvents(ctx context.Context, req ListRequest) (EventPage, error) {
	var errs []domain.FieldError
	fail := func(field, msg string) { errs = append(errs, domain.FieldError{Field: field, Message: msg}) }

	f := ports.EventFilter{EventType: req.EventType, SourceModule: req.SourceModule, ActorID: req.ActorID}
	if req.EventType != "" && !slices.Contains(domain.EventTypes(), req.EventType) {
		fail("event_type", "must be an event type of the catalog")
	}
	if req.SourceModule != "" && !slices.Contains(domain.SourceModules(), req.SourceModule) {
		fail("source_module", "must be one of "+strings.Join(domain.SourceModules(), ", "))
	}
	if req.Severity != "" {
		s, err := domain.ParseSeverity(req.Severity)
		if err != nil {
			fail("severity", "must be one of INFO, LOW, MEDIUM, HIGH, CRITICAL")
		} else {
			f.Severity = &s
		}
	}

	var rangeErrs []domain.FieldError
	f.From, f.To, rangeErrs = resolveRange(req.From, req.To, q.now())
	errs = append(errs, rangeErrs...)

	limit := req.Limit
	switch {
	case limit == 0:
		limit = DefaultLimit
	case limit < 1 || limit > MaxLimit:
		fail("limit", fmt.Sprintf("must be between 1 and %d", MaxLimit))
	}

	if req.Cursor != "" {
		c, err := decodeCursor(req.Cursor)
		if err != nil {
			fail("cursor", "is not a cursor returned by this API")
		} else {
			f.After = &c
		}
	}

	if len(errs) > 0 {
		return EventPage{}, &domain.ValidationError{Fields: errs}
	}

	// One extra event tells whether another page exists.
	f.Limit = limit + 1
	events, err := q.events.ListEvents(ctx, f)
	if err != nil {
		return EventPage{}, err
	}
	page := EventPage{Events: events}
	if len(events) > limit {
		page.Events = events[:limit]
		last := page.Events[limit-1]
		page.NextCursor = encodeCursor(ports.Cursor{OccurredAt: last.OccurredAt, ID: last.ID})
	}
	return page, nil
}

// StatsRequest is the range of a suspicious activity report. Zero values mean "not sent".
type StatsRequest struct {
	From, To time.Time
}

// StatsReport is the suspicious activity in [From, To].
type StatsReport struct {
	From, To time.Time
	ports.SuspiciousStats
}

// SuspiciousStats counts failed logins per hour, denied accesses per actor and the IPs with
// the most HIGH or CRITICAL events. The range follows the same rules as ListEvents.
func (q *Query) SuspiciousStats(ctx context.Context, req StatsRequest) (StatsReport, error) {
	from, to, errs := resolveRange(req.From, req.To, q.now())
	if len(errs) > 0 {
		return StatsReport{}, &domain.ValidationError{Fields: errs}
	}
	stats, err := q.events.SuspiciousStats(ctx, from, to, StatsTop)
	if err != nil {
		return StatsReport{}, err
	}
	return StatsReport{From: from, To: to, SuspiciousStats: stats}, nil
}

// VerifyRequest is an id range of the chain. Zero means "from the first row" for FromID and
// "to the last row" for ToID.
type VerifyRequest struct {
	FromID, ToID int64
}

// VerifyReport is the result of verifying [FromID, ToID]; ToID is 0 for an open range.
type VerifyReport struct {
	FromID, ToID int64
	ports.ChainReport
}

// VerifyChain checks the hash chain over the requested id range.
func (q *Query) VerifyChain(ctx context.Context, req VerifyRequest) (VerifyReport, error) {
	var errs []domain.FieldError
	switch {
	case req.FromID < 0:
		errs = append(errs, domain.FieldError{Field: "from_id", Message: "must be positive"})
	case req.ToID < 0:
		errs = append(errs, domain.FieldError{Field: "to_id", Message: "must be positive"})
	case req.ToID > 0 && req.FromID > req.ToID:
		errs = append(errs, domain.FieldError{Field: "from_id", Message: "must not be greater than to_id"})
	}
	if len(errs) > 0 {
		return VerifyReport{}, &domain.ValidationError{Fields: errs}
	}

	from, to := max(req.FromID, 1), req.ToID
	if to == 0 {
		to = math.MaxInt64
	}
	report, err := q.events.VerifyChain(ctx, from, to)
	if err != nil {
		return VerifyReport{}, err
	}
	return VerifyReport{FromID: from, ToID: req.ToID, ChainReport: report}, nil
}

// resolveRange fills a missing bound from the other one (or from now) and checks that
// from <= to and that the window is at most MaxQueryRange.
func resolveRange(from, to, now time.Time) (time.Time, time.Time, []domain.FieldError) {
	if to.IsZero() {
		to = now
		if !from.IsZero() && from.After(to) {
			to = from
		}
	}
	if from.IsZero() {
		from = to.Add(-DefaultQueryRange)
	}
	switch {
	case from.After(to):
		return from, to, []domain.FieldError{{Field: "from", Message: "must not be after to"}}
	case to.Sub(from) > MaxQueryRange:
		return from, to, []domain.FieldError{{Field: "to", Message: fmt.Sprintf("the range must not exceed %d days", int(MaxQueryRange.Hours()/24))}}
	}
	return from, to, nil
}

// A cursor is base64url("<occurred_at in Unix microseconds>.<id>"). It is opaque to clients.
func encodeCursor(c ports.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.OccurredAt.UnixMicro(), 10) + "." + strconv.FormatInt(c.ID, 10)))
}

func decodeCursor(s string) (ports.Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ports.Cursor{}, err
	}
	micros, id, ok := strings.Cut(string(raw), ".")
	if !ok {
		return ports.Cursor{}, fmt.Errorf("malformed cursor")
	}
	us, err := strconv.ParseInt(micros, 10, 64)
	if err != nil {
		return ports.Cursor{}, err
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 {
		return ports.Cursor{}, fmt.Errorf("malformed cursor id")
	}
	return ports.Cursor{OccurredAt: time.UnixMicro(us).UTC(), ID: n}, nil
}
