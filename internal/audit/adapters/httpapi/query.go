package httpapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
	"github.com/medinetcore/aud/internal/jwtauth"
)

const queryTag = "Query"

// eventView is a stored event as the query API returns it.
type eventView struct {
	ID             int64          `json:"id" doc:"Position of the event in the hash chain (audit_logs.id)." example:"1042"`
	EventID        string         `json:"event_id" format:"uuid" doc:"Identifier assigned by the emitter." example:"0b0e5f8e-6a4c-4f7e-9d3a-2f1c8b7a6e5d"`
	ClientID       string         `json:"client_id" doc:"Ingest client that sent the event." example:"iam-service"`
	SourceModule   string         `json:"source_module" doc:"Emitting module." example:"IAM"`
	EventType      string         `json:"event_type" doc:"Type from the event catalog." example:"auth.login_failed"`
	Severity       string         `json:"severity" enum:"INFO,LOW,MEDIUM,HIGH,CRITICAL" example:"MEDIUM"`
	ActorID        string         `json:"actor_id,omitempty" example:"user-77"`
	ActorType      string         `json:"actor_type,omitempty" enum:"user,service,anonymous" example:"user"`
	TargetResource string         `json:"target_resource,omitempty" example:"session/abc"`
	SourceIP       string         `json:"source_ip,omitempty" example:"10.1.2.3"`
	UserAgent      string         `json:"user_agent,omitempty" example:"Mozilla/5.0"`
	OccurredAt     time.Time      `json:"occurred_at" doc:"When the event happened, according to the emitter (UTC)."`
	ReceivedAt     time.Time      `json:"received_at" doc:"When AUD accepted the event (UTC)."`
	Payload        map[string]any `json:"payload" doc:"Event details sent by the emitter."`
	PrevHash       string         `json:"prev_hash" doc:"Hash of the previous event in the chain (hex)." example:"9f2c…"`
	Hash           string         `json:"hash" doc:"SHA-256 of prev_hash and the canonical event (hex)." example:"4b1a…"`
}

func newEventView(e ports.StoredEvent) (eventView, error) {
	// UseNumber keeps payload numbers exactly as stored, even beyond float64 precision.
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(e.Payload))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return eventView{}, err
	}
	return eventView{
		ID:             e.ID,
		EventID:        e.EventID,
		ClientID:       e.ClientID,
		SourceModule:   e.SourceModule,
		EventType:      e.EventType,
		Severity:       e.Severity.String(),
		ActorID:        e.ActorID,
		ActorType:      e.ActorType,
		TargetResource: e.TargetResource,
		SourceIP:       e.SourceIP,
		UserAgent:      e.UserAgent,
		OccurredAt:     e.OccurredAt.UTC(),
		ReceivedAt:     e.ReceivedAt.UTC(),
		Payload:        payload,
		PrevHash:       hex.EncodeToString(e.PrevHash[:]),
		Hash:           hex.EncodeToString(e.Hash[:]),
	}, nil
}

// queryOperation describes a GET operation of the query API, protected by a bearer token
// holding one of roles.
func queryOperation(id, path, summary, description string, roles []string, errs ...int) huma.Operation {
	return huma.Operation{
		OperationID: id,
		Method:      http.MethodGet,
		Path:        path,
		Summary:     summary,
		Description: description + "\n\nRequired role: " + strings.Join(roles, " or ") + ".",
		Tags:        []string{queryTag},
		Security:    []map[string][]string{{bearerScheme: {}}},
		Metadata:    map[string]any{metaRoles: roles},
		Errors:      append([]int{http.StatusUnauthorized, http.StatusForbidden}, errs...),
	}
}

var readerRoles = []string{jwtauth.RoleAuditor, jwtauth.RoleAdmin}

type getEventInput struct {
	ID string `path:"id" pattern:"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" doc:"event_id of the event (UUID)." example:"0b0e5f8e-6a4c-4f7e-9d3a-2f1c8b7a6e5d"`
}

type getEventOutput struct {
	Body eventView
}

// eventTypeParam and sourceModuleParam publish the catalogs as enums, so the documentation
// lists them and huma rejects anything else with 400.
type (
	eventTypeParam    string
	sourceModuleParam string
)

func (eventTypeParam) Schema(huma.Registry) *huma.Schema {
	return stringEnum(domain.EventTypes(), "Event type from the catalog (contract §2).")
}

func (sourceModuleParam) Schema(huma.Registry) *huma.Schema {
	return stringEnum(domain.SourceModules(), "Emitting module code.")
}

func stringEnum(values []string, doc string) *huma.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = v
	}
	return &huma.Schema{Type: huma.TypeString, Enum: enum, Description: doc}
}

type listEventsInput struct {
	EventType    eventTypeParam    `query:"event_type"`
	Severity     string            `query:"severity" enum:"INFO,LOW,MEDIUM,HIGH,CRITICAL" doc:"Exact severity."`
	SourceModule sourceModuleParam `query:"source_module"`
	ActorID      string            `query:"actor_id" maxLength:"128" doc:"Exact actor_id." example:"user-77"`
	From         time.Time         `query:"from" doc:"Start of the range on occurred_at, inclusive (RFC 3339). Default: to minus 7 days." example:"2026-10-20T00:00:00Z"`
	To           time.Time         `query:"to" doc:"End of the range on occurred_at, inclusive (RFC 3339). Default: now. The range may span at most 31 days." example:"2026-10-25T23:59:59Z"`
	Cursor       string            `query:"cursor" maxLength:"64" doc:"next_cursor of the previous page."`
	Limit        int               `query:"limit" minimum:"1" maximum:"100" default:"50" doc:"Events per page."`
}

type eventListBody struct {
	Items      []eventView `json:"items" doc:"Events, newest first (occurred_at, then id, descending)."`
	NextCursor string      `json:"next_cursor,omitempty" doc:"Pass it as cursor to get the next page. Absent on the last page."`
}

type listEventsOutput struct {
	Body eventListBody
}

type statsInput struct {
	From time.Time `query:"from" doc:"Start of the range on occurred_at, inclusive (RFC 3339). Default: to minus 7 days." example:"2026-10-25T00:00:00Z"`
	To   time.Time `query:"to" doc:"End of the range on occurred_at, inclusive (RFC 3339). Default: now. The range may span at most 31 days." example:"2026-10-25T23:59:59Z"`
}

type hourCount struct {
	Hour  time.Time `json:"hour" doc:"Start of the UTC hour." example:"2026-10-25T10:00:00Z"`
	Count int64     `json:"count" example:"3"`
}

type actorCount struct {
	ActorID string `json:"actor_id,omitempty" doc:"Absent for denied accesses without an actor." example:"user-77"`
	Count   int64  `json:"count" example:"5"`
}

type ipCount struct {
	SourceIP string `json:"source_ip" example:"203.0.113.5"`
	Count    int64  `json:"count" example:"4"`
}

type statsBody struct {
	From                time.Time    `json:"from" doc:"Start of the range actually used."`
	To                  time.Time    `json:"to" doc:"End of the range actually used."`
	FailedLoginsPerHour []hourCount  `json:"failed_logins_per_hour" doc:"auth.login_failed events per UTC hour, oldest first. Hours without events are omitted."`
	DeniedByActor       []actorCount `json:"denied_by_actor" doc:"access.denied events per actor, most first (top 10)."`
	TopIPs              []ipCount    `json:"top_ips_high_critical" doc:"Source IPs with the most HIGH or CRITICAL events, most first (top 10)."`
}

type statsOutput struct {
	Body statsBody
}

func newStatsBody(r application.StatsReport) statsBody {
	b := statsBody{
		From:                r.From.UTC(),
		To:                  r.To.UTC(),
		FailedLoginsPerHour: make([]hourCount, len(r.FailedLoginsPerHour)),
		DeniedByActor:       make([]actorCount, len(r.DeniedByActor)),
		TopIPs:              make([]ipCount, len(r.TopIPs)),
	}
	for i, h := range r.FailedLoginsPerHour {
		b.FailedLoginsPerHour[i] = hourCount{Hour: h.Hour.UTC(), Count: h.Count}
	}
	for i, a := range r.DeniedByActor {
		b.DeniedByActor[i] = actorCount(a)
	}
	for i, ip := range r.TopIPs {
		b.TopIPs[i] = ipCount{SourceIP: ip.IP, Count: ip.Count}
	}
	return b
}

type verifyInput struct {
	FromID int64 `query:"from_id" minimum:"1" doc:"First id of the range (audit_logs.id). Default: the first event." example:"1"`
	ToID   int64 `query:"to_id" minimum:"1" doc:"Last id of the range. Default: the last event." example:"5000"`
}

type verifyBody struct {
	Status        string `json:"status" enum:"ok,broken" doc:"ok when every link and hash in the range matches."`
	Checked       int64  `json:"checked" doc:"Rows verified, including the broken one."`
	FromID        int64  `json:"from_id" doc:"First id of the range actually used."`
	ToID          int64  `json:"to_id,omitempty" doc:"Last id of the range, when one was given."`
	FirstBrokenID int64  `json:"first_broken_id,omitempty" doc:"First row whose prev_hash or hash does not match. Only when broken."`
	LastID        int64  `json:"last_id,omitempty" doc:"Last row verified. Only when ok and the range is not empty."`
	LastHash      string `json:"last_hash,omitempty" doc:"Hash of last_id (hex). Keeping it outside AUD lets a later check prove that rows up to last_id were not rewritten."`
}

type verifyOutput struct {
	Body verifyBody
}

func newVerifyBody(r application.VerifyReport) verifyBody {
	b := verifyBody{Status: "ok", Checked: r.Checked, FromID: r.FromID, ToID: r.ToID}
	switch {
	case !r.OK:
		b.Status, b.FirstBrokenID = "broken", r.FirstBrokenID
	case r.LastID > 0:
		b.LastID, b.LastHash = r.LastID, hex.EncodeToString(r.LastHash[:])
	}
	return b
}

// validationProblem turns a use case validation error into a 400 naming each query parameter.
func validationProblem(err *domain.ValidationError) huma.StatusError {
	details := make([]error, len(err.Fields))
	for i, f := range err.Fields {
		details[i] = &huma.ErrorDetail{Location: "query." + f.Field, Message: f.Message}
	}
	return huma.Error400BadRequest("invalid query parameters", details...)
}

// registerQuery registers the query operations. Every one needs a bearer token.
func registerQuery(api huma.API, tokens *jwtauth.Verifier, q *application.Query) {
	auth := huma.Middlewares{requireRoles(api, tokens)}

	op := queryOperation("getEvent", "/api/v1/events/{id}", "Get one event",
		"Returns one stored event by its `event_id`.", readerRoles, http.StatusBadRequest, http.StatusNotFound)
	op.Middlewares = auth
	huma.Register(api, op, func(ctx context.Context, in *getEventInput) (*getEventOutput, error) {
		ev, err := q.FindEvent(ctx, strings.ToLower(in.ID))
		if errors.Is(err, ports.ErrEventNotFound) {
			return nil, huma.Error404NotFound("event not found")
		}
		if err != nil {
			return nil, huma.Error500InternalServerError("", err)
		}
		view, err := newEventView(ev)
		if err != nil {
			return nil, huma.Error500InternalServerError("", err)
		}
		return &getEventOutput{Body: view}, nil
	})

	op = queryOperation("listEvents", "/api/v1/events", "List events",
		"Lists stored events, newest first, with optional filters. Pagination is keyset based: "+
			"follow next_cursor until it is absent. Without from and to, the last 7 days are listed.",
		readerRoles, http.StatusBadRequest)
	op.Middlewares = auth
	huma.Register(api, op, func(ctx context.Context, in *listEventsInput) (*listEventsOutput, error) {
		page, err := q.ListEvents(ctx, application.ListRequest{
			EventType:    string(in.EventType),
			SourceModule: string(in.SourceModule),
			ActorID:      in.ActorID,
			Severity:     in.Severity,
			From:         in.From,
			To:           in.To,
			Cursor:       in.Cursor,
			Limit:        in.Limit,
		})
		var verr *domain.ValidationError
		if errors.As(err, &verr) {
			return nil, validationProblem(verr)
		}
		if err != nil {
			return nil, huma.Error500InternalServerError("", err)
		}
		body := eventListBody{Items: make([]eventView, len(page.Events)), NextCursor: page.NextCursor}
		for i, e := range page.Events {
			if body.Items[i], err = newEventView(e); err != nil {
				return nil, huma.Error500InternalServerError("", err)
			}
		}
		return &listEventsOutput{Body: body}, nil
	})

	op = queryOperation("getSuspiciousStats", "/api/v1/stats/suspicious", "Suspicious activity report",
		"Counts failed logins per hour, denied accesses per actor and the source IPs with the most "+
			"HIGH or CRITICAL events within a range. Without from and to, the last 7 days are used.",
		readerRoles, http.StatusBadRequest)
	op.Middlewares = auth
	huma.Register(api, op, func(ctx context.Context, in *statsInput) (*statsOutput, error) {
		report, err := q.SuspiciousStats(ctx, application.StatsRequest{From: in.From, To: in.To})
		var verr *domain.ValidationError
		if errors.As(err, &verr) {
			return nil, validationProblem(verr)
		}
		if err != nil {
			return nil, huma.Error500InternalServerError("", err)
		}
		return &statsOutput{Body: newStatsBody(report)}, nil
	})

	op = queryOperation("verifyIntegrity", "/api/v1/integrity/verify", "Verify the hash chain",
		"Walks the hash chain over an id range and returns ok, or the first id where it breaks. "+
			"A row breaks the chain when its stored columns no longer produce its hash, or when its "+
			"prev_hash is not the hash of the previous stored row (an altered or deleted row).",
		[]string{jwtauth.RoleAdmin}, http.StatusBadRequest)
	op.Middlewares = auth
	huma.Register(api, op, func(ctx context.Context, in *verifyInput) (*verifyOutput, error) {
		report, err := q.VerifyChain(ctx, application.VerifyRequest{FromID: in.FromID, ToID: in.ToID})
		var verr *domain.ValidationError
		if errors.As(err, &verr) {
			return nil, validationProblem(verr)
		}
		if err != nil {
			return nil, huma.Error500InternalServerError("", err)
		}
		return &verifyOutput{Body: newVerifyBody(report)}, nil
	})
}
