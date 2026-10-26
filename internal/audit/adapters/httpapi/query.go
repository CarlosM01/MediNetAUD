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
}
