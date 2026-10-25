package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

// Limits of the ingest contract §1.
const (
	maxEventBody   = 64 * 1024   // POST /events
	maxBatchBody   = 1024 * 1024 // POST /events/batch
	maxBatchEvents = 100
)

// Retry-After values, in seconds.
const (
	retryAfterFull     = "1"
	retryAfterShutdown = "5"
)

// eventBody is the JSON shape of one event (contract §1).
type eventBody struct {
	EventID        string          `json:"event_id"`
	SourceModule   string          `json:"source_module"`
	EventType      string          `json:"event_type"`
	Severity       string          `json:"severity"`
	OccurredAt     string          `json:"occurred_at"`
	ActorID        string          `json:"actor_id"`
	ActorType      string          `json:"actor_type"`
	TargetResource string          `json:"target_resource"`
	SourceIP       string          `json:"source_ip"`
	UserAgent      string          `json:"user_agent"`
	Payload        json.RawMessage `json:"payload"`
}

func (b eventBody) input() domain.EventInput {
	return domain.EventInput(b)
}

type batchBody struct {
	Events []json.RawMessage `json:"events"`
}

func ingestEvent(svc *application.Ingest) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isJSON(r) {
			writeProblem(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		var body eventBody
		if fe, err := decodeStrict(r.Body, &body); err != nil {
			writeDecodeError(w, fe, err)
			return
		}
		if !submit(w, r, svc, []domain.EventInput{body.input()}, false) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "event_id": body.EventID})
	}
}

func ingestBatch(svc *application.Ingest) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isJSON(r) {
			writeProblem(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		var batch batchBody
		if fe, err := decodeStrict(r.Body, &batch); err != nil {
			writeDecodeError(w, fe, err)
			return
		}
		if n := len(batch.Events); n < 1 || n > maxBatchEvents {
			writeProblem(w, http.StatusBadRequest, "event validation failed", domain.FieldError{
				Field: "events", Message: fmt.Sprintf("must contain between 1 and %d events", maxBatchEvents),
			})
			return
		}

		inputs := make([]domain.EventInput, len(batch.Events))
		for i, raw := range batch.Events {
			var body eventBody
			fe, err := decodeStrict(bytes.NewReader(raw), &body)
			if err != nil {
				if fe == nil {
					fe = &domain.FieldError{Message: "must be a JSON object"}
				}
				fe.Field = strings.TrimSuffix(fmt.Sprintf("events[%d].%s", i, fe.Field), ".")
				writeProblem(w, http.StatusBadRequest, "event validation failed", *fe)
				return
			}
			inputs[i] = body.input()
		}
		if !submit(w, r, svc, inputs, true) {
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "count": len(inputs)})
	}
}

// submit hands the events to the use case and writes the error response, if any.
func submit(w http.ResponseWriter, r *http.Request, svc *application.Ingest, inputs []domain.EventInput, batch bool) bool {
	client, ok := clientFrom(r.Context())
	if !ok {
		writeProblem(w, http.StatusUnauthorized, unauthorizedDetail)
		return false
	}
	err := svc.Submit(client, inputs, batch)
	var verr *domain.ValidationError
	switch {
	case err == nil:
		return true
	case errors.As(err, &verr):
		writeProblem(w, http.StatusBadRequest, "event validation failed", verr.Fields...)
	case errors.Is(err, application.ErrModuleMismatch):
		writeProblem(w, http.StatusForbidden, application.ErrModuleMismatch.Error())
	case errors.Is(err, ports.ErrQueueFull):
		w.Header().Set("Retry-After", retryAfterFull)
		writeProblem(w, http.StatusServiceUnavailable, "event queue is full")
	case errors.Is(err, ports.ErrQueueClosed):
		w.Header().Set("Retry-After", retryAfterShutdown)
		writeProblem(w, http.StatusServiceUnavailable, "service is shutting down")
	default:
		slog.ErrorContext(r.Context(), "ingest failed", "client_id", client.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
	}
	return false
}

func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// decodeStrict decodes exactly one JSON value into v, rejecting unknown fields. On failure it
// returns the offending field when it can tell which one it was.
func decodeStrict(r io.Reader, v any) (*domain.FieldError, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			if typeErr.Field == "" {
				return nil, err
			}
			return &domain.FieldError{Field: typeErr.Field, Message: wrongTypeMessage(typeErr.Type.Kind())}, err
		}
		if name, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			return &domain.FieldError{Field: strings.Trim(name, `"`), Message: "is not allowed"}, err
		}
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return nil, nil
}

func wrongTypeMessage(k reflect.Kind) string {
	switch k {
	case reflect.String:
		return "must be a string"
	case reflect.Slice:
		return "must be an array"
	default:
		return "has the wrong type"
	}
}

func writeDecodeError(w http.ResponseWriter, fe *domain.FieldError, err error) {
	if fe != nil {
		writeProblem(w, http.StatusBadRequest, "event validation failed", *fe)
		return
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeProblem(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	writeProblem(w, http.StatusBadRequest, "request body must be one valid JSON object")
}
