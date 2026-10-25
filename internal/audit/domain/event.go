package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits of the ingest contract v1.0 (§1).
const (
	// FutureTolerance is how far occurred_at may be ahead of the AUD clock.
	FutureTolerance = 5 * time.Minute
	// MaxPayloadBytes is the maximum size of the serialized payload.
	MaxPayloadBytes = 16 * 1024
	// MaxPayloadDepth bounds payload nesting so the database JSON parser never hits its stack limit.
	MaxPayloadDepth = 32

	maxActorIDChars        = 128
	maxTargetResourceChars = 256
	maxUserAgentChars      = 512
)

var (
	uuidPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	targetResourcePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*/.+$`)
)

// EventInput is an event exactly as an emitter sent it, before validation.
// Empty strings mean the field was not sent.
type EventInput struct {
	EventID        string
	SourceModule   string
	EventType      string
	Severity       string
	OccurredAt     string
	ActorID        string
	ActorType      string
	TargetResource string
	SourceIP       string
	UserAgent      string
	Payload        json.RawMessage
}

// Event is a validated security event. Optional fields are empty when absent.
type Event struct {
	EventID        string
	SourceModule   string
	EventType      string
	Severity       Severity
	OccurredAt     time.Time // UTC, microsecond precision (as stored by timestamptz)
	ActorID        string
	ActorType      string
	TargetResource string
	SourceIP       string // canonical text form
	UserAgent      string
	Payload        json.RawMessage // compact JSON object with sorted keys
}

// FieldError describes why one field is invalid.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError lists every invalid field of an event.
type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Field + ": " + f.Message
	}
	return "invalid event: " + strings.Join(parts, "; ")
}

// NewEvent validates in against the ingest contract and returns the normalized event.
// now is the AUD clock, used for the future tolerance of occurred_at.
func NewEvent(in EventInput, now time.Time) (Event, error) {
	var errs []FieldError
	fail := func(field, msg string) { errs = append(errs, FieldError{Field: field, Message: msg}) }

	e := Event{
		EventID:        in.EventID,
		SourceModule:   in.SourceModule,
		EventType:      in.EventType,
		ActorID:        in.ActorID,
		ActorType:      in.ActorType,
		TargetResource: in.TargetResource,
		UserAgent:      in.UserAgent,
	}

	switch {
	case in.EventID == "":
		fail("event_id", "is required")
	case !uuidPattern.MatchString(in.EventID):
		fail("event_id", "must be a canonical lowercase UUID")
	}

	switch {
	case in.SourceModule == "":
		fail("source_module", "is required")
	case !slices.Contains(sourceModules, in.SourceModule):
		fail("source_module", "must be one of "+strings.Join(sourceModules, ", "))
	}

	switch {
	case in.EventType == "":
		fail("event_type", "is required")
	case !slices.Contains(eventTypes, in.EventType):
		fail("event_type", "is not in the event catalog")
	}

	if in.Severity == "" {
		fail("severity", "is required")
	} else if s, err := ParseSeverity(in.Severity); err != nil {
		fail("severity", "must be one of "+strings.Join(severityNames[:], ", "))
	} else {
		e.Severity = s
	}

	if in.OccurredAt == "" {
		fail("occurred_at", "is required")
	} else if t, err := time.Parse(time.RFC3339Nano, in.OccurredAt); err != nil {
		fail("occurred_at", "must be an RFC 3339 date-time with time zone")
	} else if t.After(now.Add(FutureTolerance)) {
		fail("occurred_at", "must not be more than 5 minutes in the future")
	} else {
		e.OccurredAt = t.UTC().Truncate(time.Microsecond)
	}

	if msg := checkText(in.ActorID, maxActorIDChars); msg != "" {
		fail("actor_id", msg)
	}
	switch {
	case in.ActorType == "" && in.ActorID != "":
		fail("actor_type", "is required when actor_id is present")
	case in.ActorType != "" && !slices.Contains(actorTypes, in.ActorType):
		fail("actor_type", "must be one of "+strings.Join(actorTypes, ", "))
	}

	if msg := checkText(in.TargetResource, maxTargetResourceChars); msg != "" {
		fail("target_resource", msg)
	} else if in.TargetResource != "" && !targetResourcePattern.MatchString(in.TargetResource) {
		fail("target_resource", "must have the form <type>/<id>")
	}

	if in.SourceIP != "" {
		ip, err := netip.ParseAddr(in.SourceIP)
		if err != nil || ip.Zone() != "" {
			fail("source_ip", "must be an IPv4 or IPv6 address")
		} else {
			e.SourceIP = ip.String()
		}
	}

	if msg := checkText(in.UserAgent, maxUserAgentChars); msg != "" {
		fail("user_agent", msg)
	}

	if p, msg := normalizePayload(in.Payload); msg != "" {
		fail("payload", msg)
	} else {
		e.Payload = p
	}

	if len(errs) > 0 {
		return Event{}, &ValidationError{Fields: errs}
	}
	return e, nil
}

// checkText validates an optional free-text field; it returns an error message or "".
func checkText(s string, maxChars int) string {
	switch {
	case utf8.RuneCountInString(s) > maxChars:
		return fmt.Sprintf("must be at most %d characters", maxChars)
	case strings.ContainsRune(s, 0):
		return "must not contain NUL characters"
	}
	return ""
}

// normalizePayload returns the payload as compact JSON with sorted keys and numbers kept verbatim.
func normalizePayload(raw json.RawMessage) (json.RawMessage, string) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("{}"), ""
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, "must be valid JSON"
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, "must be a single JSON object"
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, "must be a JSON object"
	}
	if msg := checkPayloadValue(v, 1); msg != "" {
		return nil, msg
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, "must be valid JSON"
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(out) > MaxPayloadBytes {
		return nil, fmt.Sprintf("must be at most %d bytes serialized", MaxPayloadBytes)
	}
	return out, ""
}

// checkPayloadValue rejects what PostgreSQL jsonb cannot store: NUL characters, numbers
// outside the float64 range and very deep nesting.
func checkPayloadValue(v any, depth int) string {
	if depth > MaxPayloadDepth {
		return fmt.Sprintf("must not be nested more than %d levels", MaxPayloadDepth)
	}
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if strings.ContainsRune(k, 0) {
				return "must not contain NUL characters"
			}
			if msg := checkPayloadValue(child, depth+1); msg != "" {
				return msg
			}
		}
	case []any:
		for _, child := range v {
			if msg := checkPayloadValue(child, depth+1); msg != "" {
				return msg
			}
		}
	case string:
		if strings.ContainsRune(v, 0) {
			return "must not contain NUL characters"
		}
	case json.Number:
		if _, err := strconv.ParseFloat(v.String(), 64); err != nil {
			return "contains a number out of range"
		}
	}
	return ""
}
