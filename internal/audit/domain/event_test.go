package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 25, 14, 10, 0, 0, time.UTC)

func validInput() EventInput {
	return EventInput{
		EventID:        "0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e8f",
		SourceModule:   "IAM",
		EventType:      "auth.login_failed",
		Severity:       "LOW",
		OccurredAt:     "2026-10-25T14:03:11Z",
		ActorID:        "user-1042",
		ActorType:      "user",
		TargetResource: "patient/8812",
		SourceIP:       "203.0.113.24",
		UserAgent:      "Mozilla/5.0",
		Payload:        []byte(`{"reason":"invalid_password","attempt":3}`),
	}
}

func TestNewEventAcceptsValidInput(t *testing.T) {
	e, err := NewEvent(validInput(), testNow)
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}
	if e.Severity != SeverityLow {
		t.Errorf("Severity = %v, want LOW", e.Severity)
	}
	if want := time.Date(2026, 10, 25, 14, 3, 11, 0, time.UTC); !e.OccurredAt.Equal(want) {
		t.Errorf("OccurredAt = %v, want %v", e.OccurredAt, want)
	}
	if got := string(e.Payload); got != `{"attempt":3,"reason":"invalid_password"}` {
		t.Errorf("Payload = %s, want keys sorted and compact", got)
	}
}

func TestNewEventNormalizes(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*EventInput)
		check func(*testing.T, Event)
	}{
		{"missing payload becomes empty object", func(in *EventInput) { in.Payload = nil }, func(t *testing.T, e Event) {
			if string(e.Payload) != "{}" {
				t.Errorf("Payload = %s, want {}", e.Payload)
			}
		}},
		{"payload numbers keep their text", func(in *EventInput) { in.Payload = []byte(`{"n": 12345678901234567890, "f": 1.50}`) }, func(t *testing.T, e Event) {
			if string(e.Payload) != `{"f":1.50,"n":12345678901234567890}` {
				t.Errorf("Payload = %s", e.Payload)
			}
		}},
		{"occurred_at with offset is stored in UTC", func(in *EventInput) { in.OccurredAt = "2026-10-25T11:03:11-03:00" }, func(t *testing.T, e Event) {
			if e.OccurredAt.Location() != time.UTC || e.OccurredAt.Hour() != 14 {
				t.Errorf("OccurredAt = %v, want 14:03:11 UTC", e.OccurredAt)
			}
		}},
		{"occurred_at is truncated to microseconds", func(in *EventInput) { in.OccurredAt = "2026-10-25T14:03:11.123456789Z" }, func(t *testing.T, e Event) {
			if e.OccurredAt.Nanosecond() != 123456000 {
				t.Errorf("Nanosecond = %d, want 123456000", e.OccurredAt.Nanosecond())
			}
		}},
		{"ipv6 is written in canonical form", func(in *EventInput) { in.SourceIP = "2001:DB8:0:0:0:0:0:1" }, func(t *testing.T, e Event) {
			if e.SourceIP != "2001:db8::1" {
				t.Errorf("SourceIP = %q, want 2001:db8::1", e.SourceIP)
			}
		}},
		{"anonymous actor without actor_id", func(in *EventInput) { in.ActorID = ""; in.ActorType = "anonymous" }, func(t *testing.T, e Event) {
			if e.ActorType != "anonymous" || e.ActorID != "" {
				t.Errorf("actor = %q/%q", e.ActorID, e.ActorType)
			}
		}},
		{"occurred_at exactly at the future tolerance", func(in *EventInput) { in.OccurredAt = testNow.Add(FutureTolerance).Format(time.RFC3339) }, func(*testing.T, Event) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInput()
			tt.edit(&in)
			e, err := NewEvent(in, testNow)
			if err != nil {
				t.Fatalf("NewEvent: %v", err)
			}
			tt.check(t, e)
		})
	}
}

func TestNewEventRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*EventInput)
		field string
	}{
		{"missing event_id", func(in *EventInput) { in.EventID = "" }, "event_id"},
		{"event_id not a uuid", func(in *EventInput) { in.EventID = "not-a-uuid" }, "event_id"},
		{"event_id in uppercase", func(in *EventInput) { in.EventID = "0192F3A4-7B1C-7D2E-9F10-3A4B5C6D7E8F" }, "event_id"},
		{"missing source_module", func(in *EventInput) { in.SourceModule = "" }, "source_module"},
		{"source_module outside the whitelist", func(in *EventInput) { in.SourceModule = "XYZ" }, "source_module"},
		{"source_module in lowercase", func(in *EventInput) { in.SourceModule = "iam" }, "source_module"},
		{"missing event_type", func(in *EventInput) { in.EventType = "" }, "event_type"},
		{"event_type outside the catalog", func(in *EventInput) { in.EventType = "auth.teleported" }, "event_type"},
		{"missing severity", func(in *EventInput) { in.Severity = "" }, "severity"},
		{"severity out of range", func(in *EventInput) { in.Severity = "SEVERE" }, "severity"},
		{"severity in lowercase", func(in *EventInput) { in.Severity = "low" }, "severity"},
		{"missing occurred_at", func(in *EventInput) { in.OccurredAt = "" }, "occurred_at"},
		{"occurred_at without time zone", func(in *EventInput) { in.OccurredAt = "2026-10-25T14:03:11" }, "occurred_at"},
		{"occurred_at not a date", func(in *EventInput) { in.OccurredAt = "yesterday" }, "occurred_at"},
		{"occurred_at beyond the future tolerance", func(in *EventInput) {
			in.OccurredAt = testNow.Add(FutureTolerance + time.Second).Format(time.RFC3339)
		}, "occurred_at"},
		{"actor_id without actor_type", func(in *EventInput) { in.ActorType = "" }, "actor_type"},
		{"actor_type outside the enum", func(in *EventInput) { in.ActorType = "robot" }, "actor_type"},
		{"actor_id too long", func(in *EventInput) { in.ActorID = strings.Repeat("a", 129) }, "actor_id"},
		{"actor_id with NUL byte", func(in *EventInput) { in.ActorID = "user\x00" }, "actor_id"},
		{"target_resource without type prefix", func(in *EventInput) { in.TargetResource = "8812" }, "target_resource"},
		{"target_resource too long", func(in *EventInput) { in.TargetResource = "patient/" + strings.Repeat("9", 249) }, "target_resource"},
		{"source_ip not an address", func(in *EventInput) { in.SourceIP = "999.1.1.1" }, "source_ip"},
		{"source_ip with zone", func(in *EventInput) { in.SourceIP = "fe80::1%eth0" }, "source_ip"},
		{"user_agent too long", func(in *EventInput) { in.UserAgent = strings.Repeat("u", 513) }, "user_agent"},
		{"payload is an array", func(in *EventInput) { in.Payload = []byte(`[1,2]`) }, "payload"},
		{"payload is a scalar", func(in *EventInput) { in.Payload = []byte(`"x"`) }, "payload"},
		{"payload is null", func(in *EventInput) { in.Payload = []byte(`null`) }, "payload"},
		{"payload over 16 KiB", func(in *EventInput) {
			in.Payload = []byte(`{"k":"` + strings.Repeat("x", MaxPayloadBytes) + `"}`)
		}, "payload"},
		{"payload with NUL character", func(in *EventInput) { in.Payload = []byte(`{"k":"a\u0000b"}`) }, "payload"},
		{"payload number out of range", func(in *EventInput) { in.Payload = []byte(`{"n":1e999}`) }, "payload"},
		// PostgreSQL numeric keeps at most 16383 decimal places; ParseFloat silently underflows to 0.
		{"payload number below the numeric scale", func(in *EventInput) { in.Payload = []byte(`{"n":1e-20000}`) }, "payload"},
		{"payload number one digit past the numeric scale", func(in *EventInput) { in.Payload = []byte(`{"n":1.5e-16383}`) }, "payload"},
		{"payload number with an exponent that overflows int", func(in *EventInput) { in.Payload = []byte(`{"n":1e-99999999999999999999}`) }, "payload"},
		{"payload number with the most negative int64 exponent", func(in *EventInput) { in.Payload = []byte(`{"n":1e-9223372036854775808}`) }, "payload"},
		{"payload nested too deep", func(in *EventInput) {
			in.Payload = []byte(`{"k":` + strings.Repeat("[", MaxPayloadDepth) + strings.Repeat("]", MaxPayloadDepth) + `}`)
		}, "payload"},
		{"payload with trailing data", func(in *EventInput) { in.Payload = []byte(`{} {}`) }, "payload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInput()
			tt.edit(&in)
			_, err := NewEvent(in, testNow)
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("err = %v, want *ValidationError", err)
			}
			if len(verr.Fields) != 1 || verr.Fields[0].Field != tt.field {
				t.Fatalf("fields = %+v, want exactly one error on %q", verr.Fields, tt.field)
			}
			if verr.Fields[0].Message == "" {
				t.Error("field error has an empty message")
			}
		})
	}
}

func TestNewEventReportsEveryInvalidField(t *testing.T) {
	in := validInput()
	in.Severity = "x"
	in.EventType = "x"
	_, err := NewEvent(in, testNow)
	var verr *ValidationError
	if !errors.As(err, &verr) || len(verr.Fields) != 2 {
		t.Fatalf("err = %v, want two field errors", err)
	}
}

func TestPayloadAtTheSizeLimitIsAccepted(t *testing.T) {
	in := validInput()
	// {"k":"..."} has 8 bytes of structure.
	in.Payload = []byte(`{"k":"` + strings.Repeat("x", MaxPayloadBytes-8) + `"}`)
	if _, err := NewEvent(in, testNow); err != nil {
		t.Fatalf("NewEvent: %v", err)
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, name := range []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		s, err := ParseSeverity(name)
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", name, err)
		}
		if s.String() != name {
			t.Errorf("String() = %q, want %q", s.String(), name)
		}
	}
}

func TestCatalogMatchesContract(t *testing.T) {
	if got := len(EventTypes()); got != 22 {
		t.Errorf("catalog has %d event types, contract v1.0 lists 22", got)
	}
	if got := len(SourceModules()); got != 12 {
		t.Errorf("whitelist has %d modules, contract v1.0 lists 12", got)
	}
}
