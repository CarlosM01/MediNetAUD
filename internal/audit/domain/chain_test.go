package domain

import (
	"encoding/hex"
	"testing"
	"time"
)

func testRecord(t *testing.T) Record {
	t.Helper()
	e, err := NewEvent(validInput(), testNow)
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}
	return Record{Event: e, ClientID: "iam-service", ReceivedAt: testNow}
}

func TestComputeHashChangesWhenAnyFieldChanges(t *testing.T) {
	base := testRecord(t)
	baseHash := ComputeHash(GenesisHash, base)

	tests := []struct {
		name string
		edit func(*Record)
	}{
		{"event_id", func(r *Record) { r.EventID = "0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e90" }},
		{"client_id", func(r *Record) { r.ClientID = "iam-service-2" }},
		{"source_module", func(r *Record) { r.SourceModule = "PAC" }},
		{"event_type", func(r *Record) { r.EventType = "auth.logout" }},
		{"severity", func(r *Record) { r.Severity = SeverityHigh }},
		{"actor_id", func(r *Record) { r.ActorID = "user-1043" }},
		{"actor_type", func(r *Record) { r.ActorType = "service" }},
		{"target_resource", func(r *Record) { r.TargetResource = "patient/8813" }},
		{"source_ip", func(r *Record) { r.SourceIP = "203.0.113.25" }},
		{"user_agent", func(r *Record) { r.UserAgent = "curl/8.0" }},
		{"occurred_at", func(r *Record) { r.OccurredAt = r.OccurredAt.Add(time.Microsecond) }},
		{"received_at", func(r *Record) { r.ReceivedAt = r.ReceivedAt.Add(time.Microsecond) }},
		{"payload", func(r *Record) { r.Payload = []byte(`{"attempt":4,"reason":"invalid_password"}`) }},
		{"optional field removed", func(r *Record) { r.UserAgent = "" }},
		{"bytes moved between adjacent fields", func(r *Record) { r.ActorID = "user-1042u"; r.ActorType = "ser" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			tt.edit(&r)
			if ComputeHash(GenesisHash, r) == baseHash {
				t.Fatal("hash did not change")
			}
		})
	}

	t.Run("prev_hash", func(t *testing.T) {
		var prev Hash
		prev[0] = 1
		if ComputeHash(prev, base) == baseHash {
			t.Fatal("hash did not change")
		}
	})
}

func TestComputeHashIgnoresTimeZoneAndSubMicrosecondNoise(t *testing.T) {
	r := testRecord(t)
	want := ComputeHash(GenesisHash, r)

	santiago := time.FixedZone("CLT", -3*3600)
	r.OccurredAt = r.OccurredAt.In(santiago)
	r.ReceivedAt = r.ReceivedAt.In(santiago).Add(999 * time.Nanosecond)
	if got := ComputeHash(GenesisHash, r); got != want {
		t.Fatalf("hash depends on the time zone or on nanoseconds the database cannot store")
	}
}

// The canonical serialization is a persisted format: /integrity/verify recomputes old hashes,
// so this known answer must never change.
func TestComputeHashKnownAnswer(t *testing.T) {
	r := sealed(testRecord(t))
	const want = "738fbe1b6d98eb3aca76732f3ae1ab683c78a753c293ef3d28e91ccb2f05ac24"
	if got := hex.EncodeToString(r.Hash[:]); got != want {
		t.Fatalf("hash = %s, want %s", got, want)
	}
}

func TestSealLinksRecords(t *testing.T) {
	first := sealed(testRecord(t))
	if first.PrevHash != GenesisHash {
		t.Fatalf("first record prev_hash = %x, want genesis", first.PrevHash)
	}
	second := testRecord(t)
	second.EventID = "0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e90"
	second.Seal(first.Hash)
	if second.PrevHash != first.Hash {
		t.Fatal("second record does not point to the first")
	}
	if second.Hash != ComputeHash(first.Hash, second) {
		t.Fatal("sealed hash differs from ComputeHash")
	}
}

func sealed(r Record) Record {
	r.Seal(GenesisHash)
	return r
}
