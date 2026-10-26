package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/medinetcore/aud/internal/audit/domain"
	"github.com/medinetcore/aud/internal/audit/ports"
)

func TestFindEvent(t *testing.T) {
	store, _ := setupStore(t)
	ctx := context.Background()
	recs := []domain.Record{record(t, 1, nil), record(t, 2, func(in *domain.EventInput) {
		in.SourceIP, in.ActorID, in.ActorType = "", "", ""
		in.Payload = []byte(`{"n": 12345678901234567890, "a": [1, 2]}`)
	})}
	if _, err := store.Append(ctx, recs); err != nil {
		t.Fatal(err)
	}

	got, err := store.FindEvent(ctx, recs[1].EventID)
	if err != nil {
		t.Fatalf("FindEvent: %v", err)
	}
	if got.ID != 2 || got.EventID != recs[1].EventID || got.ActorID != "" || got.SourceIP != "" {
		t.Errorf("FindEvent = %+v, want the second record with no actor or IP", got)
	}
	if string(got.Payload) != `{"a": [1, 2], "n": 12345678901234567890}` {
		t.Errorf("payload = %s, want the stored jsonb text", got.Payload)
	}
	if got.Hash != domain.ComputeHash(got.PrevHash, got.Record) {
		t.Error("returned record does not match its own hash")
	}

	_, err = store.FindEvent(ctx, "11111111-2222-4333-8444-555555555555")
	if !errors.Is(err, ports.ErrEventNotFound) {
		t.Errorf("FindEvent(unknown) error = %v, want ErrEventNotFound", err)
	}
}
