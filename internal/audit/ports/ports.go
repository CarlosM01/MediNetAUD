package ports

import (
	"context"
	"errors"

	"github.com/medinetcore/aud/internal/audit/domain"
)

// ErrClientNotFound means the client does not exist or is inactive.
var ErrClientNotFound = errors.New("client not found")

// Client is an emitter allowed to ingest events, with its HMAC secret in clear text.
type Client struct {
	ID     string
	Module string
	Secret []byte
}

// ClientStore looks up active ingest clients.
type ClientStore interface {
	FindClient(ctx context.Context, clientID string) (Client, error)
}

// EventStore persists records in the append-only hash chain.
type EventStore interface {
	// Append seals the records in order and stores them in one transaction. A record whose
	// event_id already exists is skipped and does not advance the chain. It returns how many
	// records were inserted.
	Append(ctx context.Context, records []domain.Record) (int, error)
}
