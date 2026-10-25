package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/medinetcore/aud/internal/audit/ports"
	"github.com/medinetcore/aud/internal/secretbox"
)

// secretBytes is the entropy of a generated client secret (printed as 64 hex characters).
const secretBytes = 32

// ErrClientExists means the client_id is already registered.
var ErrClientExists = errors.New("client already exists")

// ClientStore keeps ingest clients with their HMAC secret encrypted (AES-256-GCM, bound to
// the client_id). FindClient works as aud_app; CreateClient and DisableClient need aud_owner.
type ClientStore struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
}

var _ ports.ClientStore = (*ClientStore)(nil)

// NewClientStore returns a store that encrypts secrets with box.
func NewClientStore(pool *pgxpool.Pool, box *secretbox.Box) *ClientStore {
	return &ClientStore{pool: pool, box: box}
}

// FindClient implements ports.ClientStore. Inactive clients are reported as not found.
func (s *ClientStore) FindClient(ctx context.Context, clientID string) (ports.Client, error) {
	var (
		module string
		sealed []byte
	)
	err := s.pool.QueryRow(ctx,
		"SELECT module_code, secret_enc FROM api_clients WHERE client_id = $1 AND active", clientID,
	).Scan(&module, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.Client{}, ports.ErrClientNotFound
	}
	if err != nil {
		return ports.Client{}, fmt.Errorf("find client: %w", err)
	}
	secret, err := s.box.Open(sealed, []byte(clientID))
	if err != nil {
		return ports.Client{}, fmt.Errorf("decrypt secret of client %s: %w", clientID, err)
	}
	return ports.Client{ID: clientID, Module: module, Secret: secret}, nil
}

// CreateClient registers a client for module and returns its new secret. The secret is not
// stored in clear text anywhere, so this is the only time it can be read.
func (s *ClientStore) CreateClient(ctx context.Context, clientID, module string) (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(raw)
	sealed, err := s.box.Seal([]byte(secret), []byte(clientID))
	if err != nil {
		return "", err
	}
	tag, err := s.pool.Exec(ctx,
		"INSERT INTO api_clients (client_id, module_code, secret_enc) VALUES ($1, $2, $3) ON CONFLICT (client_id) DO NOTHING",
		clientID, module, sealed)
	if err != nil {
		return "", fmt.Errorf("create client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", ErrClientExists
	}
	return secret, nil
}

// DisableClient deactivates a client; its signatures are rejected from then on.
func (s *ClientStore) DisableClient(ctx context.Context, clientID string) error {
	tag, err := s.pool.Exec(ctx, "UPDATE api_clients SET active = false WHERE client_id = $1", clientID)
	if err != nil {
		return fmt.Errorf("disable client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ports.ErrClientNotFound
	}
	return nil
}
