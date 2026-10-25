package postgres

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres/pgtest"
	"github.com/medinetcore/aud/internal/audit/ports"
	"github.com/medinetcore/aud/internal/secretbox"
)

func TestClientLifecycle(t *testing.T) {
	db := pgtest.Start(t)
	ctx := context.Background()
	box, err := secretbox.New(bytes.Repeat([]byte{9}, secretbox.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	owner := NewClientStore(pgtest.Pool(t, db.OwnerURL), box)
	app := NewClientStore(pgtest.Pool(t, db.AppURL), box)

	secret, err := owner.CreateClient(ctx, "lab-service", "LAB")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(secret) {
		t.Fatalf("secret = %q, want 64 hex characters", secret)
	}

	var stored []byte
	if err := pgtest.Pool(t, db.OwnerURL).QueryRow(ctx,
		"SELECT secret_enc FROM api_clients WHERE client_id = 'lab-service'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(secret)) {
		t.Fatal("secret_enc holds the secret in clear text")
	}

	got, err := app.FindClient(ctx, "lab-service")
	if err != nil {
		t.Fatalf("FindClient as aud_app: %v", err)
	}
	if got.Module != "LAB" || string(got.Secret) != secret {
		t.Fatalf("FindClient = %+v, want module LAB and the issued secret", got)
	}

	if _, err := owner.CreateClient(ctx, "lab-service", "LAB"); !errors.Is(err, ErrClientExists) {
		t.Fatalf("CreateClient twice: err = %v, want ErrClientExists", err)
	}
	if _, err := app.FindClient(ctx, "nobody"); !errors.Is(err, ports.ErrClientNotFound) {
		t.Fatalf("FindClient(unknown): err = %v, want ErrClientNotFound", err)
	}
	if _, err := app.CreateClient(ctx, "far-service", "FAR"); err == nil {
		t.Fatal("aud_app could create a client")
	}

	if err := owner.DisableClient(ctx, "lab-service"); err != nil {
		t.Fatalf("DisableClient: %v", err)
	}
	if _, err := app.FindClient(ctx, "lab-service"); !errors.Is(err, ports.ErrClientNotFound) {
		t.Fatalf("FindClient(disabled): err = %v, want ErrClientNotFound", err)
	}
}
