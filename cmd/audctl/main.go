// Command audctl administers AUD ingest clients. It connects as aud_owner, so it is meant
// for operators only; the API itself never uses the owner credentials.
//
//	audctl client create <client_id> <module>   prints the new secret once
//	audctl client disable <client_id>
//
// Environment: AUD_ADMIN_DATABASE_URL (aud_owner) and AUD_SECRET_KEY (base64, 32 bytes).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres"
	"github.com/medinetcore/aud/internal/secretbox"
)

const usage = `usage:
  audctl client create <client_id> <module>
  audctl client disable <client_id>`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "audctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 3 || args[0] != "client" {
		return errors.New(usage)
	}

	key, err := secretbox.ParseKey(os.Getenv("AUD_SECRET_KEY"))
	if err != nil {
		return fmt.Errorf("AUD_SECRET_KEY: %w", err)
	}
	box, err := secretbox.New(key)
	if err != nil {
		return err
	}
	dsn := os.Getenv("AUD_ADMIN_DATABASE_URL")
	if dsn == "" {
		return errors.New("AUD_ADMIN_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	clients := postgres.NewClientStore(pool, box)

	switch {
	case args[1] == "create" && len(args) == 4:
		secret, err := clients.CreateClient(ctx, args[2], args[3])
		if err != nil {
			return err
		}
		fmt.Printf("client_id=%s\nsecret=%s\n", args[2], secret)
		fmt.Fprintln(os.Stderr, "Deliver the secret through a private channel. It cannot be shown again.")
		return nil
	case args[1] == "disable" && len(args) == 3:
		return clients.DisableClient(ctx, args[2])
	default:
		return errors.New(usage)
	}
}
