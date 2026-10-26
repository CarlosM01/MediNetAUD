// Command audctl administers AUD ingest clients and runs the local JWT issuer stub.
//
//	audctl client create <client_id> <module>   prints the new secret once
//	audctl client disable <client_id>
//	audctl jwt keygen <dir>                     writes jwt-private.pem and jwt-public.pem
//	audctl jwt mint -key <file> -sub <id> -roles auditor[,admin] [-ttl 1h]
//
// The client commands connect as aud_owner, so they are meant for operators only; the API
// itself never uses the owner credentials. Environment: AUD_ADMIN_DATABASE_URL (aud_owner) and
// AUD_SECRET_KEY (base64, 32 bytes).
//
// The jwt commands stand in for IAM until it issues real tokens. mint reads AUD_JWT_ISSUER and
// AUD_JWT_AUDIENCE as defaults for -iss and -aud, so its tokens match what the API expects.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/medinetcore/aud/internal/audit/adapters/postgres"
	"github.com/medinetcore/aud/internal/secretbox"
)

const usage = `usage:
  audctl client create <client_id> <module>
  audctl client disable <client_id>
  audctl jwt keygen <dir>
  audctl jwt mint -key <private.pem> -sub <id> -roles <role,...> [-ttl 1h] [-iss <iss>] [-aud <aud>]`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "audctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) < 2 {
		return errors.New(usage)
	}
	switch args[0] {
	case "client":
		return runClient(args[1:], stdout)
	case "jwt":
		return runJWT(args[1:], stdout)
	default:
		return errors.New(usage)
	}
}

func runClient(args []string, stdout io.Writer) error {
	if (args[0] != "create" || len(args) != 3) && (args[0] != "disable" || len(args) != 2) {
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
	case args[0] == "create" && len(args) == 3:
		secret, err := clients.CreateClient(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "client_id=%s\nsecret=%s\n", args[1], secret); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Deliver the secret through a private channel. It cannot be shown again.")
		return nil
	case args[0] == "disable" && len(args) == 2:
		return clients.DisableClient(ctx, args[1])
	default:
		return errors.New(usage)
	}
}
