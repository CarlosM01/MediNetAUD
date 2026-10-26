// Package pgtest starts a disposable PostgreSQL with the AUD roles and migrations, for tests.
package pgtest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// #nosec G101 -- throwaway credentials of a disposable test container.
const (
	image       = "postgres:17.6-alpine"
	database    = "aud"
	ownerPass   = "owner-test-password"
	appPass     = "app-test-password"
	superPass   = "postgres-test-password"
	startupWait = 2 * time.Minute
)

// DB is a migrated database. AppURL connects as aud_app, OwnerURL as aud_owner.
type DB struct {
	AppURL   string
	OwnerURL string
}

// Start runs a fresh database for one test and removes it when the test ends. It skips the
// test in -short mode or when Docker is unavailable.
func Start(t *testing.T) DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: skipped in -short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	root := repoRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), startupWait)
	defer cancel()

	ctr, err := tcpostgres.Run(ctx, image,
		tcpostgres.WithDatabase(database),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword(superPass),
		tcpostgres.WithInitScripts(filepath.Join(root, "deploy", "initdb", "01-roles.sh")),
		testcontainers.WithEnv(map[string]string{
			"AUD_OWNER_PASSWORD": ownerPass,
			"AUD_APP_PASSWORD":   appPass,
		}),
		tcpostgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	superURL, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	db := DB{
		AppURL:   withUser(t, superURL, "aud_app", appPass),
		OwnerURL: withUser(t, superURL, "aud_owner", ownerPass),
	}
	migrate(ctx, t, db.OwnerURL, filepath.Join(root, "migrations"))
	return db
}

// Pool opens a pool to url that is closed when the test ends.
func Pool(t *testing.T, url string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// migrate applies every *.up.sql file in order, as golang-migrate would.
func migrate(ctx context.Context, t *testing.T, ownerURL, dir string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations in %s: %v", dir, err)
	}
	sort.Strings(files)

	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatalf("connect as owner: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	for _, f := range files {
		sql, err := os.ReadFile(f) // #nosec G304 -- migration files listed by the test itself.
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Without arguments pgx uses the simple protocol, which accepts several statements.
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(f), err)
		}
	}
}

func withUser(t *testing.T, raw, user, pass string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse connection string: %v", err)
	}
	u.User = url.UserPassword(user, pass)
	return u.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal(fmt.Errorf("go.mod not found above the test directory"))
		}
		dir = parent
	}
}
