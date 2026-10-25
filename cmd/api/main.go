// Command api runs the AUD (audit and security traceability) HTTP service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/medinetcore/aud/internal/audit/adapters/httpapi"
	"github.com/medinetcore/aud/internal/audit/adapters/postgres"
	"github.com/medinetcore/aud/internal/audit/adapters/queue"
	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/config"
	"github.com/medinetcore/aud/internal/secretbox"
)

const shutdownTimeout = 15 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database: %w", err)
	}

	box, err := secretbox.New(cfg.SecretKey)
	if err != nil {
		return err
	}
	events := queue.New(postgres.NewEventStore(pool), cfg.QueueCapacity, logger)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Dependencies{
			Auth:   httpapi.NewAuthenticator(postgres.NewClientStore(pool, box)),
			Ingest: application.NewIngest(events),
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	var serveErr error
	select {
	case serveErr = <-errCh:
	case <-ctx.Done():
	}

	// Stop taking requests first, then drain the queue so every 202 reaches the database.
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	httpErr := srv.Shutdown(shutdownCtx)
	if err := events.Close(shutdownCtx); err != nil {
		logger.Error("event queue not fully drained", "error", err)
		return errors.Join(serveErr, httpErr, err)
	}
	logger.Info("event queue drained")
	return errors.Join(serveErr, httpErr)
}
