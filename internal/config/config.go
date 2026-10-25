// Package config loads the service configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/medinetcore/aud/internal/secretbox"
)

// Config holds the runtime settings of the AUD service.
type Config struct {
	HTTPAddr string
	LogLevel slog.Level
	// DatabaseURL connects as aud_app, the role that can only insert and read.
	DatabaseURL string
	// SecretKey decrypts the HMAC secrets of the ingest clients (AES-256-GCM).
	SecretKey []byte
	// QueueCapacity is how many accepted submissions may wait for the writer.
	QueueCapacity int
}

// Load reads the configuration from the environment, applying defaults for unset values.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:    getenv("HTTP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(getenv("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("invalid LOG_LEVEL: %w", err)
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}

	key, err := secretbox.ParseKey(os.Getenv("AUD_SECRET_KEY"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid AUD_SECRET_KEY: %w", err)
	}
	cfg.SecretKey = key

	capacity, err := strconv.Atoi(getenv("QUEUE_CAPACITY", "1024"))
	if err != nil || capacity < 1 {
		return Config{}, fmt.Errorf("invalid QUEUE_CAPACITY: must be a positive integer")
	}
	cfg.QueueCapacity = capacity

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
