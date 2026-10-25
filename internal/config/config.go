// Package config loads the service configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
)

// Config holds the runtime settings of the AUD service.
type Config struct {
	HTTPAddr string
	LogLevel slog.Level
}

// Load reads the configuration from the environment, applying defaults for unset values.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddr: getenv("HTTP_ADDR", ":8080"),
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(getenv("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("invalid LOG_LEVEL: %w", err)
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
