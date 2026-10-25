package config

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"testing"
)

var testKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://aud_app:pw@localhost:5432/aud")
	t.Setenv("AUD_SECRET_KEY", testKey)
}

func TestLoadDefaults(t *testing.T) {
	setRequired(t)
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("QUEUE_CAPACITY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
	if cfg.QueueCapacity != 1024 {
		t.Errorf("QueueCapacity = %d, want 1024", cfg.QueueCapacity)
	}
}

func TestLoadFromEnv(t *testing.T) {
	setRequired(t)
	t.Setenv("HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("QUEUE_CAPACITY", "50")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "127.0.0.1:9090")
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelDebug)
	}
	if cfg.DatabaseURL != "postgres://aud_app:pw@localhost:5432/aud" || len(cfg.SecretKey) != 32 || cfg.QueueCapacity != 50 {
		t.Errorf("cfg = %+v, want the database URL, a 32-byte key and capacity 50", cfg)
	}
}

func TestLoadRejectsInvalidLogLevel(t *testing.T) {
	setRequired(t)
	t.Setenv("LOG_LEVEL", "verbose")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for invalid LOG_LEVEL")
	}
}

func TestLoadRejectsMissingOrInvalidValues(t *testing.T) {
	tests := map[string][2]string{
		"missing DATABASE_URL":       {"DATABASE_URL", ""},
		"missing AUD_SECRET_KEY":     {"AUD_SECRET_KEY", ""},
		"short AUD_SECRET_KEY":       {"AUD_SECRET_KEY", base64.StdEncoding.EncodeToString([]byte("short"))},
		"QUEUE_CAPACITY not integer": {"QUEUE_CAPACITY", "many"},
		"QUEUE_CAPACITY zero":        {"QUEUE_CAPACITY", "0"},
	}
	for name, kv := range tests {
		t.Run(name, func(t *testing.T) {
			setRequired(t)
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatalf("Load() error = nil with %s=%q", kv[0], kv[1])
			}
		})
	}
}
