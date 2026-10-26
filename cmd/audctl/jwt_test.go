package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/medinetcore/aud/internal/jwtauth"
)

func TestJWTKeygenAndMintProduceVerifiableToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUD_JWT_ISSUER", "medinet-iam")
	t.Setenv("AUD_JWT_AUDIENCE", "aud")

	if err := run([]string{"jwt", "keygen", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, privateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key mode = %o, want 600", perm)
	}

	var out bytes.Buffer
	args := []string{"jwt", "mint", "-key", filepath.Join(dir, privateKeyFile), "-sub", "auditor-1", "-roles", "auditor,admin"}
	if err := run(args, &out); err != nil {
		t.Fatalf("mint: %v", err)
	}

	pub, err := os.ReadFile(filepath.Join(dir, publicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jwtauth.NewVerifier(pub, "medinet-iam", "aud")
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("Verify minted token: %v", err)
	}
	if p.Subject != "auditor-1" || !p.HasAnyRole(jwtauth.RoleAuditor) || !p.HasAnyRole(jwtauth.RoleAdmin) {
		t.Errorf("principal = %+v, want auditor-1 with auditor and admin", p)
	}
}

func TestJWTKeygenNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"jwt", "keygen", dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	got, _ := os.ReadFile(filepath.Join(dir, privateKeyFile))
	if string(got) != "keep me" {
		t.Errorf("private key changed to %q", got)
	}
}

func TestJWTKeygenLeavesNothingWhenPublicKeyExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"jwt", "keygen", dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("keygen overwrote an existing public key")
	}
	if _, err := os.Stat(filepath.Join(dir, privateKeyFile)); !os.IsNotExist(err) {
		t.Errorf("keygen left a private key without its public key (stat err = %v)", err)
	}
}

func TestJWTKeygenCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := run([]string{"jwt", "keygen", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("keygen into a missing directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}
}

func TestJWTMintTrimsRoles(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"jwt", "keygen", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"jwt", "mint", "-key", filepath.Join(dir, privateKeyFile), "-sub", "u", "-roles", " auditor, admin ,"}
	if err := run(args, &out); err != nil {
		t.Fatalf("mint: %v", err)
	}
	pub, _ := os.ReadFile(filepath.Join(dir, publicKeyFile))
	v, err := jwtauth.NewVerifier(pub, "", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles) != 2 || !p.HasAnyRole(jwtauth.RoleAuditor) || !p.HasAnyRole(jwtauth.RoleAdmin) {
		t.Errorf("Roles = %q, want [auditor admin]", p.Roles)
	}
}

func TestUsageErrors(t *testing.T) {
	tests := [][]string{
		nil,
		{"jwt"},
		{"jwt", "keygen"},
		{"jwt", "mint", "-sub", "x"},
		{"jwt", "mint", "-key", "k.pem"},
		{"jwt", "mint", "-bogus"},
		{"jwt", "mint", "-key", "k.pem", "-sub", "x"},
		{"jwt", "mint", "-key", "k.pem", "-sub", "x", "-roles", " , "},
		{"jwt", "mint", "-key", "k.pem", "-sub", "x", "-roles", "auditor", "-ttl", "0s"},
		{"jwt", "mint", "-key", "k.pem", "-sub", "x", "-roles", "auditor", "-ttl", "-1h"},
		{"client", "create", "only-id"},
		{"client", "disable"},
		{"tokens", "list"},
		{"client"},
	}
	for _, args := range tests {
		if err := run(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("run(%q) = %v, want a usage error", args, err)
		}
	}
}
