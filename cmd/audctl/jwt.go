package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/medinetcore/aud/internal/jwtauth"
)

// Key file names written by "jwt keygen".
const (
	privateKeyFile = "jwt-private.pem"
	publicKeyFile  = "jwt-public.pem"
)

func runJWT(args []string, stdout io.Writer) error {
	switch {
	case args[0] == "keygen" && len(args) == 2:
		return jwtKeygen(args[1], stdout)
	case args[0] == "mint":
		return jwtMint(args[1:], stdout)
	default:
		return errors.New(usage)
	}
}

// jwtKeygen writes a new key pair into dir, creating it if needed. It never overwrites
// existing files and leaves no half-written pair behind. The operator chooses dir on their own
// machine, hence the #nosec annotations on its file operations.
func jwtKeygen(dir string, stdout io.Writer) error {
	privPath, pubPath := filepath.Join(dir, privateKeyFile), filepath.Join(dir, publicKeyFile)
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Lstat(p); err == nil { // #nosec G703
			return fmt.Errorf("%s already exists", p)
		}
	}
	privPEM, pubPEM, err := jwtauth.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G703
		return err
	}
	if err := writeNew(privPath, privPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(pubPath, pubPEM, 0o644); err != nil {
		_ = os.Remove(privPath) // #nosec G703
		return err
	}
	_, err = fmt.Fprintf(stdout, "private key: %s (keep it private)\npublic key:  %s (AUD_JWT_PUBLIC_KEY_FILE)\n", privPath, pubPath)
	return err
}

// writeNew creates path with data. It fails if path exists and removes a partial file. path
// comes from jwtKeygen, hence the #nosec annotations.
func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) // #nosec G304 G703
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path) // #nosec G703
	}
	return err
}

// jwtMint prints a signed token.
func jwtMint(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("jwt mint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	keyPath := fs.String("key", "", "private key PEM file")
	subject := fs.String("sub", "", "subject (user id)")
	roles := fs.String("roles", "", "comma-separated roles, e.g. auditor,admin")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	issuer := fs.String("iss", os.Getenv("AUD_JWT_ISSUER"), "iss claim")
	audience := fs.String("aud", os.Getenv("AUD_JWT_AUDIENCE"), "aud claim")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n%s", err, usage)
	}
	roleList := splitRoles(*roles)
	if *keyPath == "" || *subject == "" || len(roleList) == 0 || *ttl <= 0 || fs.NArg() > 0 {
		return errors.New(usage)
	}

	privPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	iss, err := jwtauth.NewIssuer(privPEM, *issuer, *audience)
	if err != nil {
		return err
	}
	token, err := iss.Mint(*subject, roleList, *ttl)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token)
	return err
}

// splitRoles parses a comma-separated list, trimming spaces and dropping empty entries.
func splitRoles(s string) []string {
	var roles []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}
