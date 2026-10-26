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

// jwtKeygen writes a new key pair into dir. It never overwrites existing files.
func jwtKeygen(dir string, stdout io.Writer) error {
	privPEM, pubPEM, err := jwtauth.GenerateKeyPair()
	if err != nil {
		return err
	}
	privPath, pubPath := filepath.Join(dir, privateKeyFile), filepath.Join(dir, publicKeyFile)
	if err := writeNew(privPath, privPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(pubPath, pubPEM, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "private key: %s (keep it private)\npublic key:  %s (AUD_JWT_PUBLIC_KEY_FILE)\n", privPath, pubPath)
	return err
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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
	if *keyPath == "" || *subject == "" || fs.NArg() > 0 {
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
	var roleList []string
	if *roles != "" {
		roleList = strings.Split(*roles, ",")
	}
	token, err := iss.Mint(*subject, roleList, *ttl)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token)
	return err
}
