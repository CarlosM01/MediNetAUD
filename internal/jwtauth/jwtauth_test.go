package jwtauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "medinet-iam"
	testAudience = "aud"
)

var testNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func newKeys(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	privPEM, pubPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return privPEM, pubPEM
}

func newIssuer(t *testing.T, privPEM []byte, issuer, audience string) *Issuer {
	t.Helper()
	iss, err := NewIssuer(privPEM, issuer, audience)
	if err != nil {
		t.Fatal(err)
	}
	iss.now = func() time.Time { return testNow }
	return iss
}

func newVerifier(t *testing.T, pubPEM []byte, issuer, audience string) *Verifier {
	t.Helper()
	v, err := NewVerifier(pubPEM, issuer, audience)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return testNow }
	return v
}

func mint(t *testing.T, iss *Issuer, sub string, roles []string, ttl time.Duration) string {
	t.Helper()
	tok, err := iss.Mint(sub, roles, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	priv, pub := newKeys(t)
	tok := mint(t, newIssuer(t, priv, testIssuer, testAudience), "user-42", []string{RoleAuditor}, time.Hour)

	p, err := newVerifier(t, pub, testIssuer, testAudience).Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Subject != "user-42" {
		t.Errorf("Subject = %q, want user-42", p.Subject)
	}
	if !p.HasAnyRole(RoleAuditor) || p.HasAnyRole(RoleAdmin) {
		t.Errorf("Roles = %v, want only %s", p.Roles, RoleAuditor)
	}
}

func TestVerifyAcceptsTokenWithoutRoles(t *testing.T) {
	priv, pub := newKeys(t)
	tok := mint(t, newIssuer(t, priv, testIssuer, testAudience), "user-42", nil, time.Hour)

	p, err := newVerifier(t, pub, testIssuer, testAudience).Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.HasAnyRole(RoleAuditor, RoleAdmin) {
		t.Errorf("Roles = %v, want none", p.Roles)
	}
}

func TestVerifyIssuerAndAudienceAreOptional(t *testing.T) {
	priv, pub := newKeys(t)
	tok := mint(t, newIssuer(t, priv, "", ""), "user-42", []string{RoleAdmin}, time.Hour)

	if _, err := newVerifier(t, pub, "", "").Verify(tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsInvalidTokens(t *testing.T) {
	priv, pub := newKeys(t)
	otherPriv, _ := newKeys(t)
	iss := newIssuer(t, priv, testIssuer, testAudience)
	roles := []string{RoleAdmin}

	tests := []struct {
		name  string
		token string
	}{
		{"expired", mint(t, iss, "u", roles, -time.Minute)},
		{"signed with another key", mint(t, newIssuer(t, otherPriv, testIssuer, testAudience), "u", roles, time.Hour)},
		{"payload altered after signing", alterPayload(t, mint(t, iss, "u", []string{RoleAuditor}, time.Hour))},
		{"alg none", unsignedToken(t)},
		{"HS256 keyed with the public key", hs256WithPublicKey(t, pub)},
		{"ES256", es256Token(t)},
		{"without exp", signRS256(t, priv, jwt.MapClaims{"sub": "u", "iss": testIssuer, "aud": testAudience, "roles": roles})},
		{"wrong issuer", mint(t, newIssuer(t, priv, "someone-else", testAudience), "u", roles, time.Hour)},
		{"wrong audience", mint(t, newIssuer(t, priv, testIssuer, "pac"), "u", roles, time.Hour)},
		{"not yet valid", signRS256(t, priv, jwt.MapClaims{
			"sub": "u", "iss": testIssuer, "aud": testAudience, "roles": roles,
			"exp": testNow.Add(2 * time.Hour).Unix(), "nbf": testNow.Add(time.Hour).Unix(),
		})},
		{"without sub", signRS256(t, priv, jwt.MapClaims{
			"iss": testIssuer, "aud": testAudience, "roles": roles, "exp": testNow.Add(time.Hour).Unix(),
		})},
		{"roles is not a string list", signRS256(t, priv, jwt.MapClaims{
			"sub": "u", "iss": testIssuer, "aud": testAudience, "roles": "admin", "exp": testNow.Add(time.Hour).Unix(),
		})},
		{"malformed", "not.a.jwt"},
		{"empty", ""},
	}

	v := newVerifier(t, pub, testIssuer, testAudience)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := v.Verify(tt.token)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify = (%+v, %v), want ErrInvalidToken", p, err)
			}
		})
	}
}

func TestVerifyToleratesSmallClockSkew(t *testing.T) {
	priv, pub := newKeys(t)
	tok := mint(t, newIssuer(t, priv, testIssuer, testAudience), "u", []string{RoleAdmin}, -Leeway/2)

	if _, err := newVerifier(t, pub, testIssuer, testAudience).Verify(tok); err != nil {
		t.Fatalf("Verify of a token expired %s ago: %v", Leeway/2, err)
	}
}

func TestNewVerifierRejectsUnusableKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakDER, _ := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	priv, _ := newKeys(t)

	tests := []struct {
		name string
		pem  []byte
	}{
		{"empty", nil},
		{"not PEM", []byte("hello")},
		{"RSA shorter than 2048 bits", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: weakDER})},
		{"EC key", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})},
		{"private key instead of public", priv},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewVerifier(tt.pem, "", ""); err == nil {
				t.Fatal("NewVerifier accepted the key")
			}
		})
	}
}

func TestNewIssuerRejectsPublicKey(t *testing.T) {
	_, pub := newKeys(t)
	if _, err := NewIssuer(pub, "", ""); err == nil {
		t.Fatal("NewIssuer accepted a public key")
	}
}

func signRS256(t *testing.T, privPEM []byte, claims jwt.MapClaims) string {
	t.Helper()
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "u", "iss": testIssuer, "aud": testAudience,
		"roles": []string{RoleAdmin}, "exp": testNow.Add(time.Hour).Unix(),
	}
}

// alterPayload swaps the payload for one granting admin, keeping the original signature.
func alterPayload(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	body, err := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims()).SigningString()
	if err != nil {
		t.Fatal(err)
	}
	return parts[0] + "." + strings.Split(body, ".")[1] + "." + parts[2]
}

func unsignedToken(t *testing.T) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// hs256WithPublicKey is the classic algorithm-confusion attack: the public key, which anyone
// can read, used as an HMAC secret.
func hs256WithPublicKey(t *testing.T, pubPEM []byte) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims()).SignedString(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func es256Token(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims()).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
