package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// stubKeyBits is the size of the keys GenerateKeyPair creates.
const stubKeyBits = 3072

// GenerateKeyPair creates an RSA key pair for the stub issuer, PEM encoded: the private key as
// PKCS#8 and the public key as PKIX.
func GenerateKeyPair() (privatePEM, publicPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, stubKeyBits)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// Issuer is a local stand-in for IAM: it signs RS256 tokens in the format Verifier expects.
// It is meant for development and tests only.
type Issuer struct {
	key      *rsa.PrivateKey
	issuer   string
	audience string
	now      func() time.Time
}

// NewIssuer parses a PEM private key (PKCS#1 or PKCS#8). Empty issuer or audience leave the
// iss or aud claim out.
func NewIssuer(privateKeyPEM []byte, issuer, audience string) (*Issuer, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("jwt private key: %w", err)
	}
	return &Issuer{key: key, issuer: issuer, audience: audience, now: time.Now}, nil
}

// Mint signs a token for subject with roles, valid for ttl from now.
func (i *Issuer) Mint(subject string, roles []string, ttl time.Duration) (string, error) {
	now := i.now()
	c := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    i.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Roles: roles,
	}
	if i.audience != "" {
		c.Audience = jwt.ClaimStrings{i.audience}
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(i.key)
}
