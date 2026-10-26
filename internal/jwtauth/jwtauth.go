// Package jwtauth verifies the bearer tokens that grant access to the AUD query API.
//
// Tokens are JWTs signed with RS256 by IAM. Only the public key is needed to verify them.
// While IAM is not ready, Issuer (stub.go) mints compatible tokens for development and tests.
package jwtauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Roles that the query API understands (claim "roles").
const (
	RoleAuditor = "auditor"
	RoleAdmin   = "admin"
)

// Leeway absorbs clock skew between IAM and AUD when checking exp and nbf.
const Leeway = 30 * time.Second

// minKeyBits is the smallest RSA modulus accepted for RS256.
const minKeyBits = 2048

// ErrInvalidToken means the token cannot be trusted: malformed, badly signed, expired, not
// yet valid, or for another issuer or audience. Callers answer 401 without telling which.
var ErrInvalidToken = errors.New("invalid token")

// Principal is the caller identified by a valid token.
type Principal struct {
	Subject string
	Roles   []string
}

// HasAnyRole reports whether p holds at least one of roles.
func (p Principal) HasAnyRole(roles ...string) bool {
	for _, r := range roles {
		if slices.Contains(p.Roles, r) {
			return true
		}
	}
	return false
}

// claims is the token payload: the registered claims plus the role list.
type claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`
}

// Verifier checks RS256 tokens against one public key.
type Verifier struct {
	key      *rsa.PublicKey
	issuer   string
	audience string
	now      func() time.Time
}

// NewVerifier parses a PEM public key (PKIX, RSA of at least 2048 bits). When issuer or
// audience are not empty, tokens must carry exactly that iss and include that aud.
func NewVerifier(publicKeyPEM []byte, issuer, audience string) (*Verifier, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("jwt public key: %w", err)
	}
	if key.N.BitLen() < minKeyBits {
		return nil, fmt.Errorf("jwt public key: RSA key has %d bits, want at least %d", key.N.BitLen(), minKeyBits)
	}
	return &Verifier{key: key, issuer: issuer, audience: audience, now: time.Now}, nil
}

// Verify returns the principal of a valid token. Every failure wraps ErrInvalidToken.
func (v *Verifier) Verify(token string) (Principal, error) {
	opts := []jwt.ParserOption{
		// Pinning the algorithm rejects "none" and HS256 signed with the public key.
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(Leeway),
		jwt.WithTimeFunc(v.now),
	}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	var c claims
	_, err := jwt.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return v.key, nil }, opts...)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return Principal{Subject: c.Subject, Roles: c.Roles}, nil
}
