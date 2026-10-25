package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/medinetcore/aud/internal/audit/ports"
)

// Signature headers of the ingest contract §3.
const (
	headerClientID  = "X-AUD-Client-Id"
	headerTimestamp = "X-AUD-Timestamp"
	headerSignature = "X-AUD-Signature"
)

// SignatureWindow is how far X-AUD-Timestamp may be from the AUD clock, in either direction.
const SignatureWindow = 5 * time.Minute

// unauthorizedDetail is the same for every authentication failure, so the response never
// tells an attacker which part was wrong.
const unauthorizedDetail = "invalid request signature"

var (
	timestampPattern = regexp.MustCompile(`^[0-9]{1,19}$`)
	signaturePattern = regexp.MustCompile(`^sha256=([0-9a-f]{64})$`)
)

type clientKey struct{}

// clientFrom returns the client authenticated by the HMAC middleware.
func clientFrom(ctx context.Context) (ports.Client, bool) {
	c, ok := ctx.Value(clientKey{}).(ports.Client)
	return c, ok
}

// Authenticator verifies HMAC-SHA256 request signatures.
type Authenticator struct {
	clients ports.ClientStore
	now     func() time.Time
}

// NewAuthenticator returns an Authenticator that looks up secrets in clients.
func NewAuthenticator(clients ports.ClientStore) *Authenticator {
	return &Authenticator{clients: clients, now: time.Now}
}

// Middleware authenticates the request before calling next. It reads at most maxBody bytes
// (413 beyond that), checks the timestamp window and compares
// HMAC-SHA256(secret, timestamp + "." + body) in constant time. On success next receives the
// same body and the client in the request context.
func (a *Authenticator) Middleware(maxBody int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := r.Header.Get(headerClientID)
		ts := r.Header.Get(headerTimestamp)
		sigMatch := signaturePattern.FindStringSubmatch(r.Header.Get(headerSignature))
		if clientID == "" || !timestampPattern.MatchString(ts) || sigMatch == nil {
			writeProblem(w, http.StatusUnauthorized, unauthorizedDetail)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeProblem(w, http.StatusRequestEntityTooLarge, "request body exceeds "+strconv.FormatInt(maxBody, 10)+" bytes")
				return
			}
			writeProblem(w, http.StatusBadRequest, "could not read request body")
			return
		}

		if !a.withinWindow(ts) {
			writeProblem(w, http.StatusUnauthorized, unauthorizedDetail)
			return
		}

		client, err := a.clients.FindClient(r.Context(), clientID)
		if errors.Is(err, ports.ErrClientNotFound) {
			writeProblem(w, http.StatusUnauthorized, unauthorizedDetail)
			return
		}
		if err != nil {
			slog.ErrorContext(r.Context(), "client lookup failed", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}

		got, _ := hex.DecodeString(sigMatch[1]) // the pattern guarantees valid hex
		mac := hmac.New(sha256.New, client.Secret)
		mac.Write([]byte(ts))
		mac.Write([]byte{'.'})
		mac.Write(body)
		if !hmac.Equal(mac.Sum(nil), got) {
			writeProblem(w, http.StatusUnauthorized, unauthorizedDetail)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, client)))
	})
}

func (a *Authenticator) withinWindow(ts string) bool {
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	skew := a.now().Sub(time.Unix(sec, 0))
	return skew >= -SignatureWindow && skew <= SignatureWindow
}
