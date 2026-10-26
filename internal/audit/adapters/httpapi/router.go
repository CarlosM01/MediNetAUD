// Package httpapi exposes the AUD use cases over HTTP.
package httpapi

import (
	"net/http"

	"github.com/medinetcore/aud/internal/audit/application"
	"github.com/medinetcore/aud/internal/jwtauth"
)

// Dependencies are the use cases the router exposes. Routes whose dependencies are nil are
// not registered.
type Dependencies struct {
	Auth   *Authenticator
	Ingest *application.Ingest
	// Tokens verifies the bearer tokens of the query API; Query serves it.
	Tokens *jwtauth.Verifier
	Query  *application.Query
}

// NewRouter builds the HTTP handler with every AUD route registered.
func NewRouter(d Dependencies) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	if d.Auth != nil && d.Ingest != nil {
		mux.Handle("POST /api/v1/events", d.Auth.Middleware(maxEventBody, ingestEvent(d.Ingest)))
		mux.Handle("POST /api/v1/events/batch", d.Auth.Middleware(maxBatchBody, ingestBatch(d.Ingest)))
	}
	api := newAPI(mux)
	if d.Tokens != nil && d.Query != nil {
		registerQuery(api, d.Tokens, d.Query)
	}
	return mux
}
