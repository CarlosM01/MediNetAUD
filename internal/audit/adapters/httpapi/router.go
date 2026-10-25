// Package httpapi exposes the AUD use cases over HTTP.
package httpapi

import "net/http"

// NewRouter builds the HTTP handler with every AUD route registered.
func NewRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	return mux
}
