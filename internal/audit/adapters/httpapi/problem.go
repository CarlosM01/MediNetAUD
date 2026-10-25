package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/medinetcore/aud/internal/audit/domain"
)

// problem is an RFC 7807 error body, as specified by the ingest contract §4.
type problem struct {
	Type   string              `json:"type"`
	Title  string              `json:"title"`
	Status int                 `json:"status"`
	Detail string              `json:"detail,omitempty"`
	Errors []domain.FieldError `json:"errors,omitempty"`
}

func writeProblem(w http.ResponseWriter, status int, detail string, fields ...domain.FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Errors: fields,
	})
}
