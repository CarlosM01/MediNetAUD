package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

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

// problem is also the error type of the huma operations (see newProblem).
var _ huma.StatusError = (*problem)(nil)

func (p *problem) Error() string  { return p.Detail }
func (p *problem) GetStatus() int { return p.Status }

// ContentType makes huma send problems as application/problem+json.
func (p *problem) ContentType(ct string) string {
	if ct == "application/json" {
		return "application/problem+json"
	}
	return ct
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
