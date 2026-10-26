package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/medinetcore/aud/internal/audit/domain"
)

// apiVersion is the version of the AUD HTTP API published in the OpenAPI document.
const apiVersion = "1.0.0"

func init() {
	huma.NewError = newProblem
}

// newAPI registers the huma API (OpenAPI document and docs UI) on mux.
func newAPI(mux *http.ServeMux) huma.API {
	config := huma.DefaultConfig("MediNet-Core AUD", apiVersion)
	// No $schema field or Link header in responses: clients get exactly the documented body.
	config.CreateHooks = nil
	config.SchemasPath = ""
	// The router serves the merged document and Swagger UI itself (spec.go, docs.go).
	config.OpenAPIPath = ""
	config.DocsPath = ""
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		bearerScheme: {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description:  "RS256 JWT issued by IAM, with the claims `sub`, `exp` and `roles` (`auditor` or `admin`).",
		},
	}
	api := humago.New(mux, config)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		ctx.SetHeader("X-Content-Type-Options", "nosniff")
		next(ctx)
	})
	return api
}

// newProblem replaces huma's error constructor so every error has the same RFC 7807 shape as
// the ingest endpoints. Validation errors (huma uses 422) are answered with 400, and the
// cause of a 5xx is logged, never sent.
func newProblem(status int, msg string, errs ...error) huma.StatusError {
	if status == http.StatusUnprocessableEntity {
		status = http.StatusBadRequest
	}
	p := &problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Detail: msg}
	if status >= http.StatusInternalServerError {
		if err := errors.Join(errs...); err != nil {
			slog.Error("request failed", "status", status, "error", err)
		}
		p.Detail = "internal error"
		return p
	}
	for _, err := range errs {
		if err == nil {
			continue
		}
		detail := &huma.ErrorDetail{Message: err.Error()}
		if d, ok := err.(huma.ErrorDetailer); ok {
			detail = d.ErrorDetail()
		}
		p.Errors = append(p.Errors, domain.FieldError{Field: fieldName(detail.Location), Message: detail.Message})
	}
	return p
}

// fieldName turns a huma location such as "query.limit" or "path.id" into the parameter name.
func fieldName(location string) string {
	for _, prefix := range []string{"path.", "query.", "header."} {
		if name, ok := strings.CutPrefix(location, prefix); ok {
			return name
		}
	}
	return location
}
