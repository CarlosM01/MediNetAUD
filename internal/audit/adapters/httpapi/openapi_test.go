package httpapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// specOperation is the part of an OpenAPI operation the tests inspect.
type specOperation struct {
	OperationID string                `json:"operationId"`
	Summary     string                `json:"summary"`
	Description string                `json:"description"`
	Security    []map[string][]string `json:"security"`
	Parameters  []struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Schema      map[string]any `json:"schema"`
	} `json:"parameters"`
	Responses map[string]map[string]any `json:"responses"`
}

type spec struct {
	OpenAPI    string                              `json:"openapi"`
	Paths      map[string]map[string]specOperation `json:"paths"`
	Components struct {
		Schemas         map[string]map[string]any `json:"schemas"`
		Responses       map[string]map[string]any `json:"responses"`
		SecuritySchemes map[string]map[string]any `json:"securitySchemes"`
	} `json:"components"`
}

func fetchSpec(t *testing.T) (spec, string) {
	t.Helper()
	rec := get(t, newQueryRouter(&fakeReader{}), "/openapi.json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json = %d; body %s", rec.Code, rec.Body)
	}
	var s spec
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return s, rec.Body.String()
}

func TestOpenAPIDocumentsEveryOperation(t *testing.T) {
	s, raw := fetchSpec(t)
	if !strings.HasPrefix(s.OpenAPI, "3.1") {
		t.Errorf("openapi = %q, want 3.1", s.OpenAPI)
	}

	hmac := []string{"audClientId", "audTimestamp", "audSignature"}
	tests := []struct {
		method, path string
		codes        []string
		security     []string
	}{
		{"get", "/health", []string{"200"}, nil},
		{"post", "/api/v1/events", []string{"202", "400", "401", "403", "413", "415", "429", "500", "503"}, hmac},
		{"post", "/api/v1/events/batch", []string{"202", "400", "401", "403", "413", "415", "429", "500", "503"}, hmac},
		{"get", "/api/v1/events", []string{"200", "400", "401", "403", "500"}, []string{bearerScheme}},
		{"get", "/api/v1/events/{id}", []string{"200", "400", "401", "403", "404", "500"}, []string{bearerScheme}},
		{"get", "/api/v1/stats/suspicious", []string{"200", "400", "401", "403", "500"}, []string{bearerScheme}},
		{"get", "/api/v1/integrity/verify", []string{"200", "400", "401", "403", "500"}, []string{bearerScheme}},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			op, ok := s.Paths[tt.path][tt.method]
			if !ok {
				t.Fatalf("operation missing; paths: %v", keys(s.Paths))
			}
			if op.OperationID == "" || op.Summary == "" || op.Description == "" {
				t.Errorf("operationId/summary/description = %q/%q/%q, want all set", op.OperationID, op.Summary, op.Description)
			}
			if got := keys(op.Responses); !slices.Equal(got, tt.codes) {
				t.Errorf("responses = %v, want %v", got, tt.codes)
			}
			var got []string
			for _, req := range op.Security {
				got = append(got, keys(req)...)
			}
			slices.Sort(got)
			want := slices.Sorted(slices.Values(tt.security))
			if tt.security == nil {
				want = nil
			}
			if !slices.Equal(got, want) {
				t.Errorf("security = %v, want %v", got, want)
			}
			for _, p := range op.Parameters {
				if p.Description == "" && p.Schema["description"] == nil {
					t.Errorf("parameter %s has no description", p.Name)
				}
			}
		})
	}

	if strings.Contains(raw, `"422"`) {
		t.Error("the document lists 422, but validation errors are answered with 400")
	}
	for _, name := range append(hmac, bearerScheme) {
		if _, ok := s.Components.SecuritySchemes[name]; !ok {
			t.Errorf("security scheme %s missing", name)
		}
	}
}

func TestOpenAPIErrorsAreProblemDetails(t *testing.T) {
	s, _ := fetchSpec(t)
	if props, _ := s.Components.Schemas["Problem"]["properties"].(map[string]any); props["errors"] == nil || props["status"] == nil {
		t.Fatalf("Problem schema = %v, want the RFC 7807 shape with errors", s.Components.Schemas["Problem"])
	}
	for path, ops := range s.Paths {
		for method, op := range ops {
			for code, resp := range op.Responses {
				if code < "400" {
					continue
				}
				if ref, ok := resp["$ref"].(string); ok {
					resp = s.Components.Responses[strings.TrimPrefix(ref, "#/components/responses/")]
				}
				content, _ := resp["content"].(map[string]any)
				media, ok := content["application/problem+json"].(map[string]any)
				if !ok {
					t.Errorf("%s %s %s: no application/problem+json content", method, path, code)
					continue
				}
				schema, _ := media["schema"].(map[string]any)
				if schema["$ref"] != "#/components/schemas/Problem" {
					t.Errorf("%s %s %s: schema = %v, want Problem", method, path, code, schema)
				}
				if media["example"] == nil && media["examples"] == nil {
					t.Errorf("%s %s %s: no example", method, path, code)
				}
			}
		}
	}
}

// TestOpenAPIEveryOperationHasExamples checks that /docs can show a ready-to-use value for every
// parameter, request body and response, so a consumer does not have to guess the format.
func TestOpenAPIEveryOperationHasExamples(t *testing.T) {
	_, raw := fetchSpec(t)
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	resolve := func(v any) map[string]any {
		m, _ := v.(map[string]any)
		for m["$ref"] != nil {
			var target any = doc
			for _, part := range strings.Split(strings.TrimPrefix(m["$ref"].(string), "#/"), "/") {
				target = target.(map[string]any)[part]
			}
			m, _ = target.(map[string]any)
		}
		return m
	}
	hasExample := func(m map[string]any) bool {
		return m["example"] != nil || m["examples"] != nil
	}
	checkContent := func(where string, content any) {
		for mediaType, media := range resolve(content) {
			if !hasExample(resolve(media)) {
				t.Errorf("%s %s: no example", where, mediaType)
			}
		}
	}

	for path, item := range resolve(doc["paths"]) {
		for method, rawOp := range resolve(item) {
			op := resolve(rawOp)
			where := method + " " + path
			params, _ := op["parameters"].([]any)
			for _, rawParam := range params {
				p := resolve(rawParam)
				schema := resolve(p["schema"])
				if !hasExample(p) && !hasExample(schema) && schema["enum"] == nil && schema["default"] == nil {
					t.Errorf("%s parameter %v: no example, enum or default", where, p["name"])
				}
			}
			if body := resolve(op["requestBody"]); body != nil {
				checkContent(where+" request body", body["content"])
			}
			for code, resp := range resolve(op["responses"]) {
				checkContent(where+" "+code, resolve(resp)["content"])
			}
		}
	}
}

func TestOpenAPIServedAsYAML(t *testing.T) {
	rec := get(t, newQueryRouter(&fakeReader{}), "/openapi.yaml", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /openapi.yaml = %d", rec.Code)
	}
	var s spec
	var doc map[string]any
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Paths["/api/v1/events"]["post"]; !ok {
		t.Error("yaml document misses the ingest operation")
	}
}

func TestDocsServeSwaggerUI(t *testing.T) {
	rec := get(t, NewRouter(Dependencies{}), "/docs", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SwaggerUIBundle") || !strings.Contains(rec.Body.String(), "/openapi.json") {
		t.Fatalf("GET /docs = %d; body %.300s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func keys[V any](m map[string]V) []string {
	return slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
}
