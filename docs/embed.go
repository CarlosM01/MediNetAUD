// Package docs embeds the published API documents so the service can serve them.
package docs

import _ "embed"

// IngestOpenAPI is the OpenAPI document of the ingest contract (POST /events and
// POST /events/batch). It is the single source for those operations in the served spec.
//
//go:embed openapi-ingesta.yaml
var IngestOpenAPI []byte
