package httpapi

// Body limits of the ingest contract §1.
const (
	maxEventBody = 64 * 1024   // POST /events
	maxBatchBody = 1024 * 1024 // POST /events/batch
)
