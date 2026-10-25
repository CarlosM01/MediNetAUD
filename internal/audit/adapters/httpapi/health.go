package httpapi

import (
	"encoding/json"
	"net/http"
)

// health is the liveness probe: it answers 200 while the process can serve requests.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
