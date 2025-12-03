package metrics

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tinfoilsh/tfshim/config"
)

func HandleACPI(externalConfig *config.ExternalConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if externalConfig.ACPIAPIKey != "" {
			apiKey := strings.TrimPrefix(
				r.Header.Get("Authorization"),
				"Bearer ",
			)
			if apiKey != externalConfig.ACPIAPIKey {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
