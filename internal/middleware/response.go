package middleware

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/user/flaresolverr-go/pkg/version"
)

// errorResponse represents a consistent error response format.
// Matches the types.Response structure for API consistency.
type errorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	StartTime int64  `json:"startTimestamp"`
	EndTime   int64  `json:"endTimestamp"`
	Version   string `json:"version"`
}

// writeErrorResponse writes a consistent error response with proper fields.
// startTime should be the time when the request started processing.
func writeErrorResponse(w http.ResponseWriter, statusCode int, message string, startTime time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := errorResponse{
		Status:    "error",
		Message:   message,
		StartTime: startTime.UnixMilli(),
		EndTime:   time.Now().UnixMilli(),
		Version:   version.Full(),
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error().Err(err).Str("message", message).Msg("Failed to encode middleware error response")
	}
}
