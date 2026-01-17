// Package middleware provides HTTP middleware for the FlareSolverr server.
package middleware

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// APIKey returns middleware that validates API key authentication.
// If API key authentication is disabled in config, requests pass through unchanged.
// Health and metrics endpoints are always allowed without authentication.
func APIKey(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if API key auth is disabled
			if !cfg.APIKeyEnabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip health and metrics endpoints - they should always be accessible
			// for monitoring and load balancer health checks
			if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			// Get API key from header first, then query parameter
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				apiKey = r.URL.Query().Get("api_key")
			}

			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(cfg.APIKey)) != 1 {
				writeErrorResponse(w, http.StatusUnauthorized, "Invalid or missing API key", time.Now())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
