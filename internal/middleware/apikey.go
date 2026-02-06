// Package middleware provides HTTP middleware for the FlareSolverr server.
package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// APIKey returns middleware that validates API key authentication.
// If API key authentication is disabled in config, requests pass through unchanged.
// Health and metrics endpoints are always allowed without authentication.
//
// Security: API keys are only accepted via the X-API-Key header.
// Query parameter support was removed because query strings appear in:
// - Server access logs
// - Browser history
// - Referrer headers (may leak to third-party sites)
// - Proxy logs
func APIKey(cfg *config.Config) func(http.Handler) http.Handler {
	// Pre-compute the hash of the expected API key for constant-time comparison.
	// This ensures consistent comparison time regardless of input length,
	// preventing timing attacks that could leak information about the key length.
	expectedHash := sha256.Sum256([]byte(cfg.APIKey))

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

			// Get API key from header only - query parameter support removed for security
			// Query parameters appear in access logs, browser history, and referrer headers
			apiKey := r.Header.Get("X-API-Key")

			// Hash the provided key and compare using constant-time comparison.
			// This prevents timing attacks by:
			// 1. Always comparing fixed-size hashes (32 bytes)
			// 2. Using constant-time comparison for the hash values
			// Even if the provided key is empty or much longer, comparison time is constant.
			providedHash := sha256.Sum256([]byte(apiKey))
			if subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) != 1 {
				writeErrorResponse(w, http.StatusUnauthorized, "Invalid or missing API key", time.Now())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
