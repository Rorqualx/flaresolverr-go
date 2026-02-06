package middleware

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

// CORSConfig holds CORS configuration options.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins.
	// If empty, all origins are allowed (wildcard).
	AllowedOrigins []string
}

// CORS returns middleware that adds CORS headers to responses.
// Fix #17: If allowedOrigins is empty, rejects cross-origin requests (secure default).
// If allowedOrigins is set, only those origins are allowed and the specific
// origin is returned instead of wildcard.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	// Build a set for O(1) lookup
	allowedSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		allowedSet[origin] = struct{}{}
	}

	// Fix #17: Log warning at startup if no origins configured
	if len(allowedSet) == 0 {
		log.Warn().Msg("CORS_ALLOWED_ORIGINS not set - all cross-origin requests will be rejected (secure default)")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Determine which origin to allow
			var allowOrigin string
			if len(allowedSet) == 0 {
				// Fix #17: SECURE DEFAULT - reject all cross-origin requests
				// Don't set any CORS headers, browser will block the request
				if origin != "" {
					// Fix #43: Log rejected origins at debug level
					log.Debug().Str("origin", origin).Msg("CORS request rejected (no allowed origins configured)")
				}
			} else if origin != "" {
				// Check if origin is in allowed list
				if _, ok := allowedSet[origin]; ok {
					// Return the specific origin, not wildcard
					// This is more secure and required for credentials
					allowOrigin = origin
				} else {
					// Fix #43: Log rejected origin at debug level
					log.Debug().Str("origin", origin).Msg("CORS request from non-allowed origin")
				}
			}

			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				// Fix 3.17: Include X-API-Key in allowed headers for CORS preflight
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")

				// Add credentials support for specific origins
				// This is required for cookies and auth headers in cross-origin requests
				w.Header().Set("Access-Control-Allow-Credentials", "true")

				// Always set Vary header to prevent caching issues with CDNs
				w.Header().Set("Vary", "Origin")
			}

			// Handle preflight
			if r.Method == http.MethodOptions {
				// Add security headers to preflight response
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("Cache-Control", "no-store, max-age=0")
				// Fix #30: Reduce preflight cache from 2 hours to 10 minutes
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders returns middleware that adds security-related HTTP headers.
// These headers help protect against common web vulnerabilities.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent caching of sensitive responses
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		next.ServeHTTP(w, r)
	})
}
