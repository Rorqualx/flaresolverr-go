package middleware

import (
	"net/http"
)

// CORSConfig holds CORS configuration options.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins.
	// If empty, all origins are allowed (wildcard).
	AllowedOrigins []string
}

// CORS returns middleware that adds CORS headers to responses.
// If allowedOrigins is empty, allows all origins (backward compatible but less secure).
// If allowedOrigins is set, only those origins are allowed and the specific
// origin is returned instead of wildcard.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	// Build a set for O(1) lookup
	allowedSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		allowedSet[origin] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Determine which origin to allow
			var allowOrigin string
			if len(allowedSet) == 0 {
				// No restrictions - allow all (backward compatible)
				allowOrigin = "*"
			} else if origin != "" {
				// Check if origin is in allowed list
				if _, ok := allowedSet[origin]; ok {
					// Return the specific origin, not wildcard
					// This is more secure and required for credentials
					allowOrigin = origin
				}
				// If origin not in list, don't set the header (browser will block)
			}

			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				// Always set Vary header to prevent caching issues with CDNs
				w.Header().Set("Vary", "Origin")
			}

			// Handle preflight
			if r.Method == http.MethodOptions {
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
