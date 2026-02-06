package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// sensitiveParams contains query parameter names that may contain secrets
// and should be redacted in logs.
var sensitiveParams = []string{
	"key", "token", "api_key", "apikey", "password", "secret", "auth",
	"access_token", "refresh_token", "bearer", "credential", "private_key",
}

// Fix #16: sanitizeURLForLogging removes sensitive query parameters from URLs before logging.
func sanitizeURLForLogging(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}

	if parsed.RawQuery == "" {
		return rawURL
	}

	query := parsed.Query()
	redacted := false
	for _, param := range sensitiveParams {
		for key := range query {
			if strings.EqualFold(key, param) {
				query.Set(key, "[REDACTED]")
				redacted = true
			}
		}
	}

	if !redacted {
		return rawURL
	}

	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// Fix #15: maskIP masks an IP address for privacy in logs.
// IPv4: returns x.x.x.0/24 (masks last octet)
// IPv6: returns x:x:x::/48 (masks last 80 bits)
func maskIP(addr string) string {
	// Split host:port if present
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, use addr directly
		host = addr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "[redacted]"
	}

	// IPv4
	if ip4 := ip.To4(); ip4 != nil {
		masked := ip4.Mask(net.CIDRMask(24, 32))
		return masked.String() + "/24"
	}

	// IPv6
	masked := ip.Mask(net.CIDRMask(48, 128))
	return masked.String() + "/48"
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher interface for streaming responses.
// This is required for SSE and other streaming use cases.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Logging returns middleware that logs request details.
// Fix #15, #16: Masks IP addresses and sanitizes URLs in logs for privacy.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log after completion
		duration := time.Since(start)

		log.Info().
			Str("method", r.Method).
			Str("path", sanitizeURLForLogging(r.URL.String())).
			Str("remote_addr", maskIP(r.RemoteAddr)).
			Int("status", wrapped.statusCode).
			Dur("duration", duration).
			Msg("Request completed")
	})
}
