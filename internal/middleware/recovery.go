// Package middleware provides HTTP middleware components.
package middleware

import (
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// sanitizeStackTrace removes potentially sensitive file paths from stack traces.
// This prevents disclosure of internal server structure in logs that might be
// forwarded to external log aggregation services.
func sanitizeStackTrace(stack []byte) string {
	// Convert to string and split into lines
	lines := strings.Split(string(stack), "\n")
	sanitized := make([]string, 0, len(lines))

	for _, line := range lines {
		// Keep goroutine info and function names
		// Redact full file paths but keep file names
		if strings.Contains(line, "/") && strings.Contains(line, ".go:") {
			// Extract just the filename and line number
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				lastPart := parts[len(parts)-1]
				// Preserve indentation
				indent := ""
				for _, c := range line {
					if c == '\t' || c == ' ' {
						indent += string(c)
					} else {
						break
					}
				}
				sanitized = append(sanitized, indent+lastPart)
				continue
			}
		}
		sanitized = append(sanitized, line)
	}

	return strings.Join(sanitized, "\n")
}

// headerChecker is an optional interface for response writers that track header state.
type headerChecker interface {
	Written() bool
}

// Recovery returns middleware that recovers from panics and logs the error.
// Fix #27: Simplified - removed dead code (responseStarted was never set to true).
// Sanitizes stack traces to prevent sensitive path disclosure.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()
				log.Error().
					Interface("error", err).
					Str("stack", sanitizeStackTrace(stack)).
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("Panic recovered")

				// Only write error response if headers haven't been sent
				// Check if response writer supports tracking header state
				if hc, ok := w.(headerChecker); ok && hc.Written() {
					log.Warn().Msg("Cannot write error response - headers already sent")
					return
				}

				// Try to write error response (may fail if headers already sent)
				writeErrorResponse(w, http.StatusInternalServerError, "Internal server error", startTime)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
