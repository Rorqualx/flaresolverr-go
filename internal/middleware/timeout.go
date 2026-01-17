package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// timeoutWriter wraps http.ResponseWriter to prevent writes after timeout.
// Once timedOut is set, all writes are discarded to prevent panics and races.
type timeoutWriter struct {
	http.ResponseWriter
	mu          sync.Mutex
	timedOut    bool
	wroteHeader bool
}

// Write implements http.ResponseWriter. Discards writes after timeout.
func (tw *timeoutWriter) Write(b []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut {
		// Discard write after timeout - return success to avoid handler errors
		return len(b), nil
	}
	return tw.ResponseWriter.Write(b)
}

// WriteHeader implements http.ResponseWriter. Discards after timeout.
func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut || tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.ResponseWriter.WriteHeader(code)
}

// Header implements http.ResponseWriter.
func (tw *timeoutWriter) Header() http.Header {
	return tw.ResponseWriter.Header()
}

// markTimedOut marks the writer as timed out, preventing further writes.
func (tw *timeoutWriter) markTimedOut() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.timedOut = true
}

// hasWrittenHeader returns true if WriteHeader was called before timeout.
func (tw *timeoutWriter) hasWrittenHeader() bool {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	return tw.wroteHeader
}

// Timeout returns middleware that adds a timeout to the request context.
// When timeout occurs before handler completes, a 504 Gateway Timeout is sent.
// The handler goroutine continues but its writes are safely discarded.
func Timeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Wrap the response writer to safely handle timeout
			tw := &timeoutWriter{ResponseWriter: w}

			// Create a channel to signal completion
			done := make(chan struct{})

			go func() {
				next.ServeHTTP(tw, r.WithContext(ctx))
				close(done)
			}()

			select {
			case <-done:
				// Request completed normally - nothing more to do
			case <-ctx.Done():
				// Timeout occurred - mark writer to discard future writes
				tw.markTimedOut()

				// Only write timeout response if handler hasn't started writing
				if ctx.Err() == context.DeadlineExceeded && !tw.hasWrittenHeader() {
					writeErrorResponse(w, http.StatusGatewayTimeout, "Request timeout", startTime)
				}
			}
		})
	}
}
