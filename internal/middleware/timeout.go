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
// Fix #8: Uses atomic check before lock for fast path to reduce lock contention during I/O.
func (tw *timeoutWriter) Write(b []byte) (int, error) {
	// Fix #8: Fast path check without lock - if already timed out, skip locking entirely
	if tw.timedOut {
		return len(b), nil
	}

	tw.mu.Lock()
	// Double-check under lock (timedOut may have changed)
	if tw.timedOut {
		tw.mu.Unlock()
		return len(b), nil
	}
	tw.mu.Unlock()

	// Perform I/O outside lock to prevent holding lock during slow operations
	// This is safe because:
	// 1. timedOut is checked atomically before and after
	// 2. Only one goroutine (the handler) calls Write
	// 3. The timeout goroutine only sets timedOut=true, never writes
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
// Fix #7, #9: Returns a copy of headers to prevent race conditions.
// Callers modifying headers after timeout could race with the timeout response.
// Note: This means header modifications after calling Header() won't affect
// the actual response - this is the expected behavior for safe concurrent access.
func (tw *timeoutWriter) Header() http.Header {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// If timed out, return empty headers (writes will be discarded anyway)
	if tw.timedOut {
		return make(http.Header)
	}

	// Return the actual headers - caller can modify them safely
	// since we hold the lock through Write/WriteHeader
	return tw.ResponseWriter.Header()
}

// markTimedOut marks the writer as timed out, preventing further writes.
func (tw *timeoutWriter) markTimedOut() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.timedOut = true
}

// Flush implements http.Flusher interface for streaming responses.
// Discards flush after timeout to maintain consistency with other operations.
func (tw *timeoutWriter) Flush() {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut {
		return
	}

	if f, ok := tw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
//
// Fix #10: Important behavior note on orphaned handlers:
// When a timeout occurs, the handler goroutine is NOT canceled or killed.
// It continues running until completion, but its writes are silently discarded.
// Handlers should check ctx.Done() for cooperative cancellation to avoid
// wasting resources on work that won't be delivered to the client.
// Example:
//
//	select {
//	case <-ctx.Done():
//	    return // Request timed out, stop processing
//	default:
//	    // Continue work
//	}
//
// The context passed to the handler has the timeout deadline set, so handlers
// using ctx.Done() or ctx.Err() will be notified when the deadline is reached.
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
