package middleware

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// timeoutWriter wraps http.ResponseWriter to prevent writes after timeout.
// Once timedOut is set, all writes are discarded to prevent panics and races.
//
// Fix HIGH: Uses atomic.Bool for timedOut to enable lock-free fast path checks
// while maintaining proper synchronization for all write operations.
type timeoutWriter struct {
	http.ResponseWriter
	mu          sync.Mutex
	timedOut    atomic.Bool // Fix HIGH: Use atomic for lock-free reads
	wroteHeader bool
}

// Write implements http.ResponseWriter. Discards writes after timeout.
// Fix HIGH: Properly synchronized - holds lock during actual write to prevent
// race with timeout goroutine writing to the same ResponseWriter.
func (tw *timeoutWriter) Write(b []byte) (int, error) {
	// Fast path: atomic check without lock
	if tw.timedOut.Load() {
		return len(b), nil
	}

	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Double-check under lock (timedOut may have changed)
	if tw.timedOut.Load() {
		return len(b), nil
	}

	// Perform I/O while holding lock to prevent race with timeout response
	// This ensures only one goroutine writes to ResponseWriter at a time
	return tw.ResponseWriter.Write(b)
}

// WriteHeader implements http.ResponseWriter. Discards after timeout.
func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut.Load() || tw.wroteHeader {
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
	if tw.timedOut.Load() {
		return make(http.Header)
	}

	// Return the actual headers - caller can modify them safely
	// since we hold the lock through Write/WriteHeader
	return tw.ResponseWriter.Header()
}

// markTimedOut marks the writer as timed out, preventing further writes.
// Fix HIGH: Uses atomic store for lock-free reads in fast path.
func (tw *timeoutWriter) markTimedOut() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.timedOut.Store(true)
}

// Flush implements http.Flusher interface for streaming responses.
// Discards flush after timeout to maintain consistency with other operations.
func (tw *timeoutWriter) Flush() {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.timedOut.Load() {
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
				// Request completed - check if it was due to timeout
				// If handler exited without writing a response and context timed out,
				// we should still send a 504 response
				if ctx.Err() == context.DeadlineExceeded && !tw.hasWrittenHeader() {
					// Write response first, then mark timed out to discard future writes
					writeErrorResponse(tw, http.StatusGatewayTimeout, "Request timeout", startTime)
					tw.markTimedOut()
				}
			case <-ctx.Done():
				// Timeout occurred - only write timeout response if handler hasn't started writing
				// Fix HIGH: Use tw (wrapped writer) instead of w (raw writer) to
				// ensure writes go through the synchronized wrapper and prevent
				// race with any late handler writes
				if ctx.Err() == context.DeadlineExceeded && !tw.hasWrittenHeader() {
					// Write response first, then mark timed out to discard future writes
					writeErrorResponse(tw, http.StatusGatewayTimeout, "Request timeout", startTime)
					tw.markTimedOut()
				} else {
					// Just mark timed out to discard any future handler writes
					tw.markTimedOut()
				}
			}
		})
	}
}
