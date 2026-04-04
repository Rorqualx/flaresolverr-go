// Package dashboard provides a TUI dashboard for monitoring FlareSolverr.
package dashboard

import (
	"sync"
	"time"
)

// maxEvents is the ring buffer capacity.
const maxEvents = 1000

// RequestEvent represents a single completed HTTP request.
type RequestEvent struct {
	Timestamp  time.Time
	Method     string
	Path       string
	StatusCode int
	Latency    time.Duration
}

// EventBuffer is a bounded ring buffer for request events.
// Writers (HTTP goroutines) and readers (dashboard goroutine) are synchronized via mutex.
type EventBuffer struct {
	mu     sync.Mutex
	events []RequestEvent
	head   int   // next write position
	count  int   // current number of events stored (up to maxEvents)
	total  int64 // total events ever recorded
}

// NewEventBuffer creates a ring buffer with pre-allocated capacity.
func NewEventBuffer() *EventBuffer {
	return &EventBuffer{
		events: make([]RequestEvent, maxEvents),
	}
}

// Record appends a request event to the buffer.
// Called from HTTP middleware goroutines.
func (b *EventBuffer) Record(e RequestEvent) {
	b.mu.Lock()
	b.events[b.head] = e
	b.head = (b.head + 1) % maxEvents
	if b.count < maxEvents {
		b.count++
	}
	b.total++
	b.mu.Unlock()
}

// Snapshot returns the most recent n events (newest first) and the
// total event count since startup. The returned slice is a copy.
func (b *EventBuffer) Snapshot(n int) ([]RequestEvent, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if n > b.count {
		n = b.count
	}
	if n == 0 {
		return nil, b.total
	}

	result := make([]RequestEvent, n)
	for i := 0; i < n; i++ {
		// Walk backwards from the most recent entry
		idx := (b.head - 1 - i + maxEvents) % maxEvents
		result[i] = b.events[idx]
	}
	return result, b.total
}

// Total returns the total number of events ever recorded.
func (b *EventBuffer) Total() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}
