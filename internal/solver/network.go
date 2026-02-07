// Package solver provides Cloudflare challenge detection and resolution.
package solver

import (
	"context"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// Maximum number of headers to capture per response to prevent memory exhaustion
const maxNetworkCaptureHeaders = 100

// NetworkCapture provides thread-safe storage for captured HTTP response data.
// It captures the status code and headers from the main document responses,
// handling redirects by storing the final response's data.
type NetworkCapture struct {
	mu         sync.RWMutex
	statusCode int
	headers    map[string]string
	url        string
}

// newNetworkCapture creates a new NetworkCapture instance.
func newNetworkCapture() *NetworkCapture {
	return &NetworkCapture{
		statusCode: 200, // Default fallback
		headers:    make(map[string]string),
	}
}

// SetResponse updates the captured response data.
// Thread-safe: can be called from event listener goroutines.
// Creates a defensive copy of the headers map to prevent race conditions
// if the caller modifies the original map after this call.
func (nc *NetworkCapture) SetResponse(statusCode int, headers map[string]string, url string) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.statusCode = statusCode
	// Create a defensive copy of the headers map
	nc.headers = make(map[string]string, len(headers))
	for k, v := range headers {
		nc.headers[k] = v
	}
	nc.url = url
}

// StatusCode returns the captured HTTP status code.
// Thread-safe: can be called from any goroutine.
func (nc *NetworkCapture) StatusCode() int {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return nc.statusCode
}

// Headers returns a copy of the captured response headers.
// Thread-safe: can be called from any goroutine.
func (nc *NetworkCapture) Headers() map[string]string {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	// Return a copy to prevent race conditions
	result := make(map[string]string, len(nc.headers))
	for k, v := range nc.headers {
		result[k] = v
	}
	return result
}

// URL returns the captured response URL.
// Thread-safe: can be called from any goroutine.
func (nc *NetworkCapture) URL() string {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return nc.url
}

// setupNetworkCapture enables the Network domain and sets up event listeners
// to capture HTTP response data from the main document.
//
// Returns:
//   - NetworkCapture: thread-safe storage for captured response data
//   - cleanup function: MUST be called when done to prevent goroutine leaks
//   - error: if Network domain enable fails
//
// The cleanup function follows the pattern from proxy.go:49-75, using
// WaitGroup + sync.Once + timeout to ensure proper goroutine cleanup.
func setupNetworkCapture(ctx context.Context, page *rod.Page) (*NetworkCapture, func(), error) {
	capture := newNetworkCapture()

	// Enable Network domain to receive network events
	err := proto.NetworkEnable{}.Call(page)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to enable Network domain for response capture")
		// Return capture with defaults - graceful degradation
		return capture, func() {}, nil
	}

	// Create cancellable context for event listeners
	listenerCtx, cancel := context.WithCancel(ctx)
	pageWithCtx := page.Context(listenerCtx)

	// WaitGroup to track event listener goroutines
	var wg sync.WaitGroup

	// Track cleanup state to prevent double-cancel
	var cleanupOnce sync.Once
	cleanupFunc := func() {
		cleanupOnce.Do(func() {
			cancel()
			// Wait for goroutines to finish with timeout
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
				log.Debug().Msg("Network capture listeners cleaned up")
			case <-time.After(5 * time.Second):
				log.Warn().Msg("Timeout waiting for network capture listeners to cleanup")
			}
			// Disable Network domain to stop receiving events
			// This prevents resource leak from lingering event subscriptions
			if err := (proto.NetworkDisable{}).Call(page); err != nil {
				log.Debug().Err(err).Msg("Failed to disable Network domain during cleanup")
			}
		})
	}

	// Listen for Network.responseReceived events
	// We use a buffered channel to signal when the first event is received,
	// which confirms the subscription is active. This avoids the race condition
	// of using a fixed sleep delay.
	listenerActive := make(chan struct{}, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Add panic recovery to prevent goroutine panic from crashing the process
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("Recovered from panic in network capture listener")
			}
		}()

		// Create the event handler - this returns a blocking function
		waitFn := pageWithCtx.EachEvent(func(e *proto.NetworkResponseReceived) bool {
			// Signal that we've received at least one event, confirming subscription is active
			select {
			case listenerActive <- struct{}{}:
			default:
				// Already signaled, don't block
			}

			select {
			case <-listenerCtx.Done():
				return true // Stop listening
			default:
			}

			// Only capture Document responses (main page, not subresources)
			if e.Type != proto.NetworkResourceTypeDocument {
				return false // Continue listening
			}

			// Extract headers from the response
			headers := make(map[string]string)
			if e.Response != nil {
				headerCount := 0
				for key, value := range e.Response.Headers {
					// Enforce header count limit to prevent memory exhaustion
					if headerCount >= maxNetworkCaptureHeaders {
						log.Debug().
							Int("captured", headerCount).
							Int("max", maxNetworkCaptureHeaders).
							Msg("Network capture header limit reached, truncating")
						break
					}
					// NetworkHeaders is map[string]gson.JSON, use Str() to convert
					headers[key] = value.Str()
					headerCount++
				}

				// Capture response data
				statusCode := e.Response.Status
				url := e.Response.URL

				log.Debug().
					Int("status_code", statusCode).
					Str("url", url).
					Int("header_count", len(headers)).
					Msg("Captured Document response")

				capture.SetResponse(statusCode, headers, url)
			}

			return false // Continue listening (handle redirects)
		})

		// Start listening - this blocks until context is canceled or handler returns true
		// The subscription becomes active when waitFn() is called
		waitFn()
	}()

	// Give the goroutine time to set up the subscription.
	// We use a short timeout since EachEvent should subscribe quickly.
	// The actual confirmation comes from receiving events, but we need to
	// let navigation start for events to flow.
	// Fix MEDIUM: Use time.NewTimer with defer Stop() to prevent timer leak
	initTimer := time.NewTimer(100 * time.Millisecond)
	defer initTimer.Stop()

	select {
	case <-initTimer.C:
		// Subscription should be active by now
		log.Debug().Msg("Network capture subscription initialized")
	case <-ctx.Done():
		return capture, cleanupFunc, ctx.Err()
	}

	log.Debug().Msg("Network capture enabled")
	return capture, cleanupFunc, nil
}
