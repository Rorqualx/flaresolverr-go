package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxClients is the maximum number of tracked clients to prevent memory exhaustion.
// At approximately 100 bytes per client, 10000 clients = ~1MB memory.
const maxClients = 10000

// RateLimiter implements a token bucket rate limiter per IP.
type RateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*client
	rate       int           // requests per window
	window     time.Duration // time window
	cleanup    time.Duration // cleanup interval for stale entries
	trustProxy bool          // whether to trust X-Forwarded-For headers
	stopCh     chan struct{}
	wg         sync.WaitGroup // Track background goroutines for clean shutdown
}

type client struct {
	tokens    int
	lastReset time.Time
}

// NewRateLimiter creates a new rate limiter.
// rate: maximum requests per window
// window: time window for rate limiting
// trustProxy: whether to trust X-Forwarded-For and X-Real-IP headers
func NewRateLimiter(rate int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		clients:    make(map[string]*client),
		rate:       rate,
		window:     window,
		cleanup:    5 * time.Minute,
		trustProxy: trustProxy,
		stopCh:     make(chan struct{}),
	}

	// Start cleanup routine with WaitGroup tracking for clean shutdown
	rl.wg.Add(1)
	go func() {
		defer rl.wg.Done()
		rl.cleanupRoutine()
	}()

	return rl
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	c, exists := rl.clients[ip]

	if !exists {
		// Check if we've reached max clients
		if len(rl.clients) >= maxClients {
			// Evict oldest client to make room
			rl.evictOldest()
		}

		rl.clients[ip] = &client{
			tokens:    rl.rate - 1,
			lastReset: now,
		}
		return true
	}

	// Reset tokens if window has passed
	if now.Sub(c.lastReset) >= rl.window {
		c.tokens = rl.rate - 1
		c.lastReset = now
		return true
	}

	// Check if tokens available
	if c.tokens > 0 {
		c.tokens--
		return true
	}

	return false
}

// cleanupRoutine removes stale client entries.
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanupStale()
		case <-rl.stopCh:
			return
		}
	}
}

func (rl *RateLimiter) cleanupStale() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	staleThreshold := 2 * rl.window

	for ip, c := range rl.clients {
		if now.Sub(c.lastReset) > staleThreshold {
			delete(rl.clients, ip)
		}
	}
}

// evictOldest removes the oldest client entry to make room for new ones.
// Must be called while holding rl.mu.
func (rl *RateLimiter) evictOldest() {
	var oldestIP string
	var oldestTime time.Time

	for ip, c := range rl.clients {
		if oldestIP == "" || c.lastReset.Before(oldestTime) {
			oldestIP = ip
			oldestTime = c.lastReset
		}
	}

	if oldestIP != "" {
		delete(rl.clients, oldestIP)
	}
}

// Close stops the cleanup routine and waits for it to finish.
func (rl *RateLimiter) Close() {
	close(rl.stopCh)
	rl.wg.Wait()
}

// GetClientIP extracts the client IP from the request.
func (rl *RateLimiter) GetClientIP(r *http.Request) string {
	return getClientIP(r, rl.trustProxy)
}

// RateLimit returns middleware that limits requests per IP.
// trustProxy: set to true only if running behind a trusted reverse proxy
//
// Fix #16: IMPORTANT - Singleton usage note:
// This function creates a new RateLimiter instance each time it's called.
// For proper rate limiting, call this function ONCE during server initialization
// and reuse the returned middleware for all routes. Creating multiple instances
// would result in separate rate limit counters, effectively disabling rate limiting.
//
// Example (correct):
//
//	rateLimitMiddleware := middleware.RateLimit(60) // Create once
//	mux.Use(rateLimitMiddleware) // Reuse for all routes
//
// Example (incorrect - creates separate counters):
//
//	mux.Handle("/api", middleware.RateLimit(60)(apiHandler))
//	mux.Handle("/health", middleware.RateLimit(60)(healthHandler)) // Separate counter!
func RateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
	return RateLimitWithTrust(requestsPerMinute, false)
}

// RateLimitWithTrust returns middleware that limits requests per IP with configurable proxy trust.
// trustProxy: set to true only if running behind a trusted reverse proxy (nginx, cloudflare, etc.)
// WARNING: Enabling trustProxy when not behind a proxy allows attackers to bypass rate limiting
// by spoofing X-Forwarded-For headers.
//
// Fix #16: See RateLimit() for singleton usage notes - call ONCE and reuse.
func RateLimitWithTrust(requestsPerMinute int, trustProxy bool) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(requestsPerMinute, time.Minute, trustProxy)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
			ip := limiter.GetClientIP(r)

			if !limiter.Allow(ip) {
				w.Header().Set("Retry-After", "60")
				writeErrorResponse(w, http.StatusTooManyRequests, "Rate limit exceeded. Please try again later.", startTime)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request.
// When trustProxy is false (default), only RemoteAddr is used to prevent IP spoofing.
// When trustProxy is true, X-Forwarded-For and X-Real-IP headers are checked first.
func getClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Check X-Forwarded-For header (may contain multiple IPs)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP (leftmost = original client)
			if idx := strings.Index(xff, ","); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// Use RemoteAddr (always trusted as it's from the TCP connection)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
