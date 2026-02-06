package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
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
	closeOnce  sync.Once      // Fix #28: Ensure Close is idempotent
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
	// Fix: Check for empty map to prevent scanning empty map
	if len(rl.clients) == 0 {
		return
	}

	var oldestIP string
	var oldestTime time.Time
	first := true

	for ip, c := range rl.clients {
		if first || c.lastReset.Before(oldestTime) {
			oldestIP = ip
			oldestTime = c.lastReset
			first = false
		}
	}

	if oldestIP != "" {
		delete(rl.clients, oldestIP)
	}
}

// Close stops the cleanup routine and waits for it to finish.
// Fix #28: Uses sync.Once to make Close idempotent and prevent panic on double-close.
func (rl *RateLimiter) Close() {
	rl.closeOnce.Do(func() {
		close(rl.stopCh)
		rl.wg.Wait()
	})
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

// RateLimiterMiddleware wraps RateLimiter with cleanup support for graceful shutdown.
// Call Close() on shutdown to stop the cleanup goroutine.
type RateLimiterMiddleware struct {
	limiter *RateLimiter
	handler func(http.Handler) http.Handler
}

// Close stops the rate limiter's cleanup routine.
func (m *RateLimiterMiddleware) Close() {
	if m.limiter != nil {
		m.limiter.Close()
	}
}

// Handler returns the middleware handler function.
func (m *RateLimiterMiddleware) Handler() func(http.Handler) http.Handler {
	return m.handler
}

// RateLimitWithTrust returns middleware that limits requests per IP with configurable proxy trust.
// trustProxy: set to true only if running behind a trusted reverse proxy (nginx, cloudflare, etc.)
// WARNING: Enabling trustProxy when not behind a proxy allows attackers to bypass rate limiting
// by spoofing X-Forwarded-For headers.
//
// Fix #16: See RateLimit() for singleton usage notes - call ONCE and reuse.
//
// Fix #29: Deprecated: Use NewRateLimitMiddleware for proper cleanup support.
// This function creates a RateLimiter with a background goroutine that cannot be stopped,
// which causes goroutine leaks. Use NewRateLimitMiddleware().Handler() instead and call
// Close() on shutdown.
func RateLimitWithTrust(requestsPerMinute int, trustProxy bool) func(http.Handler) http.Handler {
	log.Warn().Msg("RateLimitWithTrust is deprecated and leaks goroutines - use NewRateLimitMiddleware instead")

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

// NewRateLimitMiddleware creates a rate limiter middleware with cleanup support.
// Call Close() on the returned middleware during shutdown to prevent goroutine leaks.
func NewRateLimitMiddleware(requestsPerMinute int, trustProxy bool) *RateLimiterMiddleware {
	limiter := NewRateLimiter(requestsPerMinute, time.Minute, trustProxy)

	m := &RateLimiterMiddleware{
		limiter: limiter,
	}

	m.handler = func(next http.Handler) http.Handler {
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

	return m
}

// normalizeIP validates and normalizes an IP address string.
// Returns a canonical IP string or the original string if invalid.
// This prevents bypass attempts using IPv6 variations.
func normalizeIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return ""
	}

	// Parse and normalize the IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Invalid IP - return as-is for logging but may cause issues
		return ipStr
	}

	// Normalize IPv4-mapped IPv6 addresses to IPv4
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}

	// Return canonical IPv6 form
	return ip.String()
}

// getClientIP extracts the client IP from the request.
// When trustProxy is false (default), only RemoteAddr is used to prevent IP spoofing.
// When trustProxy is true, X-Forwarded-For and X-Real-IP headers are checked first.
// Fix: Validates and normalizes IP addresses to prevent bypasses.
func getClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// Check X-Forwarded-For header (may contain multiple IPs)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP (leftmost = original client)
			var ipStr string
			if idx := strings.Index(xff, ","); idx > 0 {
				ipStr = xff[:idx]
			} else {
				ipStr = xff
			}
			// Validate and normalize the extracted IP
			normalized := normalizeIP(ipStr)
			if normalized != "" {
				return normalized
			}
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			normalized := normalizeIP(xri)
			if normalized != "" {
				return normalized
			}
		}
	}

	// Use RemoteAddr (always trusted as it's from the TCP connection)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return normalizeIP(ip)
}
