package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter per IP.
type RateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*client
	rate       int           // requests per window
	window     time.Duration // time window
	cleanup    time.Duration // cleanup interval for stale entries
	trustProxy bool          // whether to trust X-Forwarded-For headers
	stopCh     chan struct{}
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

	go rl.cleanupRoutine()

	return rl
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	c, exists := rl.clients[ip]

	if !exists {
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

// Close stops the cleanup routine.
func (rl *RateLimiter) Close() {
	close(rl.stopCh)
}

// GetClientIP extracts the client IP from the request.
func (rl *RateLimiter) GetClientIP(r *http.Request) string {
	return getClientIP(r, rl.trustProxy)
}

// RateLimit returns middleware that limits requests per IP.
// trustProxy: set to true only if running behind a trusted reverse proxy
func RateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
	return RateLimitWithTrust(requestsPerMinute, false)
}

// RateLimitWithTrust returns middleware that limits requests per IP with configurable proxy trust.
// trustProxy: set to true only if running behind a trusted reverse proxy (nginx, cloudflare, etc.)
// WARNING: Enabling trustProxy when not behind a proxy allows attackers to bypass rate limiting
// by spoofing X-Forwarded-For headers.
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
