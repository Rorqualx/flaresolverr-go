package middleware

import (
	"net/http"
	"net/netip"
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
	mu        sync.Mutex
	clients   map[string]*client
	rate      int           // requests per window
	window    time.Duration // time window
	cleanup   time.Duration // cleanup interval for stale entries
	trust     ProxyTrust    // which peers may report the client address in headers
	stopCh    chan struct{}
	wg        sync.WaitGroup // Track background goroutines for clean shutdown
	closeOnce sync.Once      // Fix #28: Ensure Close is idempotent
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
	return NewRateLimiterWithTrust(rate, window, ProxyTrust{Enabled: trustProxy})
}

// ProxyTrust says whose word is taken for a request's client address.
//
// X-Forwarded-For is written by whoever sent the request, so it is only
// meaningful when the request came from a reverse proxy the operator runs.
type ProxyTrust struct {
	// Enabled turns on use of X-Forwarded-For / X-Real-IP (TRUST_PROXY).
	Enabled bool

	// Proxies lists the reverse proxies' addresses (TRUSTED_PROXIES). When set,
	// the headers are used only for requests arriving from one of them, and
	// X-Forwarded-For is read from the right, skipping trusted hops, so a
	// client cannot choose its own key by prepending addresses.
	//
	// When empty (with Enabled), the leftmost X-Forwarded-For entry is believed
	// from any peer: the legacy behavior, which a client can spoof.
	Proxies []netip.Prefix
}

// NewRateLimiterWithTrust creates a new rate limiter with explicit proxy trust.
func NewRateLimiterWithTrust(rate int, window time.Duration, trust ProxyTrust) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*client),
		rate:    rate,
		window:  window,
		cleanup: 5 * time.Minute,
		trust:   trust,
		stopCh:  make(chan struct{}),
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
	return clientKey(r, rl.trust)
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
func NewRateLimitMiddleware(requestsPerMinute int, trust ProxyTrust) *RateLimiterMiddleware {
	limiter := NewRateLimiterWithTrust(requestsPerMinute, time.Minute, trust)

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

// ipv6ClientPrefixBits is the prefix an IPv6 client is keyed by. A single
// subscriber is normally handed a /64 or larger, so limiting per address would
// let one client use 2^64 keys.
const ipv6ClientPrefixBits = 64

// parseClientAddr parses an address from a header or RemoteAddr host part.
// It accepts a bare address or address:port, and normalises IPv4-mapped IPv6.
func parseClientAddr(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().WithZone(""), true
	}
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return addrPort.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// rateKey turns a client address into a rate-limit key: the address itself
// for IPv4, the /64 it belongs to for IPv6.
func rateKey(addr netip.Addr) string {
	if addr.Is6() {
		if prefix, err := addr.Prefix(ipv6ClientPrefixBits); err == nil {
			return prefix.String()
		}
	}
	return addr.String()
}

// trusted reports whether addr is one of the operator's reverse proxies.
func (t ProxyTrust) trusted(addr netip.Addr) bool {
	for _, prefix := range t.Proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientKey returns the rate-limit key for a request.
//
// The peer address of the TCP connection is the only thing a client cannot
// forge, so it is the answer unless the operator has said forwarding headers
// may be believed. A header value that is not an IP address is never used as a
// key: it would let a client mint unlimited keys of arbitrary size.
func clientKey(r *http.Request, trust ProxyTrust) string {
	remote, remoteOK := parseClientAddr(r.RemoteAddr)
	fallback := r.RemoteAddr
	if remoteOK {
		fallback = rateKey(remote)
	}

	if !trust.Enabled {
		return fallback
	}

	if len(trust.Proxies) == 0 {
		// Legacy mode: believe the leftmost X-Forwarded-For entry from anyone
		if first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ","); first != "" {
			if addr, ok := parseClientAddr(first); ok {
				return rateKey(addr)
			}
			return fallback
		}
		if addr, ok := parseClientAddr(r.Header.Get("X-Real-IP")); ok {
			return rateKey(addr)
		}
		return fallback
	}

	// Headers only count when the request really came from a trusted proxy
	if !remoteOK || !trust.trusted(remote) {
		return fallback
	}

	// Walk X-Forwarded-For from the right. Each trusted proxy appended the
	// address it received from; the first address that is not one of ours is
	// the client as seen by our outermost proxy. Anything to its left was
	// supplied by the client and is ignored.
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	client, found := netip.Addr{}, false
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		addr, ok := parseClientAddr(hop)
		if !ok {
			return fallback // malformed chain: do not guess
		}
		client, found = addr, true
		if !trust.trusted(addr) {
			break
		}
	}
	if found {
		return rateKey(client)
	}

	if addr, ok := parseClientAddr(r.Header.Get("X-Real-IP")); ok {
		return rateKey(addr)
	}
	return fallback
}
