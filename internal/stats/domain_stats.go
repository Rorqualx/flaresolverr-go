// Package stats provides domain-level statistics tracking for request patterns.
package stats

import (
	"math"
	"net/url"
	"sync"
	"time"
)

// maxDomains is the maximum number of domains to track before LRU eviction.
const maxDomains = 10000

// DomainStats tracks request statistics for a single domain.
type DomainStats struct {
	mu sync.RWMutex

	// Counters
	RequestCount   int64 `json:"requestCount"`
	SuccessCount   int64 `json:"successCount"`
	ErrorCount     int64 `json:"errorCount"`
	RateLimitCount int64 `json:"rateLimitCount"`

	// Timing (internal, for calculations)
	totalLatencyMs int64

	// Timestamps
	LastRequestTime time.Time `json:"lastRequestTime,omitempty"`
	LastSuccessTime time.Time `json:"lastSuccessTime,omitempty"`
	LastRateLimited time.Time `json:"lastRateLimited,omitempty"`
	LastAccess      time.Time `json:"-"` // For LRU eviction, not serialized

	// Configuration (optional overrides)
	CrawlDelay    *int `json:"crawlDelay,omitempty"`    // Seconds, from robots.txt
	ManualDelayMs *int `json:"manualDelayMs,omitempty"` // User override

	// Cached calculation
	cachedDelay     int
	lastCalculation time.Time
}

// DomainStatsJSON is the JSON-serializable representation of DomainStats.
type DomainStatsJSON struct {
	RequestCount     int64     `json:"requestCount"`
	SuccessCount     int64     `json:"successCount"`
	ErrorCount       int64     `json:"errorCount"`
	RateLimitCount   int64     `json:"rateLimitCount"`
	AvgLatencyMs     int64     `json:"avgLatencyMs"`
	LastRequestTime  time.Time `json:"lastRequestTime,omitempty"`
	LastSuccessTime  time.Time `json:"lastSuccessTime,omitempty"`
	LastRateLimited  time.Time `json:"lastRateLimited,omitempty"`
	SuggestedDelayMs int       `json:"suggestedDelayMs"`
	CrawlDelay       *int      `json:"crawlDelay,omitempty"`
}

// ToJSON converts DomainStats to its JSON-serializable form.
func (s *DomainStats) ToJSON(minDelay, maxDelay int) DomainStatsJSON {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var avgLatency int64
	if s.RequestCount > 0 {
		avgLatency = s.totalLatencyMs / s.RequestCount
	}

	return DomainStatsJSON{
		RequestCount:     s.RequestCount,
		SuccessCount:     s.SuccessCount,
		ErrorCount:       s.ErrorCount,
		RateLimitCount:   s.RateLimitCount,
		AvgLatencyMs:     avgLatency,
		LastRequestTime:  s.LastRequestTime,
		LastSuccessTime:  s.LastSuccessTime,
		LastRateLimited:  s.LastRateLimited,
		SuggestedDelayMs: s.suggestedDelayMs(minDelay, maxDelay),
		CrawlDelay:       s.CrawlDelay,
	}
}

// suggestedDelayMs calculates the recommended delay (must hold read lock).
func (s *DomainStats) suggestedDelayMs(minDelay, maxDelay int) int {
	// Base case: no data yet
	if s.RequestCount == 0 {
		return minDelay
	}

	// Calculate average latency
	avgLatencyMs := float64(s.totalLatencyMs) / float64(s.RequestCount)

	// Calculate error rate
	errorRate := float64(s.ErrorCount) / float64(s.RequestCount)
	rateLimitRate := float64(s.RateLimitCount) / float64(s.RequestCount)

	// Start with latency-based delay (AutoThrottle concept)
	// Target: 2 concurrent requests equivalent
	targetConcurrency := 2.0
	baseDelay := avgLatencyMs / targetConcurrency

	// Apply error rate multiplier: 0% = 1.0x, 10% = 1.5x, 20% = 2.0x
	errorMultiplier := 1.0 + (errorRate * 5.0)
	baseDelay *= errorMultiplier

	// Apply rate limit penalty: >5% rate limited = 2x delay
	if rateLimitRate > 0.05 {
		baseDelay *= 2.0
	}

	// Check for recent rate limiting (within 5 minutes)
	if !s.LastRateLimited.IsZero() && time.Since(s.LastRateLimited) < 5*time.Minute {
		// Exponential decay: full penalty at 0 min, half at 2.5 min, quarter at 5 min
		minutesSince := time.Since(s.LastRateLimited).Minutes()
		recentPenalty := 10000.0 * math.Pow(0.5, minutesSince/2.5)
		baseDelay = math.Max(baseDelay, recentPenalty)
	}

	// Honor robots.txt crawl-delay if set
	if s.CrawlDelay != nil {
		crawlDelayMs := float64(*s.CrawlDelay * 1000)
		baseDelay = math.Max(baseDelay, crawlDelayMs)
	}

	// Honor manual override if set
	if s.ManualDelayMs != nil {
		baseDelay = math.Max(baseDelay, float64(*s.ManualDelayMs))
	}

	// Clamp to configured bounds
	result := int(math.Max(float64(minDelay), math.Min(float64(maxDelay), baseDelay)))
	return result
}

// SuggestedDelayMs returns the recommended delay for this domain.
func (s *DomainStats) SuggestedDelayMs(minDelay, maxDelay int) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use cached value if recent (within 5 seconds)
	if time.Since(s.lastCalculation) < 5*time.Second && s.cachedDelay > 0 {
		return s.cachedDelay
	}

	return s.suggestedDelayMs(minDelay, maxDelay)
}

// ErrorRate returns the error rate (0.0-1.0) for this domain.
func (s *DomainStats) ErrorRate() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.RequestCount == 0 {
		return 0
	}
	return float64(s.ErrorCount) / float64(s.RequestCount)
}

// Manager manages statistics for all domains.
type Manager struct {
	mu      sync.RWMutex
	domains map[string]*DomainStats

	// Configuration
	DefaultMinDelayMs int
	DefaultMaxDelayMs int
}

// NewManager creates a new domain stats manager.
func NewManager() *Manager {
	return &Manager{
		domains:           make(map[string]*DomainStats),
		DefaultMinDelayMs: 1000,  // 1 second minimum
		DefaultMaxDelayMs: 30000, // 30 second maximum
	}
}

// ExtractDomain extracts the domain from a URL.
func ExtractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// getOrCreate returns the stats for a domain, creating if needed.
// Implements LRU eviction when the domain count exceeds maxDomains.
func (m *Manager) getOrCreate(domain string) *DomainStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, exists := m.domains[domain]
	if !exists {
		// Evict oldest domain if at capacity
		if len(m.domains) >= maxDomains {
			m.evictOldestLocked()
		}
		stats = &DomainStats{
			LastAccess: time.Now(),
		}
		m.domains[domain] = stats
	} else {
		stats.LastAccess = time.Now()
	}
	return stats
}

// evictOldestLocked removes the least recently accessed domain.
// Must be called with m.mu held.
func (m *Manager) evictOldestLocked() {
	var oldestDomain string
	var oldestTime time.Time

	for domain, stats := range m.domains {
		if oldestDomain == "" || stats.LastAccess.Before(oldestTime) {
			oldestDomain = domain
			oldestTime = stats.LastAccess
		}
	}

	if oldestDomain != "" {
		delete(m.domains, oldestDomain)
	}
}

// Get returns the stats for a domain (nil if not tracked).
func (m *Manager) Get(domain string) *DomainStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.domains[domain]
}

// RecordRequest updates stats after a request completes.
func (m *Manager) RecordRequest(domain string, latencyMs int64, success bool, rateLimited bool) {
	if domain == "" {
		return
	}

	stats := m.getOrCreate(domain)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.RequestCount++
	stats.totalLatencyMs += latencyMs
	stats.LastRequestTime = time.Now()

	if success {
		stats.SuccessCount++
		stats.LastSuccessTime = time.Now()
	} else {
		stats.ErrorCount++
	}

	if rateLimited {
		stats.RateLimitCount++
		stats.LastRateLimited = time.Now()
	}

	// Invalidate cache
	stats.cachedDelay = 0
}

// SuggestedDelay returns the suggested delay for a domain.
func (m *Manager) SuggestedDelay(domain string) int {
	stats := m.Get(domain)
	if stats == nil {
		return m.DefaultMinDelayMs
	}
	return stats.SuggestedDelayMs(m.DefaultMinDelayMs, m.DefaultMaxDelayMs)
}

// ErrorRate returns the error rate for a domain.
func (m *Manager) ErrorRate(domain string) float64 {
	stats := m.Get(domain)
	if stats == nil {
		return 0
	}
	return stats.ErrorRate()
}

// RequestCount returns the request count for a domain.
func (m *Manager) RequestCount(domain string) int64 {
	stats := m.Get(domain)
	if stats == nil {
		return 0
	}
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	return stats.RequestCount
}

// AllStats returns a copy of all domain statistics.
func (m *Manager) AllStats() map[string]DomainStatsJSON {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]DomainStatsJSON, len(m.domains))
	for domain, stats := range m.domains {
		result[domain] = stats.ToJSON(m.DefaultMinDelayMs, m.DefaultMaxDelayMs)
	}
	return result
}

// SetManualDelay sets a manual delay override for a domain.
func (m *Manager) SetManualDelay(domain string, delayMs int) {
	stats := m.getOrCreate(domain)
	stats.mu.Lock()
	defer stats.mu.Unlock()
	stats.ManualDelayMs = &delayMs
	stats.cachedDelay = 0 // Invalidate cache
}

// ClearManualDelay removes the manual delay override for a domain.
func (m *Manager) ClearManualDelay(domain string) {
	stats := m.Get(domain)
	if stats == nil {
		return
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	stats.ManualDelayMs = nil
	stats.cachedDelay = 0 // Invalidate cache
}

// Reset clears all statistics for a domain.
func (m *Manager) Reset(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.domains, domain)
}

// ResetAll clears all domain statistics.
func (m *Manager) ResetAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domains = make(map[string]*DomainStats)
}

// DomainCount returns the number of tracked domains.
func (m *Manager) DomainCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains)
}
