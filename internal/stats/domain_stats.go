// Package stats provides domain-level statistics tracking for request patterns.
package stats

import (
	"math"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// maxDomains is the maximum number of domains to track before LRU eviction.
const maxDomains = 10000

// evictionBatchSize is the number of domains to evict at once to reduce eviction overhead.
const evictionBatchSize = 100

// TurnstileMethodStats tracks which Turnstile solving method works best for a domain.
// Methods: "wait", "shadow", "keyboard", "widget", "iframe", "positional"
type TurnstileMethodStats struct {
	MethodAttempts  map[string]int64 `json:"methodAttempts,omitempty"`  // Attempts per method
	MethodSuccesses map[string]int64 `json:"methodSuccesses,omitempty"` // Successes per method
	LastSuccess     string           `json:"lastSuccess,omitempty"`     // Last method that worked
	LastSuccessTime time.Time        `json:"lastSuccessTime,omitempty"`
}

// GetBestMethod returns the method with highest success rate for this domain.
// Returns empty string if no successful method found.
func (t *TurnstileMethodStats) GetBestMethod() string {
	if t == nil || len(t.MethodSuccesses) == 0 {
		return ""
	}

	// If we have a recent success, prefer that method
	if t.LastSuccess != "" && !t.LastSuccessTime.IsZero() {
		// If last success was within 1 hour, strongly prefer it
		if time.Since(t.LastSuccessTime) < time.Hour {
			return t.LastSuccess
		}
	}

	// Otherwise find the method with highest success rate
	bestMethod := ""
	bestRate := 0.0

	for method, successes := range t.MethodSuccesses {
		attempts := t.MethodAttempts[method]
		if attempts > 0 {
			rate := float64(successes) / float64(attempts)
			if rate > bestRate {
				bestRate = rate
				bestMethod = method
			}
		}
	}

	return bestMethod
}

// SolveMethodStats tracks success/failure by solve method.
// This enables per-domain profiling to determine which solving approach works best.
type SolveMethodStats struct {
	// Native solving statistics
	NativeAttempts    int64 `json:"nativeAttempts"`
	NativeSuccesses   int64 `json:"nativeSuccesses"`
	NativeTotalTimeMs int64 `json:"nativeTotalTimeMs"` // For calculating average

	// External solver statistics (keyed by provider name)
	ExternalAttempts  map[string]int64 `json:"externalAttempts,omitempty"`
	ExternalSuccesses map[string]int64 `json:"externalSuccesses,omitempty"`
	ExternalTotalTime map[string]int64 `json:"externalTotalTime,omitempty"` // For calculating averages

	// Turnstile method-specific tracking
	TurnstileMethods *TurnstileMethodStats `json:"turnstileMethods,omitempty"`

	// Last successful method
	LastSuccessMethod string    `json:"lastSuccessMethod,omitempty"`
	LastSuccessTime   time.Time `json:"lastSuccessTime,omitempty"`
}

// SolverPreferences stores per-domain solver configuration.
// These preferences can be set manually or learned from solve history.
type SolverPreferences struct {
	NativeFirst       bool     `json:"nativeFirst"`                 // Try native solving first (default: true)
	NativeAttempts    *int     `json:"nativeAttempts,omitempty"`    // Override native attempts before fallback
	PreferredProvider string   `json:"preferredProvider,omitempty"` // Preferred external provider
	TimeoutOverrideMs *int     `json:"timeoutOverrideMs,omitempty"` // Domain-specific timeout
	DisableMethods    []string `json:"disableMethods,omitempty"`    // Methods to skip for this domain
}

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

	// Solve method statistics
	SolveStats SolveMethodStats `json:"solveStats,omitempty"`

	// Domain-specific solver preferences
	SolverPrefs *SolverPreferences `json:"solverPrefs,omitempty"`

	// Cached calculation
	// Audit Issue 8: Use -1 as invalid marker since 0 is a valid delay value
	cachedDelay int // -1 means cache is invalid
	// Fix #44: Uses time.Now() which includes monotonic clock component
	// for accurate elapsed time calculations even if wall clock changes.
	// Go's time.Time automatically uses monotonic clock for time.Since().
	lastCalculation time.Time
}

// SolveMethodStatsJSON is the JSON-serializable representation of SolveMethodStats.
type SolveMethodStatsJSON struct {
	NativeAttempts    int64            `json:"nativeAttempts"`
	NativeSuccesses   int64            `json:"nativeSuccesses"`
	NativeAvgTimeMs   int64            `json:"nativeAvgTimeMs"`
	NativeSuccessRate float64          `json:"nativeSuccessRate"`
	ExternalAttempts  map[string]int64 `json:"externalAttempts,omitempty"`
	ExternalSuccesses map[string]int64 `json:"externalSuccesses,omitempty"`
	LastSuccessMethod string           `json:"lastSuccessMethod,omitempty"`
	LastSuccessTime   time.Time        `json:"lastSuccessTime,omitempty"`
}

// DomainStatsJSON is the JSON-serializable representation of DomainStats.
type DomainStatsJSON struct {
	RequestCount     int64                 `json:"requestCount"`
	SuccessCount     int64                 `json:"successCount"`
	ErrorCount       int64                 `json:"errorCount"`
	RateLimitCount   int64                 `json:"rateLimitCount"`
	AvgLatencyMs     int64                 `json:"avgLatencyMs"`
	LastRequestTime  time.Time             `json:"lastRequestTime,omitempty"`
	LastSuccessTime  time.Time             `json:"lastSuccessTime,omitempty"`
	LastRateLimited  time.Time             `json:"lastRateLimited,omitempty"`
	SuggestedDelayMs int                   `json:"suggestedDelayMs"`
	CrawlDelay       *int                  `json:"crawlDelay,omitempty"`
	SolveStats       *SolveMethodStatsJSON `json:"solveStats,omitempty"`
	SolverPrefs      *SolverPreferences    `json:"solverPrefs,omitempty"`
}

// ToJSON converts DomainStats to its JSON-serializable form.
func (s *DomainStats) ToJSON(minDelay, maxDelay int) DomainStatsJSON {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var avgLatency int64
	if s.RequestCount > 0 {
		avgLatency = s.totalLatencyMs / s.RequestCount
	}

	result := DomainStatsJSON{
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
		SolverPrefs:      s.SolverPrefs,
	}

	// Include solve stats if there are any attempts
	if s.SolveStats.NativeAttempts > 0 || len(s.SolveStats.ExternalAttempts) > 0 {
		var nativeAvgTime int64
		var nativeSuccessRate float64
		if s.SolveStats.NativeAttempts > 0 {
			nativeAvgTime = s.SolveStats.NativeTotalTimeMs / s.SolveStats.NativeAttempts
			nativeSuccessRate = float64(s.SolveStats.NativeSuccesses) / float64(s.SolveStats.NativeAttempts)
		}

		result.SolveStats = &SolveMethodStatsJSON{
			NativeAttempts:    s.SolveStats.NativeAttempts,
			NativeSuccesses:   s.SolveStats.NativeSuccesses,
			NativeAvgTimeMs:   nativeAvgTime,
			NativeSuccessRate: nativeSuccessRate,
			ExternalAttempts:  s.SolveStats.ExternalAttempts,
			ExternalSuccesses: s.SolveStats.ExternalSuccesses,
			LastSuccessMethod: s.SolveStats.LastSuccessMethod,
			LastSuccessTime:   s.SolveStats.LastSuccessTime,
		}
	}

	return result
}

// suggestedDelayMs calculates the recommended delay (must hold read lock).
// Fix: Adds NaN/Inf protection and validation for calculated values.
func (s *DomainStats) suggestedDelayMs(minDelay, maxDelay int) int {
	// Base case: no data yet
	if s.RequestCount == 0 {
		return minDelay
	}

	// Validate RequestCount is positive (should never be negative, but defensive)
	if s.RequestCount < 0 {
		return minDelay
	}

	// Calculate average latency with NaN protection
	avgLatencyMs := float64(s.totalLatencyMs) / float64(s.RequestCount)
	if math.IsNaN(avgLatencyMs) || math.IsInf(avgLatencyMs, 0) {
		avgLatencyMs = 0
	}

	// Calculate error rate with NaN protection
	errorRate := float64(s.ErrorCount) / float64(s.RequestCount)
	if math.IsNaN(errorRate) || math.IsInf(errorRate, 0) || errorRate < 0 {
		errorRate = 0
	}
	rateLimitRate := float64(s.RateLimitCount) / float64(s.RequestCount)
	if math.IsNaN(rateLimitRate) || math.IsInf(rateLimitRate, 0) || rateLimitRate < 0 {
		rateLimitRate = 0
	}

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
// Fix: Uses simple write lock instead of error-prone double-checked locking.
// The performance cost of always acquiring write lock is negligible compared
// to the complexity and potential bugs of double-checked locking with RWMutex.
func (s *DomainStats) SuggestedDelayMs(minDelay, maxDelay int) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cache validity
	if time.Since(s.lastCalculation) < 5*time.Second && s.cachedDelay >= 0 {
		return s.cachedDelay
	}

	// Calculate, cache, and update timestamp atomically under write lock
	delay := s.suggestedDelayMs(minDelay, maxDelay)
	s.cachedDelay = delay
	s.lastCalculation = time.Now()
	return delay
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

	// Fix #14: Background cleanup
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewManager creates a new domain stats manager.
// Fix #14: Starts background cleanup routine for stale entries.
func NewManager() *Manager {
	m := &Manager{
		domains:           make(map[string]*DomainStats),
		DefaultMinDelayMs: 1000,  // 1 second minimum
		DefaultMaxDelayMs: 30000, // 30 second maximum
		stopCh:            make(chan struct{}),
	}

	// Start background cleanup routine
	m.wg.Add(1)
	go m.cleanupRoutine()

	return m
}

// cleanupRoutine periodically removes stale domain stats entries.
// Fix #14: Prevents unbounded memory growth from domains that are no longer accessed.
func (m *Manager) cleanupRoutine() {
	defer m.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupStale(30 * time.Minute)
		case <-m.stopCh:
			return
		}
	}
}

// cleanupStale removes domain stats that haven't been accessed recently.
func (m *Manager) cleanupStale(maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var removed int

	for domain, stats := range m.domains {
		stats.mu.RLock()
		lastAccess := stats.LastAccess
		stats.mu.RUnlock()

		if now.Sub(lastAccess) > maxAge {
			delete(m.domains, domain)
			removed++
		}
	}

	if removed > 0 {
		log.Debug().
			Int("removed", removed).
			Int("remaining", len(m.domains)).
			Msg("Cleaned up stale domain stats")
	}
}

// Close stops the background cleanup routine.
func (m *Manager) Close() {
	close(m.stopCh)
	m.wg.Wait()
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
// Fix: Avoids nested lock acquisition by using atomic operations where possible
// and releasing manager lock before accessing stats lock.
func (m *Manager) getOrCreate(domain string) *DomainStats {
	m.mu.Lock()

	stats, exists := m.domains[domain]
	if !exists {
		// Evict oldest domains in batch if at capacity
		if len(m.domains) >= maxDomains {
			m.evictOldestBatchLocked(evictionBatchSize)
		}
		stats = &DomainStats{
			cachedDelay: -1,         // Initialize with invalid cache marker
			LastAccess:  time.Now(), // Safe - no one else has reference yet
		}
		m.domains[domain] = stats
		m.mu.Unlock() // Release manager lock before any further operations
		return stats
	}

	// Release manager lock before acquiring stats lock to prevent nested lock
	m.mu.Unlock()

	// Update last access time with stats lock
	stats.mu.Lock()
	stats.LastAccess = time.Now()
	stats.mu.Unlock()

	return stats
}

// evictOldestBatchLocked removes the N least recently accessed domains.
// Must be called with m.mu held.
// Evicting in batches reduces the overhead of repeated single evictions.
// Fix: Uses a snapshot of LastAccess times to avoid nested locking.
// Since we hold m.mu, no new entries can be added, and the LastAccess
// values we read are good enough for LRU approximation.
func (m *Manager) evictOldestBatchLocked(count int) {
	if count <= 0 || len(m.domains) == 0 {
		return
	}

	// For small domain counts, use simple approach
	if len(m.domains) <= count {
		// Clear all
		for domain := range m.domains {
			delete(m.domains, domain)
		}
		return
	}

	// Collect domains with their access times
	// Note: Reading LastAccess without lock is safe here because:
	// 1. We hold m.mu, so no new domains can be added
	// 2. Worst case, we get a slightly stale time, which is acceptable for LRU
	// 3. This avoids nested lock acquisition which could cause deadlocks
	type domainTime struct {
		domain     string
		lastAccess time.Time
	}
	candidates := make([]domainTime, 0, len(m.domains))
	for domain, stats := range m.domains {
		// Read LastAccess atomically without lock to avoid nested locking
		// The slight race is acceptable - we're just doing approximate LRU
		stats.mu.RLock()
		lastAccess := stats.LastAccess
		stats.mu.RUnlock()
		candidates = append(candidates, domainTime{domain, lastAccess})
	}

	// Find the N oldest domains using a simple selection approach
	// For the typical batch size of 100 out of 10000, this is efficient enough
	for i := 0; i < count && i < len(candidates); i++ {
		minIdx := i
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].lastAccess.Before(candidates[minIdx].lastAccess) {
				minIdx = j
			}
		}
		if minIdx != i {
			candidates[i], candidates[minIdx] = candidates[minIdx], candidates[i]
		}
		// Delete the oldest
		delete(m.domains, candidates[i].domain)
	}
}

// Get returns the stats for a domain (nil if not tracked).
func (m *Manager) Get(domain string) *DomainStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.domains[domain]
}

// Maximum counter value to prevent overflow (use 90% of int64 max)
const maxCounterValue int64 = (1 << 62)

// RecordRequest updates stats after a request completes.
// Fix: Adds overflow protection for counters.
func (m *Manager) RecordRequest(domain string, latencyMs int64, success bool, rateLimited bool) {
	if domain == "" {
		return
	}

	stats := m.getOrCreate(domain)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	// Overflow protection: reset counters if approaching max value
	// Fix: Reset timestamps atomically along with counters to maintain consistency
	if stats.RequestCount >= maxCounterValue {
		log.Warn().
			Str("domain", domain).
			Int64("request_count", stats.RequestCount).
			Msg("Counter overflow protection triggered, resetting stats")
		stats.RequestCount = 0
		stats.SuccessCount = 0
		stats.ErrorCount = 0
		stats.RateLimitCount = 0
		stats.totalLatencyMs = 0
		// Reset timestamps to prevent stale data correlation
		stats.LastRequestTime = time.Time{}
		stats.LastSuccessTime = time.Time{}
		stats.LastRateLimited = time.Time{}
	}

	stats.RequestCount++
	// Protect latency accumulator from overflow
	if stats.totalLatencyMs < maxCounterValue-latencyMs {
		stats.totalLatencyMs += latencyMs
	}
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

	// Invalidate cache (use -1 as invalid marker since 0 is a valid delay)
	stats.cachedDelay = -1
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
// Fix #31: Uses manager lock for getOrCreate then stats lock for update,
// ensuring consistent lock ordering and preventing races.
func (m *Manager) SetManualDelay(domain string, delayMs int) {
	stats := m.getOrCreate(domain)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.ManualDelayMs = &delayMs
	stats.cachedDelay = -1 // Invalidate cache
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
	stats.cachedDelay = -1 // Invalidate cache
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

// RecordSolveOutcome records the result of a solve attempt for a domain.
// method should be "native" or the external provider name (e.g., "2captcha", "capsolver").
// success indicates whether the solve succeeded.
// durationMs is the time taken for the solve attempt.
func (m *Manager) RecordSolveOutcome(domain, method string, success bool, durationMs int64) {
	if domain == "" || method == "" {
		return
	}

	stats := m.getOrCreate(domain)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	if method == "native" {
		stats.SolveStats.NativeAttempts++
		if durationMs > 0 && stats.SolveStats.NativeTotalTimeMs < maxCounterValue-durationMs {
			stats.SolveStats.NativeTotalTimeMs += durationMs
		}
		if success {
			stats.SolveStats.NativeSuccesses++
			stats.SolveStats.LastSuccessMethod = method
			stats.SolveStats.LastSuccessTime = time.Now()
		}
	} else {
		// External provider
		if stats.SolveStats.ExternalAttempts == nil {
			stats.SolveStats.ExternalAttempts = make(map[string]int64)
		}
		if stats.SolveStats.ExternalSuccesses == nil {
			stats.SolveStats.ExternalSuccesses = make(map[string]int64)
		}
		if stats.SolveStats.ExternalTotalTime == nil {
			stats.SolveStats.ExternalTotalTime = make(map[string]int64)
		}

		stats.SolveStats.ExternalAttempts[method]++
		if durationMs > 0 {
			current := stats.SolveStats.ExternalTotalTime[method]
			if current < maxCounterValue-durationMs {
				stats.SolveStats.ExternalTotalTime[method] = current + durationMs
			}
		}
		if success {
			stats.SolveStats.ExternalSuccesses[method]++
			stats.SolveStats.LastSuccessMethod = method
			stats.SolveStats.LastSuccessTime = time.Now()
		}
	}
}

// GetPreferredSolveMethod returns the best solving method for a domain based on history.
// Returns "native" if native solving has >20% success rate or no external history exists.
// Returns the external provider name if it has a better success rate.
// Returns empty string if no solve history exists for this domain.
func (m *Manager) GetPreferredSolveMethod(domain string) string {
	stats := m.Get(domain)
	if stats == nil {
		return ""
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	// No solve history
	if stats.SolveStats.NativeAttempts == 0 && len(stats.SolveStats.ExternalAttempts) == 0 {
		return ""
	}

	// Check if solver preferences override history
	if stats.SolverPrefs != nil && stats.SolverPrefs.PreferredProvider != "" {
		return stats.SolverPrefs.PreferredProvider
	}

	// Calculate native success rate
	var nativeSuccessRate float64
	if stats.SolveStats.NativeAttempts > 0 {
		nativeSuccessRate = float64(stats.SolveStats.NativeSuccesses) / float64(stats.SolveStats.NativeAttempts)
	}

	// Find best external provider
	bestExternal := ""
	bestExternalRate := 0.0
	for provider, attempts := range stats.SolveStats.ExternalAttempts {
		if attempts > 0 {
			successes := stats.SolveStats.ExternalSuccesses[provider]
			rate := float64(successes) / float64(attempts)
			if rate > bestExternalRate {
				bestExternalRate = rate
				bestExternal = provider
			}
		}
	}

	// Prefer native if it has decent success rate
	if nativeSuccessRate >= 0.2 || bestExternal == "" {
		if stats.SolveStats.NativeAttempts > 0 {
			return "native"
		}
	}

	// Otherwise prefer the best external provider
	if bestExternalRate > nativeSuccessRate {
		return bestExternal
	}

	return "native"
}

// ShouldSkipNative returns true if native solving has consistently failed (<20% success rate)
// and should be skipped in favor of external solvers.
// Requires at least 5 native attempts before making this determination.
func (m *Manager) ShouldSkipNative(domain string) bool {
	stats := m.Get(domain)
	if stats == nil {
		return false
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	// Check if preferences explicitly disable native
	if stats.SolverPrefs != nil {
		for _, method := range stats.SolverPrefs.DisableMethods {
			if method == "native" {
				return true
			}
		}
	}

	// Need sufficient attempts to make a determination
	const minAttempts = 5
	if stats.SolveStats.NativeAttempts < minAttempts {
		return false
	}

	// Calculate success rate
	successRate := float64(stats.SolveStats.NativeSuccesses) / float64(stats.SolveStats.NativeAttempts)

	// Skip native if success rate is below 20%
	return successRate < 0.2
}

// SetDomainSolverPrefs sets solver preferences for a domain.
func (m *Manager) SetDomainSolverPrefs(domain string, prefs *SolverPreferences) {
	if domain == "" {
		return
	}

	stats := m.getOrCreate(domain)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.SolverPrefs = prefs
}

// GetDomainSolverPrefs returns solver preferences for a domain.
// Returns nil if no preferences are set.
func (m *Manager) GetDomainSolverPrefs(domain string) *SolverPreferences {
	stats := m.Get(domain)
	if stats == nil {
		return nil
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	return stats.SolverPrefs
}

// NativeSuccessRate returns the native solve success rate for a domain (0.0 to 1.0).
// Returns -1 if no native attempts have been made.
func (m *Manager) NativeSuccessRate(domain string) float64 {
	stats := m.Get(domain)
	if stats == nil {
		return -1
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.SolveStats.NativeAttempts == 0 {
		return -1
	}

	return float64(stats.SolveStats.NativeSuccesses) / float64(stats.SolveStats.NativeAttempts)
}

// RecordTurnstileMethod records a Turnstile method attempt and its outcome.
// method should be one of: "wait", "shadow", "keyboard", "widget", "iframe", "positional"
func (m *Manager) RecordTurnstileMethod(domain, method string, success bool) {
	if domain == "" || method == "" {
		return
	}

	stats := m.getOrCreate(domain)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	// Initialize TurnstileMethods if nil
	if stats.SolveStats.TurnstileMethods == nil {
		stats.SolveStats.TurnstileMethods = &TurnstileMethodStats{
			MethodAttempts:  make(map[string]int64),
			MethodSuccesses: make(map[string]int64),
		}
	}

	tm := stats.SolveStats.TurnstileMethods

	// Initialize maps if nil (defensive)
	if tm.MethodAttempts == nil {
		tm.MethodAttempts = make(map[string]int64)
	}
	if tm.MethodSuccesses == nil {
		tm.MethodSuccesses = make(map[string]int64)
	}

	// Record attempt
	tm.MethodAttempts[method]++

	// Record success
	if success {
		tm.MethodSuccesses[method]++
		tm.LastSuccess = method
		tm.LastSuccessTime = time.Now()
	}
}

// GetBestTurnstileMethod returns the best Turnstile method for a domain based on history.
// Returns empty string if no history exists.
func (m *Manager) GetBestTurnstileMethod(domain string) string {
	stats := m.Get(domain)
	if stats == nil {
		return ""
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.SolveStats.TurnstileMethods == nil {
		return ""
	}

	return stats.SolveStats.TurnstileMethods.GetBestMethod()
}

// GetTurnstileMethodOrder returns the ordered list of methods to try based on domain history.
// Methods with higher success rates come first. Untried methods are tried before consistently
// failing methods (negative learning). Methods that always fail are deprioritized.
func (m *Manager) GetTurnstileMethodOrder(domain string) []string {
	// Default order - "wait" first because invisible Turnstile auto-solves without interaction
	defaultOrder := []string{"wait", "shadow", "keyboard", "widget", "iframe", "positional"}

	stats := m.Get(domain)
	if stats == nil {
		return defaultOrder
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	tm := stats.SolveStats.TurnstileMethods
	if tm == nil || len(tm.MethodAttempts) == 0 {
		return defaultOrder
	}

	// Build ordered list based on success rates with negative learning
	// Score system:
	// - Methods with successes: score = success_rate (0.0 to 1.0) + 0.5 for recent success
	// - Untried methods: score = 0.5 (neutral, tried before failing methods)
	// - Methods with only failures: score = -failure_count * 0.1 (negative, penalize more failures)
	type methodScore struct {
		name  string
		score float64
	}

	scores := make([]methodScore, 0, len(defaultOrder))

	for _, method := range defaultOrder {
		attempts := tm.MethodAttempts[method]
		successes := tm.MethodSuccesses[method]

		var score float64
		if attempts == 0 {
			// Untried method - give it a neutral positive score
			score = 0.5
		} else if successes > 0 {
			// Has some successes - use success rate
			score = float64(successes) / float64(attempts)
			// Boost recent success
			if tm.LastSuccess == method && time.Since(tm.LastSuccessTime) < time.Hour {
				score += 0.5
			}
		} else {
			// Only failures - negative score based on failure count
			// More failures = lower priority (but cap the penalty)
			failures := attempts
			if failures > 10 {
				failures = 10 // Cap penalty at 10 failures
			}
			score = -float64(failures) * 0.1
		}

		scores = append(scores, methodScore{method, score})
	}

	// Sort by score descending (simple bubble sort for small array)
	for i := 0; i < len(scores)-1; i++ {
		for j := i + 1; j < len(scores); j++ {
			if scores[j].score > scores[i].score {
				scores[i], scores[j] = scores[j], scores[i]
			}
		}
	}

	// Build result from sorted scores
	result := make([]string, 0, len(defaultOrder))
	for _, s := range scores {
		result = append(result, s.name)
	}

	return result
}

// GetTurnstileMethodStats returns a map of method -> (attempts, successes) for a domain.
// Useful for debugging and testing the learning system.
func (m *Manager) GetTurnstileMethodStats(domain string) map[string][2]int64 {
	stats := m.Get(domain)
	if stats == nil {
		return nil
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.SolveStats.TurnstileMethods == nil {
		return nil
	}

	tm := stats.SolveStats.TurnstileMethods
	result := make(map[string][2]int64)

	for method, attempts := range tm.MethodAttempts {
		successes := tm.MethodSuccesses[method]
		result[method] = [2]int64{attempts, successes}
	}

	return result
}
