// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"sync"
	"time"
)

// Metrics tracks usage statistics for CAPTCHA solvers.
type Metrics struct {
	mu        sync.RWMutex
	providers map[string]*ProviderStats
}

// ProviderStats contains statistics for a single provider.
type ProviderStats struct {
	Attempts    int64         // Total solve attempts
	Successes   int64         // Successful solves
	Failures    int64         // Failed solves
	TotalCost   float64       // Total cost in USD
	TotalTimeMs int64         // Total time spent solving in milliseconds
	LastUsed    time.Time     // Last time this provider was used
	LastBalance float64       // Last known balance (from Balance() call)
	LastError   string        // Last error message
	LastErrorAt time.Time     // When the last error occurred
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		providers: make(map[string]*ProviderStats),
	}
}

// RecordAttempt records a solve attempt for a provider.
func (m *Metrics) RecordAttempt(provider string, success bool, cost float64, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := m.getOrCreate(provider)
	stats.Attempts++
	stats.LastUsed = time.Now()
	stats.TotalTimeMs += duration.Milliseconds()

	if success {
		stats.Successes++
		stats.TotalCost += cost
	} else {
		stats.Failures++
	}
}

// RecordError records an error for a provider.
func (m *Metrics) RecordError(provider string, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := m.getOrCreate(provider)
	stats.LastError = errMsg
	stats.LastErrorAt = time.Now()
}

// UpdateBalance updates the cached balance for a provider.
func (m *Metrics) UpdateBalance(provider string, balance float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := m.getOrCreate(provider)
	stats.LastBalance = balance
}

// GetStats returns a copy of stats for a provider.
func (m *Metrics) GetStats(provider string) *ProviderStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.providers[provider]
	if !exists {
		return nil
	}

	// Return a copy to prevent race conditions
	return &ProviderStats{
		Attempts:    stats.Attempts,
		Successes:   stats.Successes,
		Failures:    stats.Failures,
		TotalCost:   stats.TotalCost,
		TotalTimeMs: stats.TotalTimeMs,
		LastUsed:    stats.LastUsed,
		LastBalance: stats.LastBalance,
		LastError:   stats.LastError,
		LastErrorAt: stats.LastErrorAt,
	}
}

// ToJSON returns all metrics as a map for JSON serialization.
func (m *Metrics) ToJSON() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})

	for name, stats := range m.providers {
		successRate := float64(0)
		avgTimeMs := int64(0)

		if stats.Attempts > 0 {
			successRate = float64(stats.Successes) / float64(stats.Attempts) * 100
			avgTimeMs = stats.TotalTimeMs / stats.Attempts
		}

		providerData := map[string]interface{}{
			"attempts":     stats.Attempts,
			"successes":    stats.Successes,
			"failures":     stats.Failures,
			"success_rate": successRate,
			"total_cost":   stats.TotalCost,
			"avg_time_ms":  avgTimeMs,
			"last_balance": stats.LastBalance,
		}

		if !stats.LastUsed.IsZero() {
			providerData["last_used"] = stats.LastUsed.Format(time.RFC3339)
		}

		if stats.LastError != "" {
			providerData["last_error"] = stats.LastError
			if !stats.LastErrorAt.IsZero() {
				providerData["last_error_at"] = stats.LastErrorAt.Format(time.RFC3339)
			}
		}

		result[name] = providerData
	}

	// Add summary
	var totalAttempts, totalSuccesses, totalFailures int64
	var totalCost float64

	for _, stats := range m.providers {
		totalAttempts += stats.Attempts
		totalSuccesses += stats.Successes
		totalFailures += stats.Failures
		totalCost += stats.TotalCost
	}

	overallSuccessRate := float64(0)
	if totalAttempts > 0 {
		overallSuccessRate = float64(totalSuccesses) / float64(totalAttempts) * 100
	}

	result["_summary"] = map[string]interface{}{
		"total_attempts":  totalAttempts,
		"total_successes": totalSuccesses,
		"total_failures":  totalFailures,
		"success_rate":    overallSuccessRate,
		"total_cost":      totalCost,
	}

	return result
}

// Reset clears all metrics.
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers = make(map[string]*ProviderStats)
}

// getOrCreate returns existing stats or creates new ones for a provider.
// Must be called with lock held.
func (m *Metrics) getOrCreate(provider string) *ProviderStats {
	stats, exists := m.providers[provider]
	if !exists {
		stats = &ProviderStats{}
		m.providers[provider] = stats
	}
	return stats
}

// SuccessRate returns the success rate for a provider.
func (m *Metrics) SuccessRate(provider string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.providers[provider]
	if !exists || stats.Attempts == 0 {
		return 0
	}

	return float64(stats.Successes) / float64(stats.Attempts) * 100
}

// AverageTime returns the average solve time for a provider.
func (m *Metrics) AverageTime(provider string) time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.providers[provider]
	if !exists || stats.Attempts == 0 {
		return 0
	}

	avgMs := stats.TotalTimeMs / stats.Attempts
	return time.Duration(avgMs) * time.Millisecond
}

// TotalCost returns the total cost across all providers.
func (m *Metrics) TotalCost() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var total float64
	for _, stats := range m.providers {
		total += stats.TotalCost
	}
	return total
}
