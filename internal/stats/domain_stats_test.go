package stats

import (
	"testing"
	"time"
)

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{
			name:   "simple url",
			rawURL: "https://example.com/page",
			want:   "example.com",
		},
		{
			name:   "url with port",
			rawURL: "https://example.com:8080/page",
			want:   "example.com",
		},
		{
			name:   "url with subdomain",
			rawURL: "https://api.example.com/v1/data",
			want:   "api.example.com",
		},
		{
			name:   "url with www",
			rawURL: "https://www.example.com/page",
			want:   "www.example.com",
		},
		{
			name:   "http url",
			rawURL: "http://example.com/page",
			want:   "example.com",
		},
		{
			name:   "url with query params",
			rawURL: "https://example.com/page?foo=bar",
			want:   "example.com",
		},
		{
			name:   "invalid url",
			rawURL: "not-a-valid-url",
			want:   "",
		},
		{
			name:   "empty url",
			rawURL: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDomain(tt.rawURL)
			if got != tt.want {
				t.Errorf("ExtractDomain(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestManager_RecordRequest(t *testing.T) {
	m := NewManager()

	// Record some requests
	m.RecordRequest("example.com", 100, true, false)
	m.RecordRequest("example.com", 200, true, false)
	m.RecordRequest("example.com", 150, false, true) // Rate limited

	stats := m.Get("example.com")
	if stats == nil {
		t.Fatal("Expected stats for example.com, got nil")
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.RequestCount != 3 {
		t.Errorf("RequestCount = %d, want 3", stats.RequestCount)
	}
	if stats.SuccessCount != 2 {
		t.Errorf("SuccessCount = %d, want 2", stats.SuccessCount)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", stats.ErrorCount)
	}
	if stats.RateLimitCount != 1 {
		t.Errorf("RateLimitCount = %d, want 1", stats.RateLimitCount)
	}
	if stats.totalLatencyMs != 450 {
		t.Errorf("totalLatencyMs = %d, want 450", stats.totalLatencyMs)
	}
}

func TestManager_SuggestedDelay(t *testing.T) {
	m := NewManager()

	// Unknown domain should return minimum delay
	delay := m.SuggestedDelay("unknown.com")
	if delay != m.DefaultMinDelayMs {
		t.Errorf("SuggestedDelay for unknown domain = %d, want %d", delay, m.DefaultMinDelayMs)
	}

	// Record some successful requests
	for i := 0; i < 10; i++ {
		m.RecordRequest("fast.com", 500, true, false)
	}

	// Domain with fast responses should have lower delay
	fastDelay := m.SuggestedDelay("fast.com")
	if fastDelay > 1000 {
		t.Errorf("SuggestedDelay for fast domain = %d, want <= 1000", fastDelay)
	}

	// Record requests with high error rate
	for i := 0; i < 5; i++ {
		m.RecordRequest("error.com", 1000, false, false)
	}
	for i := 0; i < 5; i++ {
		m.RecordRequest("error.com", 1000, true, false)
	}

	// Domain with errors should have higher delay
	errorDelay := m.SuggestedDelay("error.com")
	if errorDelay <= fastDelay {
		t.Errorf("SuggestedDelay for error domain (%d) should be > fast domain (%d)", errorDelay, fastDelay)
	}
}

func TestManager_ErrorRate(t *testing.T) {
	m := NewManager()

	// No requests = 0 error rate
	if rate := m.ErrorRate("unknown.com"); rate != 0 {
		t.Errorf("ErrorRate for unknown domain = %f, want 0", rate)
	}

	// 50% error rate
	m.RecordRequest("half.com", 100, true, false)
	m.RecordRequest("half.com", 100, false, false)

	rate := m.ErrorRate("half.com")
	if rate < 0.49 || rate > 0.51 {
		t.Errorf("ErrorRate = %f, want ~0.5", rate)
	}
}

func TestManager_SetManualDelay(t *testing.T) {
	m := NewManager()

	// Set manual delay
	m.SetManualDelay("manual.com", 5000)

	// Record some fast requests
	for i := 0; i < 10; i++ {
		m.RecordRequest("manual.com", 100, true, false)
	}

	// Manual delay should override calculated delay
	delay := m.SuggestedDelay("manual.com")
	if delay < 5000 {
		t.Errorf("SuggestedDelay with manual override = %d, want >= 5000", delay)
	}

	// Clear manual delay
	m.ClearManualDelay("manual.com")

	// Now delay should be based on actual stats
	delay = m.SuggestedDelay("manual.com")
	if delay >= 5000 {
		t.Errorf("SuggestedDelay after clearing manual = %d, want < 5000", delay)
	}
}

func TestManager_Reset(t *testing.T) {
	m := NewManager()

	m.RecordRequest("reset.com", 100, true, false)
	if m.DomainCount() != 1 {
		t.Errorf("DomainCount = %d, want 1", m.DomainCount())
	}

	m.Reset("reset.com")
	if m.DomainCount() != 0 {
		t.Errorf("DomainCount after reset = %d, want 0", m.DomainCount())
	}

	if stats := m.Get("reset.com"); stats != nil {
		t.Error("Expected nil stats after reset")
	}
}

func TestManager_ResetAll(t *testing.T) {
	m := NewManager()

	m.RecordRequest("a.com", 100, true, false)
	m.RecordRequest("b.com", 100, true, false)
	m.RecordRequest("c.com", 100, true, false)

	if m.DomainCount() != 3 {
		t.Errorf("DomainCount = %d, want 3", m.DomainCount())
	}

	m.ResetAll()
	if m.DomainCount() != 0 {
		t.Errorf("DomainCount after ResetAll = %d, want 0", m.DomainCount())
	}
}

func TestManager_AllStats(t *testing.T) {
	m := NewManager()

	m.RecordRequest("a.com", 100, true, false)
	m.RecordRequest("b.com", 200, false, true)

	allStats := m.AllStats()
	if len(allStats) != 2 {
		t.Errorf("AllStats length = %d, want 2", len(allStats))
	}

	if _, ok := allStats["a.com"]; !ok {
		t.Error("Expected a.com in AllStats")
	}
	if _, ok := allStats["b.com"]; !ok {
		t.Error("Expected b.com in AllStats")
	}

	// Check that stats are populated correctly
	aStats := allStats["a.com"]
	if aStats.RequestCount != 1 {
		t.Errorf("a.com RequestCount = %d, want 1", aStats.RequestCount)
	}
	if aStats.SuccessCount != 1 {
		t.Errorf("a.com SuccessCount = %d, want 1", aStats.SuccessCount)
	}

	bStats := allStats["b.com"]
	if bStats.RateLimitCount != 1 {
		t.Errorf("b.com RateLimitCount = %d, want 1", bStats.RateLimitCount)
	}
}

func TestDomainStats_RecentRateLimitPenalty(t *testing.T) {
	m := NewManager()

	// Record a rate limited request
	m.RecordRequest("limited.com", 1000, false, true)

	// Immediately after rate limiting, delay should be high
	stats := m.Get("limited.com")
	stats.mu.Lock()
	stats.LastRateLimited = time.Now() // Ensure it's very recent
	stats.mu.Unlock()

	delay := m.SuggestedDelay("limited.com")
	if delay < 5000 {
		t.Errorf("SuggestedDelay immediately after rate limit = %d, want >= 5000", delay)
	}
}

func TestManager_EmptyDomain(t *testing.T) {
	m := NewManager()

	// Empty domain should not be recorded
	m.RecordRequest("", 100, true, false)

	if m.DomainCount() != 0 {
		t.Errorf("DomainCount after recording empty domain = %d, want 0", m.DomainCount())
	}
}

func TestManager_RequestCount(t *testing.T) {
	m := NewManager()

	// Unknown domain
	if count := m.RequestCount("unknown.com"); count != 0 {
		t.Errorf("RequestCount for unknown = %d, want 0", count)
	}

	m.RecordRequest("count.com", 100, true, false)
	m.RecordRequest("count.com", 100, true, false)
	m.RecordRequest("count.com", 100, true, false)

	if count := m.RequestCount("count.com"); count != 3 {
		t.Errorf("RequestCount = %d, want 3", count)
	}
}

// TestDomainStats_CacheConcurrency tests that concurrent access to the
// cache is safe and doesn't cause data races or stale reads.
func TestDomainStats_CacheConcurrency(t *testing.T) {
	m := NewManager()
	domain := "concurrent.com"

	// Record some initial data
	m.RecordRequest(domain, 100, true, false)

	// Run concurrent readers and writers
	done := make(chan bool)
	const goroutines = 10
	const iterations = 100

	// Start readers
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				delay := m.SuggestedDelay(domain)
				if delay < 0 {
					t.Errorf("SuggestedDelay returned invalid value: %d", delay)
				}
			}
			done <- true
		}()
	}

	// Start writers (invalidate cache by recording requests)
	for i := 0; i < goroutines/2; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				m.RecordRequest(domain, int64(100+j), j%2 == 0, j%5 == 0)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < goroutines+goroutines/2; i++ {
		<-done
	}

	// Verify final state is consistent
	finalDelay := m.SuggestedDelay(domain)
	if finalDelay < m.DefaultMinDelayMs || finalDelay > m.DefaultMaxDelayMs {
		t.Errorf("Final delay %d out of bounds [%d, %d]",
			finalDelay, m.DefaultMinDelayMs, m.DefaultMaxDelayMs)
	}
}
