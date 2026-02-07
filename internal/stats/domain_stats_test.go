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
	defer m.Close()

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

func TestManager_RecordSolveOutcome_Native(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Record native solve attempts
	m.RecordSolveOutcome("solve.com", "native", true, 1000)
	m.RecordSolveOutcome("solve.com", "native", true, 2000)
	m.RecordSolveOutcome("solve.com", "native", false, 500)

	stats := m.Get("solve.com")
	if stats == nil {
		t.Fatal("Expected stats for solve.com")
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.SolveStats.NativeAttempts != 3 {
		t.Errorf("NativeAttempts = %d, want 3", stats.SolveStats.NativeAttempts)
	}
	if stats.SolveStats.NativeSuccesses != 2 {
		t.Errorf("NativeSuccesses = %d, want 2", stats.SolveStats.NativeSuccesses)
	}
	if stats.SolveStats.NativeTotalTimeMs != 3500 {
		t.Errorf("NativeTotalTimeMs = %d, want 3500", stats.SolveStats.NativeTotalTimeMs)
	}
	if stats.SolveStats.LastSuccessMethod != "native" {
		t.Errorf("LastSuccessMethod = %s, want 'native'", stats.SolveStats.LastSuccessMethod)
	}
}

func TestManager_RecordSolveOutcome_External(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Record external solve attempts
	m.RecordSolveOutcome("external.com", "2captcha", true, 5000)
	m.RecordSolveOutcome("external.com", "2captcha", false, 10000)
	m.RecordSolveOutcome("external.com", "capsolver", true, 3000)

	stats := m.Get("external.com")
	if stats == nil {
		t.Fatal("Expected stats for external.com")
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if stats.SolveStats.ExternalAttempts["2captcha"] != 2 {
		t.Errorf("2captcha attempts = %d, want 2", stats.SolveStats.ExternalAttempts["2captcha"])
	}
	if stats.SolveStats.ExternalSuccesses["2captcha"] != 1 {
		t.Errorf("2captcha successes = %d, want 1", stats.SolveStats.ExternalSuccesses["2captcha"])
	}
	if stats.SolveStats.ExternalAttempts["capsolver"] != 1 {
		t.Errorf("capsolver attempts = %d, want 1", stats.SolveStats.ExternalAttempts["capsolver"])
	}
	if stats.SolveStats.ExternalSuccesses["capsolver"] != 1 {
		t.Errorf("capsolver successes = %d, want 1", stats.SolveStats.ExternalSuccesses["capsolver"])
	}
	if stats.SolveStats.LastSuccessMethod != "capsolver" {
		t.Errorf("LastSuccessMethod = %s, want 'capsolver'", stats.SolveStats.LastSuccessMethod)
	}
}

func TestManager_GetPreferredSolveMethod(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// No history = empty
	if method := m.GetPreferredSolveMethod("unknown.com"); method != "" {
		t.Errorf("GetPreferredSolveMethod for unknown = %q, want ''", method)
	}

	// Native with good success rate should be preferred
	m.RecordSolveOutcome("native.com", "native", true, 1000)
	m.RecordSolveOutcome("native.com", "native", true, 1000)
	m.RecordSolveOutcome("native.com", "native", false, 1000)
	// 66% success rate

	if method := m.GetPreferredSolveMethod("native.com"); method != "native" {
		t.Errorf("GetPreferredSolveMethod for native.com = %q, want 'native'", method)
	}

	// External with better success rate should win over poor native (<20%)
	m.RecordSolveOutcome("mixed.com", "native", false, 1000)
	m.RecordSolveOutcome("mixed.com", "native", false, 1000)
	m.RecordSolveOutcome("mixed.com", "native", false, 1000)
	m.RecordSolveOutcome("mixed.com", "native", false, 1000)
	m.RecordSolveOutcome("mixed.com", "native", false, 1000)
	m.RecordSolveOutcome("mixed.com", "native", false, 1000) // 0% native (6 failures)
	m.RecordSolveOutcome("mixed.com", "2captcha", true, 1000)
	m.RecordSolveOutcome("mixed.com", "2captcha", true, 1000) // 100% external

	if method := m.GetPreferredSolveMethod("mixed.com"); method != "2captcha" {
		t.Errorf("GetPreferredSolveMethod for mixed.com = %q, want '2captcha'", method)
	}
}

func TestManager_ShouldSkipNative(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// No history = don't skip
	if m.ShouldSkipNative("unknown.com") {
		t.Error("ShouldSkipNative for unknown domain should be false")
	}

	// Too few attempts = don't skip
	m.RecordSolveOutcome("new.com", "native", false, 1000)
	if m.ShouldSkipNative("new.com") {
		t.Error("ShouldSkipNative with <5 attempts should be false")
	}

	// Poor success rate with sufficient attempts = skip
	for i := 0; i < 10; i++ {
		m.RecordSolveOutcome("bad.com", "native", false, 1000)
	}
	m.RecordSolveOutcome("bad.com", "native", true, 1000) // 9% success rate

	if !m.ShouldSkipNative("bad.com") {
		t.Error("ShouldSkipNative for bad.com should be true")
	}

	// Good success rate = don't skip
	for i := 0; i < 5; i++ {
		m.RecordSolveOutcome("good.com", "native", true, 1000)
	}
	if m.ShouldSkipNative("good.com") {
		t.Error("ShouldSkipNative for good.com should be false")
	}
}

func TestManager_ShouldSkipNative_WithPrefs(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Set preferences to disable native
	m.SetDomainSolverPrefs("prefs.com", &SolverPreferences{
		DisableMethods: []string{"native"},
	})

	// Even with no history, should skip due to preferences
	if !m.ShouldSkipNative("prefs.com") {
		t.Error("ShouldSkipNative should respect DisableMethods preference")
	}
}

func TestManager_SetDomainSolverPrefs(t *testing.T) {
	m := NewManager()
	defer m.Close()

	prefs := &SolverPreferences{
		NativeFirst:       true,
		NativeAttempts:    intPtr(5),
		PreferredProvider: "capsolver",
		TimeoutOverrideMs: intPtr(60000),
	}

	m.SetDomainSolverPrefs("prefs.com", prefs)

	got := m.GetDomainSolverPrefs("prefs.com")
	if got == nil {
		t.Fatal("Expected preferences to be set")
	}

	if got.PreferredProvider != "capsolver" {
		t.Errorf("PreferredProvider = %s, want 'capsolver'", got.PreferredProvider)
	}
	if got.NativeAttempts == nil || *got.NativeAttempts != 5 {
		t.Errorf("NativeAttempts = %v, want 5", got.NativeAttempts)
	}
}

func TestManager_GetDomainSolverPrefs_NotSet(t *testing.T) {
	m := NewManager()
	defer m.Close()

	if prefs := m.GetDomainSolverPrefs("unknown.com"); prefs != nil {
		t.Errorf("Expected nil preferences for unknown domain, got %v", prefs)
	}
}

func TestManager_NativeSuccessRate(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Unknown domain = -1
	if rate := m.NativeSuccessRate("unknown.com"); rate != -1 {
		t.Errorf("NativeSuccessRate for unknown = %f, want -1", rate)
	}

	// 50% success rate
	m.RecordSolveOutcome("half.com", "native", true, 1000)
	m.RecordSolveOutcome("half.com", "native", false, 1000)

	rate := m.NativeSuccessRate("half.com")
	if rate < 0.49 || rate > 0.51 {
		t.Errorf("NativeSuccessRate = %f, want ~0.5", rate)
	}

	// 100% success rate
	m.RecordSolveOutcome("perfect.com", "native", true, 1000)
	m.RecordSolveOutcome("perfect.com", "native", true, 1000)

	if rate := m.NativeSuccessRate("perfect.com"); rate != 1.0 {
		t.Errorf("NativeSuccessRate = %f, want 1.0", rate)
	}
}

func TestManager_SolveStats_InAllStats(t *testing.T) {
	m := NewManager()
	defer m.Close()

	m.RecordSolveOutcome("stats.com", "native", true, 1000)
	m.RecordSolveOutcome("stats.com", "native", false, 2000)
	m.RecordSolveOutcome("stats.com", "2captcha", true, 5000)

	allStats := m.AllStats()
	statsJSON, ok := allStats["stats.com"]
	if !ok {
		t.Fatal("Expected stats.com in AllStats")
	}

	if statsJSON.SolveStats == nil {
		t.Fatal("Expected SolveStats in DomainStatsJSON")
	}

	if statsJSON.SolveStats.NativeAttempts != 2 {
		t.Errorf("NativeAttempts = %d, want 2", statsJSON.SolveStats.NativeAttempts)
	}
	if statsJSON.SolveStats.NativeSuccesses != 1 {
		t.Errorf("NativeSuccesses = %d, want 1", statsJSON.SolveStats.NativeSuccesses)
	}
	if statsJSON.SolveStats.NativeAvgTimeMs != 1500 {
		t.Errorf("NativeAvgTimeMs = %d, want 1500", statsJSON.SolveStats.NativeAvgTimeMs)
	}

	// Success rate should be 0.5
	if statsJSON.SolveStats.NativeSuccessRate < 0.49 || statsJSON.SolveStats.NativeSuccessRate > 0.51 {
		t.Errorf("NativeSuccessRate = %f, want ~0.5", statsJSON.SolveStats.NativeSuccessRate)
	}

	if statsJSON.SolveStats.ExternalAttempts["2captcha"] != 1 {
		t.Errorf("ExternalAttempts[2captcha] = %d, want 1", statsJSON.SolveStats.ExternalAttempts["2captcha"])
	}
}

func TestManager_RecordSolveOutcome_EmptyInputs(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Empty domain should not create stats
	m.RecordSolveOutcome("", "native", true, 1000)
	if m.DomainCount() != 0 {
		t.Error("Empty domain should not create stats")
	}

	// Empty method should not create stats
	m.RecordSolveOutcome("test.com", "", true, 1000)
	if m.DomainCount() != 0 {
		t.Error("Empty method should not create stats")
	}
}

func TestManager_GetPreferredSolveMethod_WithPreferredProvider(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Set preferred provider in preferences
	m.SetDomainSolverPrefs("prefs.com", &SolverPreferences{
		PreferredProvider: "capsolver",
	})

	// Record some solve history
	m.RecordSolveOutcome("prefs.com", "native", true, 1000)
	m.RecordSolveOutcome("prefs.com", "2captcha", true, 1000)

	// Should return preferred provider from preferences, not history
	if method := m.GetPreferredSolveMethod("prefs.com"); method != "capsolver" {
		t.Errorf("GetPreferredSolveMethod = %q, want 'capsolver'", method)
	}
}

// Helper function for creating int pointers
func intPtr(i int) *int {
	return &i
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

func TestManager_RecordTurnstileMethod(t *testing.T) {
	m := NewManager()
	defer m.Close()

	domain := "turnstile.example.com"

	// Record some method attempts
	m.RecordTurnstileMethod(domain, "shadow", false)
	m.RecordTurnstileMethod(domain, "shadow", false)
	m.RecordTurnstileMethod(domain, "keyboard", true)
	m.RecordTurnstileMethod(domain, "keyboard", true)
	m.RecordTurnstileMethod(domain, "keyboard", false)

	// Get best method - keyboard should win (2/3 = 67% success vs 0/2 = 0%)
	best := m.GetBestTurnstileMethod(domain)
	if best != "keyboard" {
		t.Errorf("GetBestTurnstileMethod = %q, want 'keyboard'", best)
	}
}

func TestManager_GetTurnstileMethodOrder(t *testing.T) {
	m := NewManager()
	defer m.Close()

	domain := "order.example.com"

	// Default order when no history - "wait" should be first for invisible Turnstile
	order := m.GetTurnstileMethodOrder(domain)
	expected := []string{"wait", "shadow", "keyboard", "widget", "iframe", "positional"}
	if len(order) != len(expected) {
		t.Errorf("GetTurnstileMethodOrder() length = %d, want %d", len(order), len(expected))
	}
	for i, method := range expected {
		if order[i] != method {
			t.Errorf("order[%d] = %q, want %q", i, order[i], method)
		}
	}

	// Record history with keyboard being most successful
	m.RecordTurnstileMethod(domain, "shadow", false)
	m.RecordTurnstileMethod(domain, "shadow", false)
	m.RecordTurnstileMethod(domain, "keyboard", true)
	m.RecordTurnstileMethod(domain, "widget", true)
	m.RecordTurnstileMethod(domain, "widget", false)

	// Keyboard should come first (100% success rate = 1.0)
	order = m.GetTurnstileMethodOrder(domain)
	if order[0] != "keyboard" {
		t.Errorf("First method should be 'keyboard', got %q", order[0])
	}

	// Widget should come second (50% success rate = 0.5)
	if order[1] != "widget" {
		t.Errorf("Second method should be 'widget', got %q", order[1])
	}

	// Untried methods (wait, iframe, positional) should be before failing methods
	// They have score = 0.5 (neutral), which ties with widget but comes after in sort stability
	// Shadow has 0% success with 2 failures = -0.2 score, so it should be last
	if order[5] != "shadow" {
		t.Errorf("Last method should be 'shadow' (0%% success, deprioritized), got %q", order[5])
	}

	// Verify untried methods are in the middle (before shadow)
	untriedMethods := []string{order[2], order[3], order[4]}
	hasWait := false
	hasIframe := false
	hasPositional := false
	for _, m := range untriedMethods {
		if m == "wait" {
			hasWait = true
		}
		if m == "iframe" {
			hasIframe = true
		}
		if m == "positional" {
			hasPositional = true
		}
	}
	if !hasWait || !hasIframe || !hasPositional {
		t.Errorf("Untried methods (wait, iframe, positional) should be in positions 3-5, got %v", untriedMethods)
	}
}

func TestManager_TurnstileMethod_EmptyInputs(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Empty domain should not create stats
	m.RecordTurnstileMethod("", "keyboard", true)
	if m.DomainCount() != 0 {
		t.Error("Empty domain should not create stats")
	}

	// Empty method should not create stats
	m.RecordTurnstileMethod("test.com", "", true)
	if m.DomainCount() != 0 {
		t.Error("Empty method should not create stats")
	}
}

func TestTurnstileMethodStats_GetBestMethod(t *testing.T) {
	// Test nil receiver
	var nilStats *TurnstileMethodStats
	if nilStats.GetBestMethod() != "" {
		t.Error("Nil receiver should return empty string")
	}

	// Test empty stats
	emptyStats := &TurnstileMethodStats{}
	if emptyStats.GetBestMethod() != "" {
		t.Error("Empty stats should return empty string")
	}

	// Test with recent success (should prefer it)
	recentStats := &TurnstileMethodStats{
		MethodAttempts:  map[string]int64{"keyboard": 5, "shadow": 10},
		MethodSuccesses: map[string]int64{"keyboard": 3, "shadow": 8},
		LastSuccess:     "keyboard",
		LastSuccessTime: time.Now(), // Recent
	}
	// keyboard has 60% rate but was most recent, shadow has 80%
	// With recent success, keyboard should still be preferred
	if recentStats.GetBestMethod() != "keyboard" {
		t.Errorf("Recent success should prefer 'keyboard', got %q", recentStats.GetBestMethod())
	}

	// Test with old success (should use success rate)
	oldStats := &TurnstileMethodStats{
		MethodAttempts:  map[string]int64{"keyboard": 5, "shadow": 10},
		MethodSuccesses: map[string]int64{"keyboard": 3, "shadow": 8},
		LastSuccess:     "keyboard",
		LastSuccessTime: time.Now().Add(-2 * time.Hour), // Old
	}
	// keyboard has 60%, shadow has 80% - should prefer shadow
	if oldStats.GetBestMethod() != "shadow" {
		t.Errorf("Old success should use rate, expect 'shadow', got %q", oldStats.GetBestMethod())
	}
}
