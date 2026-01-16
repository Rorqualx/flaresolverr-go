package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	// Record some metrics so they appear in output
	RecordRequest("test", "ok", 1*time.Second)
	UpdatePoolMetrics(3, 2, 1, 0)
	UpdateSessionMetrics(1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()

	// Check for some expected metrics (gauges always appear, counters appear after recording)
	expectedMetrics := []string{
		"flaresolverr_browser_pool_size",
		"flaresolverr_browser_pool_available",
		"flaresolverr_active_sessions",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("Expected metric %q not found in output", metric)
		}
	}
}

func TestSetBuildInfo(t *testing.T) {
	SetBuildInfo("1.0.0", "go1.22")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "flaresolverr_build_info") {
		t.Error("Expected flaresolverr_build_info metric")
	}
	if !strings.Contains(body, "version=\"1.0.0\"") {
		t.Error("Expected version label in build_info")
	}
	if !strings.Contains(body, "go_version=\"go1.22\"") {
		t.Error("Expected go_version label in build_info")
	}
}

func TestRecordRequest(t *testing.T) {
	// Record some requests
	RecordRequest("request.get", "ok", 1*time.Second)
	RecordRequest("request.get", "error", 500*time.Millisecond)
	RecordRequest("request.post", "ok", 2*time.Second)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()

	// Check that request metrics are recorded
	if !strings.Contains(body, "flaresolverr_requests_total") {
		t.Error("Expected flaresolverr_requests_total metric")
	}
	if !strings.Contains(body, "flaresolverr_request_duration_seconds") {
		t.Error("Expected flaresolverr_request_duration_seconds metric")
	}
}

func TestRecordChallengeSolved(t *testing.T) {
	RecordChallengeSolved("javascript")
	RecordChallengeSolved("turnstile")
	RecordChallengeSolved("javascript")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "flaresolverr_challenges_solved_total") {
		t.Error("Expected flaresolverr_challenges_solved_total metric")
	}
}

func TestRecordChallengeFailed(t *testing.T) {
	RecordChallengeFailed("timeout")
	RecordChallengeFailed("access_denied")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "flaresolverr_challenges_failed_total") {
		t.Error("Expected flaresolverr_challenges_failed_total metric")
	}
}

func TestUpdatePoolMetrics(t *testing.T) {
	UpdatePoolMetrics(3, 2, 100, 5)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "flaresolverr_browser_pool_size 3") {
		t.Error("Expected browser_pool_size to be 3")
	}
	if !strings.Contains(body, "flaresolverr_browser_pool_available 2") {
		t.Error("Expected browser_pool_available to be 2")
	}
}

func TestUpdateSessionMetrics(t *testing.T) {
	UpdateSessionMetrics(5)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "flaresolverr_active_sessions 5") {
		t.Error("Expected active_sessions to be 5")
	}
}

func TestStartMemoryCollector(t *testing.T) {
	stopCh := make(chan struct{})

	// Start collector with short interval
	go StartMemoryCollector(50*time.Millisecond, stopCh)

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)

	// Stop it
	close(stopCh)

	// Verify memory metrics were updated
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler().ServeHTTP(w, req)

	body := w.Body.String()

	// Memory metrics should have non-zero values
	if !strings.Contains(body, "flaresolverr_memory_usage_bytes") {
		t.Error("Expected flaresolverr_memory_usage_bytes metric")
	}
	if !strings.Contains(body, "flaresolverr_memory_sys_bytes") {
		t.Error("Expected flaresolverr_memory_sys_bytes metric")
	}
	if !strings.Contains(body, "flaresolverr_goroutines") {
		t.Error("Expected flaresolverr_goroutines metric")
	}
}
