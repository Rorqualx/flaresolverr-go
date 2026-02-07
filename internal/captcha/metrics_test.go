package captcha

import (
	"testing"
	"time"
)

func TestMetrics_RecordAttempt(t *testing.T) {
	m := NewMetrics()

	// Record a successful attempt
	m.RecordAttempt("2captcha", true, 0.002, 15*time.Second)

	stats := m.GetStats("2captcha")
	if stats == nil {
		t.Fatal("expected stats for 2captcha")
	}

	if stats.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", stats.Attempts)
	}

	if stats.Successes != 1 {
		t.Errorf("Successes = %d, want 1", stats.Successes)
	}

	if stats.Failures != 0 {
		t.Errorf("Failures = %d, want 0", stats.Failures)
	}

	if stats.TotalCost != 0.002 {
		t.Errorf("TotalCost = %f, want 0.002", stats.TotalCost)
	}

	if stats.TotalTimeMs != 15000 {
		t.Errorf("TotalTimeMs = %d, want 15000", stats.TotalTimeMs)
	}
}

func TestMetrics_RecordAttempt_Failure(t *testing.T) {
	m := NewMetrics()

	m.RecordAttempt("capsolver", false, 0, 5*time.Second)

	stats := m.GetStats("capsolver")
	if stats == nil {
		t.Fatal("expected stats for capsolver")
	}

	if stats.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", stats.Attempts)
	}

	if stats.Successes != 0 {
		t.Errorf("Successes = %d, want 0", stats.Successes)
	}

	if stats.Failures != 1 {
		t.Errorf("Failures = %d, want 1", stats.Failures)
	}

	// Cost should not be added for failures
	if stats.TotalCost != 0 {
		t.Errorf("TotalCost = %f, want 0", stats.TotalCost)
	}
}

func TestMetrics_RecordError(t *testing.T) {
	m := NewMetrics()

	m.RecordError("2captcha", "API key invalid")

	stats := m.GetStats("2captcha")
	if stats == nil {
		t.Fatal("expected stats for 2captcha")
	}

	if stats.LastError != "API key invalid" {
		t.Errorf("LastError = %q, want %q", stats.LastError, "API key invalid")
	}

	if stats.LastErrorAt.IsZero() {
		t.Error("LastErrorAt should not be zero")
	}
}

func TestMetrics_UpdateBalance(t *testing.T) {
	m := NewMetrics()

	m.UpdateBalance("2captcha", 5.50)

	stats := m.GetStats("2captcha")
	if stats == nil {
		t.Fatal("expected stats for 2captcha")
	}

	if stats.LastBalance != 5.50 {
		t.Errorf("LastBalance = %f, want 5.50", stats.LastBalance)
	}
}

func TestMetrics_GetStats_NotFound(t *testing.T) {
	m := NewMetrics()

	stats := m.GetStats("unknown")
	if stats != nil {
		t.Error("expected nil for unknown provider")
	}
}

func TestMetrics_ToJSON(t *testing.T) {
	m := NewMetrics()

	// Add some data
	m.RecordAttempt("2captcha", true, 0.002, 10*time.Second)
	m.RecordAttempt("2captcha", true, 0.002, 20*time.Second)
	m.RecordAttempt("2captcha", false, 0, 5*time.Second)
	m.RecordAttempt("capsolver", true, 0.003, 8*time.Second)

	result := m.ToJSON()

	// Check 2captcha stats
	twoCaptcha, ok := result["2captcha"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 2captcha in result")
	}

	if twoCaptcha["attempts"].(int64) != 3 {
		t.Errorf("2captcha attempts = %v, want 3", twoCaptcha["attempts"])
	}

	if twoCaptcha["successes"].(int64) != 2 {
		t.Errorf("2captcha successes = %v, want 2", twoCaptcha["successes"])
	}

	// Check summary
	summary, ok := result["_summary"].(map[string]interface{})
	if !ok {
		t.Fatal("expected _summary in result")
	}

	if summary["total_attempts"].(int64) != 4 {
		t.Errorf("total_attempts = %v, want 4", summary["total_attempts"])
	}

	if summary["total_successes"].(int64) != 3 {
		t.Errorf("total_successes = %v, want 3", summary["total_successes"])
	}
}

func TestMetrics_SuccessRate(t *testing.T) {
	m := NewMetrics()

	// No data
	if rate := m.SuccessRate("2captcha"); rate != 0 {
		t.Errorf("SuccessRate with no data = %f, want 0", rate)
	}

	// Add data
	m.RecordAttempt("2captcha", true, 0, time.Second)
	m.RecordAttempt("2captcha", true, 0, time.Second)
	m.RecordAttempt("2captcha", false, 0, time.Second)
	m.RecordAttempt("2captcha", false, 0, time.Second)

	rate := m.SuccessRate("2captcha")
	expected := 50.0 // 2 out of 4

	if rate != expected {
		t.Errorf("SuccessRate = %f, want %f", rate, expected)
	}
}

func TestMetrics_AverageTime(t *testing.T) {
	m := NewMetrics()

	// No data
	if avg := m.AverageTime("2captcha"); avg != 0 {
		t.Errorf("AverageTime with no data = %v, want 0", avg)
	}

	// Add data
	m.RecordAttempt("2captcha", true, 0, 10*time.Second)
	m.RecordAttempt("2captcha", true, 0, 20*time.Second)

	avg := m.AverageTime("2captcha")
	expected := 15 * time.Second

	if avg != expected {
		t.Errorf("AverageTime = %v, want %v", avg, expected)
	}
}

func TestMetrics_TotalCost(t *testing.T) {
	m := NewMetrics()

	// No data
	if cost := m.TotalCost(); cost != 0 {
		t.Errorf("TotalCost with no data = %f, want 0", cost)
	}

	// Add data across providers
	m.RecordAttempt("2captcha", true, 0.002, time.Second)
	m.RecordAttempt("2captcha", true, 0.002, time.Second)
	m.RecordAttempt("capsolver", true, 0.003, time.Second)

	cost := m.TotalCost()
	expected := 0.007

	if cost != expected {
		t.Errorf("TotalCost = %f, want %f", cost, expected)
	}
}

func TestMetrics_Reset(t *testing.T) {
	m := NewMetrics()

	// Add data
	m.RecordAttempt("2captcha", true, 0.002, time.Second)
	m.RecordAttempt("capsolver", true, 0.003, time.Second)

	// Reset
	m.Reset()

	// Verify cleared
	if stats := m.GetStats("2captcha"); stats != nil {
		t.Error("expected nil stats after reset")
	}

	if cost := m.TotalCost(); cost != 0 {
		t.Errorf("TotalCost after reset = %f, want 0", cost)
	}
}

func TestMetrics_Concurrent(t *testing.T) {
	m := NewMetrics()

	// Run concurrent operations
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				m.RecordAttempt("2captcha", j%2 == 0, 0.001, time.Millisecond)
				m.RecordError("2captcha", "test error")
				m.UpdateBalance("2captcha", 1.0)
				_ = m.GetStats("2captcha")
				_ = m.ToJSON()
				_ = m.SuccessRate("2captcha")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify data is consistent
	stats := m.GetStats("2captcha")
	if stats == nil {
		t.Fatal("expected stats")
	}

	if stats.Attempts != 1000 {
		t.Errorf("Attempts = %d, want 1000", stats.Attempts)
	}
}
