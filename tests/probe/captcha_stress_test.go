package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/captcha"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
)

// TestCaptcha_SitekeyExtraction tests sitekey extraction from real Turnstile pages.
func TestCaptcha_SitekeyExtraction(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	br, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	defer pool.Release(br)

	page, err := br.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Test against Cloudflare's Turnstile demo
	t.Log("Testing sitekey extraction from Turnstile demo...")
	if err := page.Navigate("https://demo.turnstile.workers.dev/"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	if err := page.WaitLoad(); err != nil {
		t.Logf("WaitLoad warning: %v", err)
	}

	// Wait for Turnstile to render
	time.Sleep(3 * time.Second)

	// Try to extract sitekey
	sitekey, err := captcha.ExtractTurnstileSitekey(page)
	if err != nil {
		t.Logf("Sitekey extraction failed: %v", err)
		t.Log("Note: This may be expected if the page structure changed")
	} else {
		t.Logf("SUCCESS: Extracted sitekey: %s", sitekey)
		if len(sitekey) < 10 {
			t.Error("Sitekey seems too short")
		}
	}

	// Also test action/cdata extraction
	action := captcha.ExtractTurnstileAction(page)
	cdata := captcha.ExtractTurnstileCData(page)
	t.Logf("Action: %q, CData: %q", action, cdata)
}

// TestCaptcha_MetricsConcurrency stress tests the metrics system.
func TestCaptcha_MetricsConcurrency(t *testing.T) {
	metrics := captcha.NewMetrics()

	var successCount, failCount int64
	var wg sync.WaitGroup

	// Spawn many goroutines to stress test the metrics
	numGoroutines := 100
	opsPerGoroutine := 1000

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				provider := "2captcha"
				if j%2 == 0 {
					provider = "capsolver"
				}

				success := j%3 != 0
				if success {
					atomic.AddInt64(&successCount, 1)
				} else {
					atomic.AddInt64(&failCount, 1)
				}

				metrics.RecordAttempt(provider, success, 0.001, time.Millisecond)
				metrics.RecordError(provider, "test error")
				metrics.UpdateBalance(provider, float64(j))
				_ = metrics.GetStats(provider)
				_ = metrics.ToJSON()
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalOps := int64(numGoroutines * opsPerGoroutine)
	t.Logf("Completed %d operations in %v", totalOps, elapsed)
	t.Logf("Operations per second: %.0f", float64(totalOps)/elapsed.Seconds())

	// Verify totals are correct
	json := metrics.ToJSON()
	summary := json["_summary"].(map[string]interface{})

	expectedTotal := successCount + failCount
	actualTotal := summary["total_attempts"].(int64)

	if actualTotal != expectedTotal {
		t.Errorf("Total attempts mismatch: got %d, expected %d", actualTotal, expectedTotal)
	}

	t.Logf("Total attempts: %d (success: %d, fail: %d)", actualTotal, successCount, failCount)
}

// TestCaptcha_SolverChainFallback tests the fallback behavior.
func TestCaptcha_SolverChainFallback(t *testing.T) {
	tests := []struct {
		name           string
		nativeAttempts int
		attempts       int
		wantFallback   bool
	}{
		{"before threshold", 3, 1, false},
		{"before threshold", 3, 2, false},
		{"at threshold", 3, 3, true},
		{"after threshold", 3, 5, true},
		{"high threshold", 10, 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := captcha.NewSolverChain(captcha.SolverChainConfig{
				NativeAttempts:  tt.nativeAttempts,
				FallbackEnabled: true,
			})

			got := chain.ShouldFallback(tt.attempts)
			if got != tt.wantFallback {
				t.Errorf("ShouldFallback(%d) = %v, want %v", tt.attempts, got, tt.wantFallback)
			}
		})
	}
}

// TestCaptcha_MockExternalSolver tests external solver with mock server.
func TestCaptcha_MockExternalSolver(t *testing.T) {
	// Create mock 2Captcha server
	taskID := int64(99999)
	var createCalls, resultCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			createCalls++
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"taskId":  taskID,
			})
		case "/getTaskResult":
			resultCalls++
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"status":  "ready",
				"solution": map[string]string{
					"token": "mock-turnstile-token-12345",
				},
				"cost": "0.003",
			})
		case "/getBalance":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"balance": 25.50,
			})
		}
	}))
	defer server.Close()

	solver := captcha.NewTwoCaptchaSolver(captcha.TwoCaptchaConfig{
		APIKey:  "test-api-key",
		BaseURL: server.URL,
		Timeout: 30 * time.Second,
	})

	// Test balance check
	balance, err := solver.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error: %v", err)
	}
	if balance != 25.50 {
		t.Errorf("Balance = %f, want 25.50", balance)
	}
	t.Logf("Balance: $%.2f", balance)

	// Test solving
	result, err := solver.SolveTurnstile(context.Background(), &captcha.TurnstileRequest{
		SiteKey:   "0x4AAAAAAA",
		PageURL:   "https://example.com",
		UserAgent: "Mozilla/5.0 Test",
	})

	if err != nil {
		t.Fatalf("SolveTurnstile() error: %v", err)
	}

	if result.Token != "mock-turnstile-token-12345" {
		t.Errorf("Token = %q, want mock-turnstile-token-12345", result.Token)
	}

	if result.Cost != 0.003 {
		t.Errorf("Cost = %f, want 0.003", result.Cost)
	}

	t.Logf("Create calls: %d, Result calls: %d", createCalls, resultCalls)
	t.Logf("Token: %s, Cost: $%.4f, Time: %v", result.Token, result.Cost, result.SolveTime)
}

// TestCaptcha_RealExternalSolver tests real external solver if API key is available.
func TestCaptcha_RealExternalSolver(t *testing.T) {
	skipCI(t)

	apiKey := os.Getenv("TWOCAPTCHA_API_KEY")
	if apiKey == "" {
		t.Skip("TWOCAPTCHA_API_KEY not set")
	}

	solver := captcha.NewTwoCaptchaSolver(captcha.TwoCaptchaConfig{
		APIKey:  apiKey,
		Timeout: 120 * time.Second,
	})

	// Just check balance - don't actually solve (costs money)
	balance, err := solver.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error: %v", err)
	}

	t.Logf("2Captcha balance: $%.2f", balance)

	if balance <= 0 {
		t.Log("Warning: Balance is zero or negative")
	}
}

// TestCaptcha_CapSolverMock tests CapSolver with mock server.
func TestCaptcha_CapSolverMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"taskId":  "cap-task-12345",
			})
		case "/getTaskResult":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"status":  "ready",
				"solution": map[string]string{
					"token": "capsolver-token-xyz",
				},
			})
		case "/getBalance":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"balance": 15.75,
			})
		}
	}))
	defer server.Close()

	solver := captcha.NewCapSolverSolver(captcha.CapSolverConfig{
		APIKey:  "test-api-key",
		BaseURL: server.URL,
		Timeout: 30 * time.Second,
	})

	// Test balance
	balance, err := solver.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error: %v", err)
	}
	t.Logf("CapSolver balance: $%.2f", balance)

	// Test solving
	result, err := solver.SolveTurnstile(context.Background(), &captcha.TurnstileRequest{
		SiteKey: "test-sitekey",
		PageURL: "https://example.com",
	})

	if err != nil {
		t.Fatalf("SolveTurnstile() error: %v", err)
	}

	if result.Token != "capsolver-token-xyz" {
		t.Errorf("Token = %q, want capsolver-token-xyz", result.Token)
	}

	t.Logf("Token: %s, Provider: %s", result.Token, result.Provider)
}

// TestCaptcha_SolverWithExternalFallback tests full solver integration.
func TestCaptcha_SolverWithExternalFallback(t *testing.T) {
	skipCI(t)

	// Create mock external solver
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"taskId":  int64(12345),
			})
		case "/getTaskResult":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errorId": 0,
				"status":  "ready",
				"solution": map[string]string{
					"token": "external-solved-token",
				},
				"cost": "0.002",
			})
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Create solver chain with mock provider
	metrics := captcha.NewMetrics()
	twoCaptcha := captcha.NewTwoCaptchaSolver(captcha.TwoCaptchaConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 30 * time.Second,
	})

	chain := captcha.NewSolverChain(captcha.SolverChainConfig{
		NativeAttempts:  1, // Low threshold to trigger fallback quickly
		FallbackEnabled: true,
		Providers:       []captcha.CaptchaSolver{twoCaptcha},
		Metrics:         metrics,
	})

	// Create solver with chain
	s := solver.NewWithConfig(solver.SolverConfig{
		Pool:        pool,
		UserAgent:   "Mozilla/5.0 Test",
		SolverChain: chain,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	t.Log("Testing solver with external fallback against demo site...")

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:        "https://demo.turnstile.workers.dev/",
		Timeout:    90 * time.Second,
		Screenshot: false,
	})

	if err != nil {
		t.Logf("Solve error (may be expected): %v", err)
	}

	if result != nil {
		t.Logf("Result URL: %s", result.URL)
		t.Logf("HTML length: %d", len(result.HTML))
	}

	// Check metrics
	metricsJSON := metrics.ToJSON()
	t.Logf("Metrics: %+v", metricsJSON)
}

// TestCaptcha_ConcurrentSolves stress tests concurrent solving.
func TestCaptcha_ConcurrentSolves(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    3, // Multiple browsers
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        2048,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 Test")

	// Run concurrent solves
	numConcurrent := 3
	var wg sync.WaitGroup
	var successCount, errorCount int64

	start := time.Now()

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result, err := s.Solve(ctx, &solver.SolveOptions{
				URL:     "https://httpbin.org/html", // Simple page for stress testing
				Timeout: 30 * time.Second,
			})

			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				t.Logf("[%d] Error: %v", id, err)
			} else if result != nil {
				atomic.AddInt64(&successCount, 1)
				t.Logf("[%d] Success: URL=%s, HTML=%d bytes", id, result.URL, len(result.HTML))
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("Concurrent stress test completed in %v", elapsed)
	t.Logf("Success: %d, Errors: %d", successCount, errorCount)

	if successCount == 0 {
		t.Error("All concurrent solves failed")
	}
}

// TestCaptcha_MemoryStress tests memory usage under stress.
func TestCaptcha_MemoryStress(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 Test")

	// Run multiple sequential solves
	numSolves := 5

	for i := 0; i < numSolves; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		result, err := s.Solve(ctx, &solver.SolveOptions{
			URL:     "https://httpbin.org/html",
			Timeout: 30 * time.Second,
		})

		cancel()

		if err != nil {
			t.Logf("[%d/%d] Error: %v", i+1, numSolves, err)
		} else if result != nil {
			t.Logf("[%d/%d] Success: HTML=%d bytes", i+1, numSolves, len(result.HTML))
		}

		// Brief pause between solves
		time.Sleep(500 * time.Millisecond)
	}

	t.Log("Memory stress test completed - check for memory leaks manually")
}
