package probe

import (
	"context"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
)

// TestTurnstile_MethodLearning runs multiple solve attempts and tracks method learning.
// This test verifies that the system learns which methods work for a domain.
func TestTurnstile_MethodLearning(t *testing.T) {
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

	// Create stats manager for method learning
	statsManager := stats.NewManager()
	defer statsManager.Close()

	// Create solver with stats manager
	s := solver.New(pool, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	s.SetStatsManager(statsManager)

	domain := "nowsecure.nl"
	url := "https://nowsecure.nl/"

	// Run 10 iterations with short timeouts to track learning
	const iterations = 10
	const perAttemptTimeout = 15 * time.Second

	t.Logf("Running %d iterations to test method learning...", iterations)
	t.Log("Each iteration has a short timeout - we're testing learning, not solving")
	t.Log("")

	for i := 1; i <= iterations; i++ {
		// Get method order BEFORE the attempt
		orderBefore := statsManager.GetTurnstileMethodOrder(domain)

		ctx, cancel := context.WithTimeout(context.Background(), perAttemptTimeout)

		t.Logf("=== Iteration %d/%d ===", i, iterations)
		t.Logf("Method order: %v", orderBefore)

		startTime := time.Now()
		result, err := s.Solve(ctx, &solver.SolveOptions{
			URL:     url,
			Timeout: perAttemptTimeout,
		})
		elapsed := time.Since(startTime)

		cancel()

		if err != nil {
			t.Logf("Result: timeout/error after %v (expected)", elapsed.Round(time.Millisecond))
		} else if result != nil {
			t.Logf("Result: success after %v!", elapsed.Round(time.Millisecond))
		}

		// Print method stats using public API
		printMethodStats(t, statsManager, domain)

		// Get method order AFTER the attempt to see if it changed
		orderAfter := statsManager.GetTurnstileMethodOrder(domain)
		if !slicesEqual(orderBefore, orderAfter) {
			t.Logf(">>> Method order CHANGED: %v -> %v", orderBefore, orderAfter)
		}

		t.Log("")

		// Small delay between iterations
		time.Sleep(500 * time.Millisecond)
	}

	// Final summary
	t.Log("=== FINAL SUMMARY ===")
	finalOrder := statsManager.GetTurnstileMethodOrder(domain)
	t.Logf("Final method order: %v", finalOrder)

	bestMethod := statsManager.GetBestTurnstileMethod(domain)
	if bestMethod != "" {
		t.Logf("Best method: %s", bestMethod)
	}

	// Check if order changed from default
	defaultOrder := []string{"shadow", "keyboard", "widget", "iframe", "positional"}
	if !slicesEqual(finalOrder, defaultOrder) {
		t.Log("SUCCESS: Method order has been learned and changed from default!")
	} else {
		t.Log("NOTE: Method order still matches default (may need more iterations or a success)")
	}
}

// slicesEqual checks if two string slices are equal.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestTurnstile_MethodLearningQuick is a faster version that just verifies stats are being recorded.
func TestTurnstile_MethodLearningQuick(t *testing.T) {
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

	// Create stats manager for method learning
	statsManager := stats.NewManager()
	defer statsManager.Close()

	// Create solver with stats manager
	s := solver.New(pool, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	s.SetStatsManager(statsManager)

	domain := "nowsecure.nl"
	url := "https://nowsecure.nl/"

	// Run 3 quick iterations
	const iterations = 3
	const perAttemptTimeout = 20 * time.Second

	t.Logf("Running %d quick iterations...", iterations)

	for i := 1; i <= iterations; i++ {
		orderBefore := statsManager.GetTurnstileMethodOrder(domain)
		t.Logf("Iteration %d - Order before: %v", i, orderBefore)

		ctx, cancel := context.WithTimeout(context.Background(), perAttemptTimeout)
		_, _ = s.Solve(ctx, &solver.SolveOptions{
			URL:     url,
			Timeout: perAttemptTimeout,
		})
		cancel()

		orderAfter := statsManager.GetTurnstileMethodOrder(domain)
		t.Logf("Iteration %d - Order after:  %v", i, orderAfter)

		if !slicesEqual(orderBefore, orderAfter) {
			t.Logf(">>> ORDER CHANGED!")
		}

		// Print attempt counts
		printMethodStats(t, statsManager, domain)
		t.Log("")

		time.Sleep(500 * time.Millisecond)
	}

	// Final check
	finalOrder := statsManager.GetTurnstileMethodOrder(domain)
	defaultOrder := []string{"shadow", "keyboard", "widget", "iframe", "positional"}

	if !slicesEqual(finalOrder, defaultOrder) {
		t.Logf("SUCCESS: Learning detected! Final order: %v", finalOrder)
	} else {
		t.Logf("Final order matches default: %v", finalOrder)
	}
}

func printMethodStats(t *testing.T, sm *stats.Manager, domain string) {
	// Get Turnstile method stats
	methodStats := sm.GetTurnstileMethodStats(domain)
	if methodStats != nil {
		t.Log("  Method stats:")
		for method, stats := range methodStats {
			attempts, successes := stats[0], stats[1]
			rate := float64(0)
			if attempts > 0 {
				rate = float64(successes) / float64(attempts) * 100
			}
			t.Logf("    %s: %d attempts, %d successes (%.0f%%)", method, attempts, successes, rate)
		}
	}

	// Also check best method
	best := sm.GetBestTurnstileMethod(domain)
	if best != "" {
		t.Logf("  Best Turnstile method: %s", best)
	}
}
