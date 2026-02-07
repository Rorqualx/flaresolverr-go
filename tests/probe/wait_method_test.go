// Test the new "wait" method for invisible Turnstile on nowsecure.nl
//go:build probe

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

func TestWaitMethod_NowSecure(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        1024,
	}

	// Create browser pool
	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Create stats manager to track method usage
	statsManager := stats.NewManager()
	defer statsManager.Close()

	// Create solver with stats manager
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	s := solver.New(pool, userAgent)
	s.SetStatsManager(statsManager)

	// Test URL
	url := "https://nowsecure.nl/"

	t.Logf("Testing %s with new 'wait' method...", url)
	t.Logf("Expected method order: wait, shadow, keyboard, widget, iframe, positional")

	// Create context with 90 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	start := time.Now()

	// Solve
	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    url,
		Timeout:                90 * time.Second,
		SkipResponseValidation: true, // Skip for testing
	})

	elapsed := time.Since(start)

	// Log method stats
	methodStats := statsManager.GetTurnstileMethodStats("nowsecure.nl")
	t.Logf("\n=== Method Statistics ===")
	for method, stats := range methodStats {
		attempts := stats[0]
		successes := stats[1]
		rate := float64(0)
		if attempts > 0 {
			rate = float64(successes) / float64(attempts) * 100
		}
		t.Logf("  %s: %d attempts, %d successes (%.1f%%)", method, attempts, successes, rate)
	}

	if err != nil {
		t.Logf("\n=== Result: FAILED ===")
		t.Logf("Error: %v", err)
		t.Logf("Time: %v", elapsed)
		t.Fatalf("Solve failed: %v", err)
	}

	// Check for cf_clearance cookie
	hasClearance := false
	for _, cookie := range result.Cookies {
		if cookie.Name == "cf_clearance" {
			hasClearance = true
			t.Logf("\n=== SUCCESS! ===")
			t.Logf("Got cf_clearance cookie!")
			t.Logf("Cookie value (first 50 chars): %s...", cookie.Value[:minInt(50, len(cookie.Value))])
			break
		}
	}

	t.Logf("\n=== Result Summary ===")
	t.Logf("Time: %v", elapsed)
	t.Logf("Final URL: %s", result.URL)
	t.Logf("Status: %d", result.StatusCode)
	t.Logf("Cookies: %d", len(result.Cookies))
	t.Logf("Has cf_clearance: %v", hasClearance)
	t.Logf("HTML length: %d", len(result.HTML))

	if !hasClearance {
		t.Error("Did not get cf_clearance cookie - Turnstile may not have been solved")
	}
}

func TestWaitMethod_MultipleRuns(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        1024,
	}

	// Create browser pool
	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Create stats manager to track method learning
	statsManager := stats.NewManager()
	defer statsManager.Close()

	// Create solver
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	s := solver.New(pool, userAgent)
	s.SetStatsManager(statsManager)

	url := "https://nowsecure.nl/"
	runs := 3
	successes := 0
	var totalTime time.Duration

	t.Logf("Running %d iterations to test method learning...", runs)

	for i := 0; i < runs; i++ {
		t.Logf("\n--- Run %d/%d ---", i+1, runs)

		// Check method order before this run
		order := statsManager.GetTurnstileMethodOrder("nowsecure.nl")
		t.Logf("Method order: %v", order)

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		start := time.Now()

		result, err := s.Solve(ctx, &solver.SolveOptions{
			URL:                    url,
			Timeout:                90 * time.Second,
			SkipResponseValidation: true,
		})

		elapsed := time.Since(start)
		totalTime += elapsed
		cancel()

		if err != nil {
			t.Logf("Run %d FAILED: %v (took %v)", i+1, err, elapsed)
			continue
		}

		// Check for cf_clearance
		for _, cookie := range result.Cookies {
			if cookie.Name == "cf_clearance" {
				successes++
				t.Logf("Run %d SUCCESS! Got cf_clearance (took %v)", i+1, elapsed)
				break
			}
		}

		// Wait between runs
		if i < runs-1 {
			time.Sleep(5 * time.Second)
		}
	}

	// Final stats
	t.Logf("\n=== Final Results ===")
	t.Logf("Success rate: %d/%d (%.1f%%)", successes, runs, float64(successes)/float64(runs)*100)
	t.Logf("Average time: %v", totalTime/time.Duration(runs))

	// Log final method stats
	methodStats := statsManager.GetTurnstileMethodStats("nowsecure.nl")
	t.Logf("\n=== Method Statistics ===")
	for method, stats := range methodStats {
		attempts := stats[0]
		successCount := stats[1]
		rate := float64(0)
		if attempts > 0 {
			rate = float64(successCount) / float64(attempts) * 100
		}
		t.Logf("  %s: %d attempts, %d successes (%.1f%%)", method, attempts, successCount, rate)
	}

	// Log final method order
	finalOrder := statsManager.GetTurnstileMethodOrder("nowsecure.nl")
	t.Logf("\nFinal method order: %v", finalOrder)

	if successes == 0 {
		t.Error("All runs failed - wait method may not be working")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
