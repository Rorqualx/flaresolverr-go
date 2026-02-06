package probe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
)

// TestTurnstile_NowSecure tests against nowsecure.nl which has Cloudflare protection.
// This site is specifically designed for testing anti-bot detection.
func TestTurnstile_NowSecure(t *testing.T) {
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

	s := solver.New(pool, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	t.Log("Starting Turnstile test against nowsecure.nl...")

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:        "https://nowsecure.nl/",
		Timeout:    120 * time.Second,
		Screenshot: true,
	})

	if err != nil {
		t.Logf("Solve error (may be expected): %v", err)
		// Don't fail immediately - check if we got partial results
	}

	if result != nil {
		t.Logf("Result URL: %s", result.URL)
		t.Logf("Cookies count: %d", len(result.Cookies))
		t.Logf("HTML length: %d", len(result.HTML))
		t.Logf("Turnstile token: %s", truncate(result.TurnstileToken, 50))

		// Check for cf_clearance cookie (indicates successful challenge bypass)
		hasClearance := false
		for _, c := range result.Cookies {
			t.Logf("Cookie: %s = %s", c.Name, truncate(c.Value, 30))
			if c.Name == "cf_clearance" {
				hasClearance = true
			}
		}

		if hasClearance {
			t.Log("SUCCESS: Got cf_clearance cookie!")
		} else {
			t.Log("WARNING: No cf_clearance cookie found")
		}

		// Check if we got past the challenge page
		if strings.Contains(strings.ToLower(result.HTML), "just a moment") {
			t.Log("WARNING: Still on challenge page")
		} else if strings.Contains(result.HTML, "nowsecure") {
			t.Log("SUCCESS: Got past challenge page")
		}
	}
}

// TestTurnstile_CloudflareDemo tests against Cloudflare's official Turnstile demo.
func TestTurnstile_CloudflareDemo(t *testing.T) {
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

	s := solver.New(pool, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	t.Log("Starting Turnstile test against Cloudflare demo...")

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:        "https://demo.turnstile.workers.dev/",
		Timeout:    90 * time.Second,
		Screenshot: true,
	})

	if err != nil {
		t.Logf("Solve error: %v", err)
	}

	if result != nil {
		t.Logf("Result URL: %s", result.URL)
		t.Logf("HTML length: %d", len(result.HTML))
		t.Logf("Turnstile token present: %v", result.TurnstileToken != "")

		if result.TurnstileToken != "" {
			t.Logf("Turnstile token (first 50 chars): %s", truncate(result.TurnstileToken, 50))
			t.Log("SUCCESS: Got Turnstile token!")
		}

		// Check for cf-turnstile elements in HTML
		if strings.Contains(result.HTML, "cf-turnstile") {
			t.Log("INFO: cf-turnstile element found in HTML")
		}
	}
}

// TestTurnstile_ShadowDOMDirect tests the shadow DOM traversal directly.
func TestTurnstile_ShadowDOMDirect(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true, // Use headless for stability
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

	// Acquire a browser directly to test shadow DOM traversal
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

	// Navigate to a Turnstile demo page
	t.Log("Navigating to Turnstile demo page...")
	if err := page.Navigate("https://demo.turnstile.workers.dev/"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Wait for page to load
	if err := page.WaitLoad(); err != nil {
		t.Logf("WaitLoad warning: %v", err)
	}

	// Give Turnstile time to render
	time.Sleep(3 * time.Second)

	// Test shadow DOM traversal
	t.Log("Testing shadow DOM traversal...")
	traverser := solver.NewShadowRootTraverser(page)

	// Try to find the Turnstile checkbox
	checkbox, err := traverser.FindTurnstileCheckbox(ctx)
	if err != nil {
		t.Logf("FindTurnstileCheckbox result: %v (expected if no closed shadow root)", err)
	} else if checkbox != nil {
		t.Log("SUCCESS: Found Turnstile checkbox via shadow DOM traversal!")
		_ = checkbox.Release()
	}

	// Try to get container bounds
	bounds, err := traverser.GetTurnstileContainerBounds(ctx)
	if err != nil {
		t.Logf("GetTurnstileContainerBounds result: %v", err)
	} else {
		t.Logf("SUCCESS: Found Turnstile container at x=%.0f, y=%.0f, w=%.0f, h=%.0f",
			bounds.X, bounds.Y, bounds.Width, bounds.Height)
	}
}

// TestTurnstile_WithHeadful runs the test with visible browser for debugging.
func TestTurnstile_WithHeadful(t *testing.T) {
	skipCI(t)

	// Skip unless explicitly requested
	if testing.Short() {
		t.Skip("Skipping headful test")
	}

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           false, // Show browser window
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 120 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	t.Log("Starting headful Turnstile test...")
	t.Log("Watch the browser window to observe Turnstile solving behavior")

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:        "https://nowsecure.nl/",
		Timeout:    180 * time.Second,
		Screenshot: true,
	})

	if err != nil {
		t.Logf("Solve error: %v", err)
	}

	if result != nil {
		t.Logf("Final URL: %s", result.URL)
		t.Logf("Cookies: %d", len(result.Cookies))

		for _, c := range result.Cookies {
			if c.Name == "cf_clearance" {
				t.Logf("SUCCESS: cf_clearance = %s", truncate(c.Value, 50))
			}
		}
	}

	// Keep browser open briefly for observation
	t.Log("Pausing for observation...")
	time.Sleep(5 * time.Second)
}

// truncate shortens a string to the specified length.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
