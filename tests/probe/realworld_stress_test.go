package probe

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
)

// TestRealWorld_MajorSites tests against major websites to verify compatibility.
// These sites represent different traffic levels and protection mechanisms.
func TestRealWorld_MajorSites(t *testing.T) {
	skipCI(t)

	sites := []struct {
		name    string
		url     string
		traffic string
	}{
		{"ChatGPT", "https://chatgpt.com", "6% traffic"},
		{"Shopify", "https://www.shopify.com", "2% traffic"},
		{"OpenAI", "https://openai.com", "1% traffic"},
		{"LinkedIn", "https://www.linkedin.com", "0.5% traffic"},
		{"HubSpot", "https://www.hubspot.com", "0.6% traffic"},
		{"CNN", "https://www.cnn.com", "broadcast media"},
		{"IBM", "https://www.ibm.com", "IT services"},
		{"Mozilla", "https://www.mozilla.org", "software development"},
		{"W3C", "https://www.w3.org", "non-profit"},
		{"Stripe", "https://stripe.com", "technology"},
		{"ThePirateBay", "https://thepiratebay.org", "file sharing"},
		{"ComicVine", "https://comicvine.gamespot.com", "gaming/comics"},
	}

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 60 * time.Second,
		MaxMemoryMB:        2048,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	var results []testResult
	var mu sync.Mutex

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			start := time.Now()
			result, err := s.Solve(ctx, &solver.SolveOptions{
				URL:     site.url,
				Timeout: 45 * time.Second,
			})
			elapsed := time.Since(start)

			res := testResult{
				name:    site.name,
				url:     site.url,
				traffic: site.traffic,
				elapsed: elapsed,
			}

			if err != nil {
				res.status = "ERROR"
				res.message = err.Error()
				t.Logf("[%s] Error: %v (%.2fs)", site.name, err, elapsed.Seconds())
			} else if result != nil {
				res.status = "OK"
				res.htmlLen = len(result.HTML)
				res.cookies = len(result.Cookies)
				res.finalURL = result.URL

				// Check for protection indicators
				if strings.Contains(strings.ToLower(result.HTML), "captcha") ||
					strings.Contains(strings.ToLower(result.HTML), "challenge") ||
					strings.Contains(strings.ToLower(result.HTML), "verify") {
					res.hasProtection = true
				}

				// Check for cf_clearance cookie
				for _, c := range result.Cookies {
					if c.Name == "cf_clearance" {
						res.cfClearance = true
						break
					}
				}

				t.Logf("[%s] OK: %d bytes, %d cookies, %.2fs",
					site.name, res.htmlLen, res.cookies, elapsed.Seconds())
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		})
	}

	// Print summary
	t.Log("\n" + strings.Repeat("=", 80))
	t.Log("SUMMARY")
	t.Log(strings.Repeat("=", 80))

	var successCount, errorCount int
	for _, r := range results {
		if r.status == "OK" {
			successCount++
		} else {
			errorCount++
		}

		protection := ""
		if r.hasProtection {
			protection = " [PROTECTED]"
		}
		if r.cfClearance {
			protection += " [CF_CLEARANCE]"
		}

		t.Logf("%-12s %-6s %8d bytes  %2d cookies  %.2fs%s",
			r.name, r.status, r.htmlLen, r.cookies, r.elapsed.Seconds(), protection)
	}

	t.Logf("\nTotal: %d/%d successful", successCount, len(results))
}

type testResult struct {
	name          string
	url           string
	traffic       string
	status        string
	message       string
	htmlLen       int
	cookies       int
	finalURL      string
	elapsed       time.Duration
	hasProtection bool
	cfClearance   bool
}

// TestRealWorld_SequentialStress runs sequential requests to test stability.
func TestRealWorld_SequentialStress(t *testing.T) {
	skipCI(t)

	sites := []string{
		"https://httpbin.org/html",
		"https://example.com",
		"https://www.google.com",
		"https://www.github.com",
		"https://www.wikipedia.org",
	}

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

	s := solver.New(pool, "Mozilla/5.0 Test")

	successCount := 0
	totalStart := time.Now()

	for i, url := range sites {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		start := time.Now()
		result, err := s.Solve(ctx, &solver.SolveOptions{
			URL:     url,
			Timeout: 30 * time.Second,
		})
		elapsed := time.Since(start)

		cancel()

		if err != nil {
			t.Logf("[%d/%d] %s - ERROR: %v (%.2fs)", i+1, len(sites), url, err, elapsed.Seconds())
		} else if result != nil {
			successCount++
			t.Logf("[%d/%d] %s - OK: %d bytes (%.2fs)", i+1, len(sites), url, len(result.HTML), elapsed.Seconds())
		}

		// Brief pause between requests
		time.Sleep(500 * time.Millisecond)
	}

	totalElapsed := time.Since(totalStart)
	t.Logf("\nCompleted %d/%d in %.2fs", successCount, len(sites), totalElapsed.Seconds())

	if successCount == 0 {
		t.Error("All requests failed")
	}
}

// TestRealWorld_CloudflareProtected tests against known Cloudflare-protected sites.
func TestRealWorld_CloudflareProtected(t *testing.T) {
	skipCI(t)

	// Sites known to use Cloudflare protection
	sites := []string{
		"https://nowsecure.nl/",               // Explicit Turnstile test page
		"https://demo.turnstile.workers.dev/", // Cloudflare demo
	}

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 120 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	for _, url := range sites {
		t.Run(url, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()

			t.Logf("Testing %s...", url)
			start := time.Now()

			result, err := s.Solve(ctx, &solver.SolveOptions{
				URL:        url,
				Timeout:    120 * time.Second,
				Screenshot: true,
			})

			elapsed := time.Since(start)

			if err != nil {
				t.Logf("Error: %v (%.2fs)", err, elapsed.Seconds())
				// Don't fail - Cloudflare protection may legitimately block us
				return
			}

			if result == nil {
				t.Log("No result returned")
				return
			}

			t.Logf("Final URL: %s", result.URL)
			t.Logf("HTML: %d bytes", len(result.HTML))
			t.Logf("Cookies: %d", len(result.Cookies))
			t.Logf("Elapsed: %.2fs", elapsed.Seconds())

			// Check for success indicators
			hasClearance := false
			for _, c := range result.Cookies {
				t.Logf("  Cookie: %s", c.Name)
				if c.Name == "cf_clearance" {
					hasClearance = true
				}
			}

			if hasClearance {
				t.Log("SUCCESS: Got cf_clearance cookie")
			}

			// Check if we got past the challenge
			htmlLower := strings.ToLower(result.HTML)
			if strings.Contains(htmlLower, "just a moment") ||
				strings.Contains(htmlLower, "checking your browser") {
				t.Log("WARNING: May still be on challenge page")
			} else {
				t.Log("SUCCESS: Got past challenge page")
			}
		})
	}
}

// TestRealWorld_RapidFire tests rapid sequential requests.
func TestRealWorld_RapidFire(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    3,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        2048,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	s := solver.New(pool, "Mozilla/5.0 Test")

	// Run 10 rapid requests
	numRequests := 10
	url := "https://httpbin.org/html"

	var wg sync.WaitGroup
	results := make(chan string, numRequests)

	start := time.Now()

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result, err := s.Solve(ctx, &solver.SolveOptions{
				URL:     url,
				Timeout: 30 * time.Second,
			})

			if err != nil {
				results <- fmt.Sprintf("[%d] ERROR: %v", id, err)
			} else if result != nil {
				results <- fmt.Sprintf("[%d] OK: %d bytes", id, len(result.HTML))
			}
		}(i)
	}

	wg.Wait()
	close(results)

	elapsed := time.Since(start)

	successCount := 0
	for r := range results {
		t.Log(r)
		if strings.Contains(r, "OK") {
			successCount++
		}
	}

	t.Logf("\nCompleted %d/%d in %.2fs (%.2f req/s)",
		successCount, numRequests, elapsed.Seconds(),
		float64(successCount)/elapsed.Seconds())

	if successCount < numRequests/2 {
		t.Errorf("Less than 50%% success rate: %d/%d", successCount, numRequests)
	}
}
