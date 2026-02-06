package probe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// TestSolver_NavigateAndExtract tests basic navigation and HTML extraction.
func TestSolver_NavigateAndExtract(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Start test server
	server := startTestServer(t)

	// Create solver
	s := solver.New(pool, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected successful result")
	}

	if result.HTML == "" {
		t.Error("HTML should not be empty")
	}

	if !strings.Contains(result.HTML, "Test Page") {
		t.Errorf("HTML should contain 'Test Page', got: %s", result.HTML[:min(200, len(result.HTML))])
	}
}

// TestSolver_CookieExtraction tests that cookies are captured from responses.
func TestSolver_CookieExtraction(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/cookies/set",
		Timeout:                30 * time.Second,
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Check that cookies were captured
	foundTestCookie := false
	for _, c := range result.Cookies {
		if c.Name == "test_cookie" && c.Value == "test_value" {
			foundTestCookie = true
			break
		}
	}

	if !foundTestCookie {
		t.Error("Expected to find test_cookie in response cookies")
		t.Logf("Cookies received: %+v", result.Cookies)
	}
}

// TestSolver_TimeoutRespected tests that timeout parameter is respected.
func TestSolver_TimeoutRespected(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use a very short timeout against a slow endpoint
	start := time.Now()
	_, err = s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/slow",
		Timeout:                2 * time.Second, // Should timeout before /slow responds
		SkipResponseValidation: true,
	})
	elapsed := time.Since(start)

	// Should have failed due to timeout
	if err == nil {
		t.Fatal("Expected timeout error")
	}

	// Should have failed quickly (within ~3 seconds)
	if elapsed > 10*time.Second {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// TestSolver_ScreenshotCapture tests screenshot capture functionality.
func TestSolver_ScreenshotCapture(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		Screenshot:             true,
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if result.Screenshot == "" {
		t.Error("Screenshot should not be empty when requested")
	}

	// Screenshot should be base64 encoded PNG
	// PNG base64 starts with "iVBOR" (decoded: 0x89PNG)
	if !strings.HasPrefix(result.Screenshot, "iVBOR") {
		t.Errorf("Screenshot should be base64 PNG, got prefix: %s", result.Screenshot[:min(10, len(result.Screenshot))])
	}
}

// TestSolver_HTMLTruncation tests that large HTML is truncated.
func TestSolver_HTMLTruncation(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/large",
		Timeout:                60 * time.Second,
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// HTML should be truncated
	if !result.HTMLTruncated {
		t.Error("Expected HTMLTruncated to be true for large response")
	}

	// HTML should not exceed max size (10MB)
	const maxResponseSize = 10 * 1024 * 1024
	if len(result.HTML) > maxResponseSize {
		t.Errorf("HTML exceeds max size: %d bytes", len(result.HTML))
	}
}

// TestSolver_POSTFormSubmission tests POST request handling.
func TestSolver_POSTFormSubmission(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/post",
		Timeout:                30 * time.Second,
		IsPost:                 true,
		PostData:               "key1=value1&key2=value2",
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected successful result")
	}

	// The response should contain the posted data
	if result.HTML == "" {
		t.Error("HTML should not be empty")
	}
}

// TestSolver_InvalidTimeout tests that invalid timeout is rejected.
func TestSolver_InvalidTimeout(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"zero_timeout", 0},
		{"negative_timeout", -1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Solve(ctx, &solver.SolveOptions{
				URL:                    server.URL + "/html",
				Timeout:                tt.timeout,
				SkipResponseValidation: true,
			})

			if err == nil {
				t.Error("Expected error for invalid timeout")
			}
		})
	}
}

// TestSolver_CookiesPassedToRequest tests that cookies are passed in requests.
func TestSolver_CookiesPassedToRequest(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:     server.URL + "/html",
		Timeout: 30 * time.Second,
		Cookies: []types.RequestCookie{
			{
				Name:   "custom_cookie",
				Value:  "custom_value",
				Domain: "127.0.0.1",
				Path:   "/",
			},
		},
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// The cookie we set should be in the result
	foundCookie := false
	for _, c := range result.Cookies {
		if c.Name == "custom_cookie" && c.Value == "custom_value" {
			foundCookie = true
			break
		}
	}

	if !foundCookie {
		t.Error("Expected to find custom_cookie in response")
		t.Logf("Cookies: %+v", result.Cookies)
	}
}

// TestSolver_UserAgentSet tests that user agent is set correctly.
func TestSolver_UserAgentSet(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)

	customUA := "Custom-Test-Agent/1.0"
	s := solver.New(pool, customUA)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if result.UserAgent != customUA {
		t.Errorf("UserAgent should be %q, got %q", customUA, result.UserAgent)
	}
}

// TestSolver_URLRedirect tests handling of HTTP redirects.
func TestSolver_URLRedirect(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/redirect",
		Timeout:                30 * time.Second,
		SkipResponseValidation: true,
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// URL should be the redirected destination
	if !strings.HasSuffix(result.URL, "/html") {
		t.Errorf("Expected URL to end with /html after redirect, got %s", result.URL)
	}

	// Content should be from the redirected page
	if !strings.Contains(result.HTML, "Test Page") {
		t.Error("HTML should contain content from redirected page")
	}
}

// TestSolver_WaitInSeconds tests the waitInSeconds option.
func TestSolver_WaitInSeconds(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err = s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		WaitInSeconds:          2,    // Wait 2 seconds before returning
		SkipResponseValidation: true, // Skip SSRF validation for localhost test server
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Should have waited at least 2 seconds
	if elapsed < 2*time.Second {
		t.Errorf("Expected to wait at least 2 seconds, but only waited %v", elapsed)
	}
}

// TestSolver_DisableMedia tests the media blocking option.
func TestSolver_DisableMedia(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	server := startTestServer(t)
	s := solver.New(pool, "Mozilla/5.0 Test/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test with media disabled
	result, err := s.Solve(ctx, &solver.SolveOptions{
		URL:                    server.URL + "/html",
		Timeout:                30 * time.Second,
		DisableMedia:           true,
		SkipResponseValidation: true, // Skip SSRF validation for localhost test server
	})

	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Should still get the HTML
	if !result.Success {
		t.Error("Expected successful result with media disabled")
	}
}
