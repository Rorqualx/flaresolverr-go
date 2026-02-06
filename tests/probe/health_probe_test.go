package probe

import (
	"context"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// TestPoolIsHealthy_HealthyBrowser tests that isHealthy returns true for a working browser.
func TestPoolIsHealthy_HealthyBrowser(t *testing.T) {
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

	// Pool should have 1 browser available
	if pool.Available() != 1 {
		t.Errorf("Expected 1 available browser, got %d", pool.Available())
	}

	// Acquire should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer pool.Release(b)

	// Browser should be usable
	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	page.Close()
}

// TestPoolIsHealthy_ClosedBrowser tests health check behavior with a closed browser.
// Note: This is a behavioral test - we test the pool's response to unhealthy browsers.
func TestPoolIsHealthy_ClosedBrowser(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Initial state
	if pool.Available() != 2 {
		t.Errorf("Expected 2 available browsers, got %d", pool.Available())
	}

	// Acquire a browser
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Close the browser directly (simulating crash)
	b.MustClose()

	// Release the closed browser - pool should handle this gracefully
	pool.Release(b)

	// Pool should still function
	// Wait a bit for recycle to happen
	time.Sleep(100 * time.Millisecond)
}

// TestPoolHealthCheckRoutine_StopsOnClose tests that health check goroutine stops when pool closes.
func TestPoolHealthCheckRoutine_StopsOnClose(t *testing.T) {
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

	// Close should complete without hanging
	done := make(chan struct{})
	go func() {
		err := pool.Close()
		if err != nil {
			t.Errorf("Close returned error: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("Pool.Close() timed out - goroutine may be leaked")
	}
}

// TestPool_AcquireReleaseCycle tests the basic acquire/release cycle.
func TestPool_AcquireReleaseCycle(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Acquire all browsers
	b1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}

	b2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Second acquire failed: %v", err)
	}

	// Pool should be empty
	if pool.Available() != 0 {
		t.Errorf("Expected 0 available browsers, got %d", pool.Available())
	}

	// Release one
	pool.Release(b1)

	// Pool should have one available
	assertEventually(t, func() bool {
		return pool.Available() == 1
	}, 5*time.Second, "Expected 1 available browser after release")

	// Release the other
	pool.Release(b2)

	// Pool should be full again
	assertEventually(t, func() bool {
		return pool.Available() == 2
	}, 5*time.Second, "Expected 2 available browsers after both releases")
}

// TestPool_AcquireTimeout tests that acquire times out when pool is exhausted.
func TestPool_AcquireTimeout(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 100 * time.Millisecond, // Very short timeout
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Acquire the only browser
	b, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}
	defer pool.Release(b)

	// Try to acquire another - should timeout
	start := time.Now()
	_, err = pool.Acquire(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Second acquire should have failed")
	}

	// Should have failed relatively quickly
	if elapsed > 5*time.Second {
		t.Errorf("Timeout took too long: %v", elapsed)
	}
}

// TestPool_AcquireContextCancel tests that acquire respects context cancellation.
func TestPool_AcquireContextCancel(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 10 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Acquire the only browser
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()

	b, err := pool.Acquire(ctx1)
	if err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}
	defer pool.Release(b)

	// Create a context that will be canceled
	ctx2, cancel2 := context.WithCancel(context.Background())

	// Cancel immediately
	cancel2()

	// Try to acquire - should fail immediately due to canceled context
	_, err = pool.Acquire(ctx2)
	if err == nil {
		t.Fatal("Acquire with canceled context should fail")
	}
}

// TestPool_Stats tests that pool statistics are tracked correctly.
func TestPool_Stats(t *testing.T) {
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

	// Initial stats
	stats := pool.Stats()
	initialAcquired := stats.Acquired

	// Acquire and release
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	stats = pool.Stats()
	if stats.Acquired != initialAcquired+1 {
		t.Errorf("Acquired count should be %d, got %d", initialAcquired+1, stats.Acquired)
	}

	initialReleased := stats.Released
	pool.Release(b)

	// Check released count
	assertEventually(t, func() bool {
		stats = pool.Stats()
		return stats.Released == initialReleased+1
	}, 5*time.Second, "Released count should have incremented")
}

// TestPool_Size tests that Size returns the configured pool size.
func TestPool_Size(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    3,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	if pool.Size() != 3 {
		t.Errorf("Size() should return 3, got %d", pool.Size())
	}
}

// TestPool_SpawnWithProxy tests spawning a browser with a proxy configuration.
func TestPool_SpawnWithProxy(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Spawn with a (fake) proxy - this tests the code path, not actual proxy functionality
	// The proxy doesn't need to exist for the browser to spawn
	b, err := pool.SpawnWithProxy(ctx, "http://127.0.0.1:9999")
	if err != nil {
		t.Fatalf("SpawnWithProxy failed: %v", err)
	}
	defer b.Close()

	// Browser should be usable
	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	page.Close()
}

// TestPool_AcquireAfterClose tests that Acquire fails after Close.
func TestPool_AcquireAfterClose(t *testing.T) {
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

	// Close the pool
	pool.Close()

	// Try to acquire
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = pool.Acquire(ctx)
	if err == nil {
		t.Fatal("Acquire after Close should fail")
	}

	if err != types.ErrBrowserPoolClosed {
		t.Errorf("Expected ErrBrowserPoolClosed, got %v", err)
	}
}

// TestPool_ReleaseNilBrowser tests that Release handles nil browser gracefully.
func TestPool_ReleaseNilBrowser(t *testing.T) {
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

	// Release nil should not panic
	pool.Release(nil)
}

// TestPool_AvailableAfterClose tests that Available returns 0 after Close.
func TestPool_AvailableAfterClose(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        512,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	// Check initial available
	if pool.Available() != 2 {
		t.Errorf("Expected 2 available, got %d", pool.Available())
	}

	// Close
	pool.Close()

	// Available should be 0
	if pool.Available() != 0 {
		t.Errorf("Expected 0 available after close, got %d", pool.Available())
	}
}

// TestPool_MultipleBrowsersWork tests that all browsers in pool are functional.
func TestPool_MultipleBrowsersWork(t *testing.T) {
	skipCI(t)

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               8191,
		Headless:           true,
		BrowserPoolSize:    3,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        1024,
	}

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Acquire all 3 browsers
	browsers := make([]*rod.Browser, 0, 3)
	for i := 0; i < 3; i++ {
		b, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		browsers = append(browsers, b)
	}

	// Test each browser works
	for i, b := range browsers {
		page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			t.Errorf("Browser %d: Failed to create page: %v", i, err)
			continue
		}

		// Navigate to verify functionality
		if err := page.Navigate("about:blank"); err != nil {
			t.Errorf("Browser %d: Navigation failed: %v", i, err)
		}

		page.Close()
	}

	// Release all
	for _, b := range browsers {
		pool.Release(b)
	}

	// All should be available again
	assertEventually(t, func() bool {
		return pool.Available() == 3
	}, 10*time.Second, "All browsers should be available after release")
}

// TestBrowser_DirectHealthCheck tests browser health directly using launcher.
func TestBrowser_DirectHealthCheck(t *testing.T) {
	skipCI(t)

	l := launcher.New().
		Headless(true).
		Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage")

	url, err := l.Launch()
	if err != nil {
		t.Fatalf("Failed to launch browser: %v", err)
	}

	b := rod.New().ControlURL(url)
	if err := b.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer b.Close()

	// Create and close a page as health check
	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate("about:blank"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	page.Close()

	// Browser should still be healthy
	page2, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Second page creation failed: %v", err)
	}
	page2.Close()
}
