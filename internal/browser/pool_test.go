package browser

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// testConfig returns a configuration suitable for testing.
// Uses a small pool size and short timeouts.
func testConfig() *config.Config {
	return &config.Config{
		Headless:           true,
		BrowserPoolSize:    2,
		BrowserPoolTimeout: 10 * time.Second,
		MaxMemoryMB:        1024,
	}
}

// skipCI skips tests that require a browser in CI environments.
func skipCI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}
}

func TestNewPool(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	if pool.Size() != cfg.BrowserPoolSize {
		t.Errorf("Expected pool size %d, got %d", cfg.BrowserPoolSize, pool.Size())
	}

	if pool.Available() != cfg.BrowserPoolSize {
		t.Errorf("Expected %d available browsers, got %d", cfg.BrowserPoolSize, pool.Available())
	}
}

func TestPoolAcquireRelease(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Acquire a browser
	browser, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}

	// Check available count decreased
	if pool.Available() != cfg.BrowserPoolSize-1 {
		t.Errorf("Expected %d available after acquire, got %d",
			cfg.BrowserPoolSize-1, pool.Available())
	}

	// Release the browser
	pool.Release(browser)

	// Give time for release to complete
	time.Sleep(100 * time.Millisecond)

	// Check available count restored
	if pool.Available() != cfg.BrowserPoolSize {
		t.Errorf("Expected %d available after release, got %d",
			cfg.BrowserPoolSize, pool.Available())
	}
}

func TestPoolAcquireAll(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Acquire all browsers
	browsers := make([]*rod.Browser, cfg.BrowserPoolSize)
	for i := 0; i < cfg.BrowserPoolSize; i++ {
		browser, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Failed to acquire browser %d: %v", i, err)
		}
		browsers[i] = browser
	}

	// Pool should be empty
	if pool.Available() != 0 {
		t.Errorf("Expected 0 available, got %d", pool.Available())
	}

	// Release all browsers
	for _, browser := range browsers {
		pool.Release(browser)
	}
}

func TestPoolTimeout(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	cfg.BrowserPoolTimeout = 500 * time.Millisecond

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Acquire the only browser
	browser, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	defer pool.Release(browser)

	// Try to acquire another (should timeout)
	start := time.Now()
	_, err = pool.Acquire(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	if err != types.ErrBrowserPoolTimeout {
		t.Errorf("Expected ErrBrowserPoolTimeout, got %v", err)
	}

	// Should have waited approximately the timeout duration
	if elapsed < 400*time.Millisecond || elapsed > 1*time.Second {
		t.Errorf("Expected timeout around 500ms, got %v", elapsed)
	}
}

func TestPoolContextCancellation(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	cfg.BrowserPoolTimeout = 10 * time.Second

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Acquire the only browser
	browser, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	defer pool.Release(browser)

	// Create a context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Try to acquire with context that will be cancelled
	start := time.Now()
	_, err = pool.Acquire(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected error, got nil")
	}

	// Should have been cancelled quickly
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected quick cancellation, got %v", elapsed)
	}
}

func TestPoolConcurrentAcquireRelease(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 3

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	const numGoroutines = 10
	const iterations = 5

	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*iterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

				browser, err := pool.Acquire(ctx)
				if err != nil {
					errCh <- err
					cancel()
					continue
				}

				// Simulate some work
				time.Sleep(50 * time.Millisecond)

				pool.Release(browser)
				cancel()
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		t.Errorf("Got %d errors during concurrent test: %v", len(errors), errors[0])
	}
}

func TestPoolClose(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	// Close the pool
	if err := pool.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Subsequent acquire should fail
	_, err = pool.Acquire(context.Background())
	if err != types.ErrBrowserPoolClosed {
		t.Errorf("Expected ErrBrowserPoolClosed, got %v", err)
	}

	// Close should be idempotent
	if err := pool.Close(); err != nil {
		t.Errorf("Second Close returned error: %v", err)
	}
}

func TestPoolStats(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Initial stats should be zero
	acquired, released, _, _ := pool.GetStats()
	if acquired != 0 || released != 0 {
		t.Errorf("Expected initial stats to be 0, got acquired=%d, released=%d",
			acquired, released)
	}

	// Acquire and release
	browser, _ := pool.Acquire(ctx)
	pool.Release(browser)

	time.Sleep(100 * time.Millisecond)

	acquired, released, _, _ = pool.GetStats()
	if acquired != 1 {
		t.Errorf("Expected acquired=1, got %d", acquired)
	}
	if released != 1 {
		t.Errorf("Expected released=1, got %d", released)
	}
}

func TestPoolReleaseNil(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	// Should not panic
	pool.Release(nil)
}

// Benchmark tests

func BenchmarkPoolAcquireRelease(b *testing.B) {
	cfg := testConfig()
	cfg.BrowserPoolSize = 3

	pool, err := NewPool(cfg)
	if err != nil {
		b.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		browser, err := pool.Acquire(ctx)
		if err != nil {
			b.Fatalf("Failed to acquire: %v", err)
		}
		pool.Release(browser)
	}
}

func BenchmarkPoolConcurrent(b *testing.B) {
	cfg := testConfig()
	cfg.BrowserPoolSize = 3

	pool, err := NewPool(cfg)
	if err != nil {
		b.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			browser, err := pool.Acquire(ctx)
			if err != nil {
				continue
			}
			pool.Release(browser)
		}
	})
}

