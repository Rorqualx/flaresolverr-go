// Package browser provides browser pool management for efficient resource usage.
// The pool maintains a fixed number of browser instances that are reused across requests,
// dramatically reducing memory usage compared to spawning a new browser per request.
package browser

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Pool manages a pool of reusable browser instances.
// This is the CRITICAL component for memory efficiency.
//
// Memory comparison:
//   - Without pool (Python): 400-700MB per request
//   - With pool (Go): 150-250MB per session, browsers reused
//
// The pool pre-warms browsers at startup and maintains them for reuse.
// Each browser can handle multiple sequential requests.
type Pool struct {
	mu        sync.Mutex
	browsers  []*browserEntry
	available chan *rod.Browser
	config    *config.Config
	closed    atomic.Bool

	// Stop channel for graceful shutdown of background goroutines
	stopCh chan struct{}

	// Bug 4: Atomic counter for race-free Available() reads
	availableCount atomic.Int32

	// Statistics for monitoring
	stats PoolStats
}

// browserEntry tracks metadata for each browser in the pool.
type browserEntry struct {
	browser   *rod.Browser
	createdAt time.Time
	useCount  atomic.Int64
}

// PoolStats provides statistics about pool usage.
type PoolStats struct {
	Acquired atomic.Int64
	Released atomic.Int64
	Recycled atomic.Int64
	Errors   atomic.Int64
}

// NewPool creates a new browser pool with the specified configuration.
// It pre-warms the pool by launching the configured number of browsers.
//
// This function blocks until all browsers are ready or an error occurs.
// If any browser fails to launch, the pool is cleaned up and an error is returned.
func NewPool(cfg *config.Config) (*Pool, error) {
	log.Info().
		Int("pool_size", cfg.BrowserPoolSize).
		Bool("headless", cfg.Headless).
		Str("browser_path", cfg.BrowserPath).
		Msg("Initializing browser pool")

	pool := &Pool{
		config:    cfg,
		available: make(chan *rod.Browser, cfg.BrowserPoolSize),
		browsers:  make([]*browserEntry, 0, cfg.BrowserPoolSize),
		stopCh:    make(chan struct{}),
	}

	// Pre-warm the pool by launching all browsers
	log.Info().Int("count", cfg.BrowserPoolSize).Msg("Pre-warming browser pool")

	for i := 0; i < cfg.BrowserPoolSize; i++ {
		browser, err := pool.spawnBrowser()
		if err != nil {
			// Clean up any browsers we've already created
			log.Error().Err(err).Int("browser_index", i).Msg("Failed to spawn browser during pool initialization")
			pool.Close()
			return nil, fmt.Errorf("failed to spawn browser %d: %w", i, err)
		}

		entry := &browserEntry{
			browser:   browser,
			createdAt: time.Now(),
		}
		pool.browsers = append(pool.browsers, entry)
		pool.available <- browser

		log.Debug().Int("browser_index", i).Msg("Browser spawned and added to pool")
	}

	// Bug 4: Initialize atomic counter with pool size
	pool.availableCount.Store(int32(cfg.BrowserPoolSize))

	// Start background routines
	go pool.monitorMemory()
	go pool.healthCheckRoutine()

	log.Info().
		Int("pool_size", cfg.BrowserPoolSize).
		Msg("Browser pool initialized successfully")

	return pool, nil
}

// createLauncher creates a configured Rod launcher with optimal settings.
// These flags are tuned for headless operation, memory efficiency, and anti-detection.
func (p *Pool) createLauncher() *launcher.Launcher {
	l := launcher.New()

	// Headless mode - use new headless mode for better anti-detection
	// Chrome 109+ supports --headless=new which is much harder to detect
	// because it uses the same rendering path as headed mode
	if p.config.Headless {
		l = l.Set("headless", "new")
	}

	// Custom browser path if specified
	if p.config.BrowserPath != "" {
		l = l.Bin(p.config.BrowserPath)
	}

	// Security flags - required for containerized environments
	l = l.Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage")

	// Anti-detection flags - critical for bypassing Cloudflare
	// This hides the navigator.webdriver property at the browser level
	l = l.Set("disable-blink-features", "AutomationControlled")

	// Language configuration - consistent with real browsers
	l = l.Set("accept-lang", "en-US,en")

	// Suppress Chrome dialogs
	l = l.Set("disable-search-engine-choice-screen")

	// Performance and stability flags
	l = l.Set("disable-gpu").
		Set("no-zygote").
		Set("disable-background-networking").
		Set("disable-default-apps").
		Set("disable-extensions").
		Set("disable-sync").
		Set("disable-translate").
		Set("metrics-recording-only").
		Set("mute-audio").
		Set("no-first-run").
		Set("safebrowsing-disable-auto-update")

	// Window size - consistent viewport
	l = l.Set("window-size", "1920,1080")

	// Memory optimization flags
	l = l.Set("js-flags", "--max-old-space-size=256").
		Set("disable-features", "TranslateUI,BlinkGenPropertyTrees").
		Set("disable-ipc-flooding-protection").
		Set("disable-renderer-backgrounding")

	// ARM-specific flags
	if isARM() {
		l = l.Set("disable-gpu-sandbox")
	}

	return l
}

// spawnBrowser launches a new browser instance.
// This is an internal method - external code should use Acquire/Release.
// Each call creates a fresh launcher since launchers can only be used once.
func (p *Pool) spawnBrowser() (*rod.Browser, error) {
	log.Debug().Msg("Spawning new browser instance")

	// Create a fresh launcher for this browser instance
	// (launchers can only launch once, so we need a new one each time)
	l := p.createLauncher()

	// Launch the browser process
	url, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}

	// Connect to the browser via CDP
	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to browser: %w", err)
	}

	// Configure browser-level settings
	// Only ignore certificate errors if explicitly configured (security risk)
	if p.config.IgnoreCertErrors {
		log.Warn().Msg("Certificate validation disabled - MITM attacks possible")
		browser = browser.MustIgnoreCertErrors(true)
	}

	log.Debug().Str("url", url).Msg("Browser spawned successfully")
	return browser, nil
}

// Acquire obtains a browser from the pool.
// It blocks until a browser is available, the context is cancelled,
// or the pool timeout is reached.
//
// The caller MUST call Release() when done with the browser.
// Use defer to ensure the browser is always released:
//
//	browser, err := pool.Acquire(ctx)
//	if err != nil {
//	    return err
//	}
//	defer pool.Release(browser)
func (p *Pool) Acquire(ctx context.Context) (*rod.Browser, error) {
	if p.closed.Load() {
		return nil, types.ErrBrowserPoolClosed
	}

	const maxRetries = 5 // Prevent infinite retry if all browsers are unhealthy

	for retry := 0; retry < maxRetries; retry++ {
		log.Debug().
			Int("available", len(p.available)).
			Int("retry", retry).
			Msg("Acquiring browser from pool")

		select {
		case browser := <-p.available:
			// Got a browser from the pool
			p.stats.Acquired.Add(1)
			p.availableCount.Add(-1) // Bug 4: Decrement atomic counter

			// Verify browser is healthy before returning
			if !p.isHealthy(browser) {
				log.Warn().Int("retry", retry).Msg("Acquired unhealthy browser, recycling")
				p.stats.Errors.Add(1)
				go p.recycleBrowser(browser) // Recycle in background
				continue                     // Iterate instead of recurse
			}

			// Update use count (requires lock to safely access p.browsers)
			p.mu.Lock()
			for _, entry := range p.browsers {
				if entry.browser == browser {
					entry.useCount.Add(1)
					break
				}
			}
			p.mu.Unlock()

			log.Debug().
				Int64("total_acquired", p.stats.Acquired.Load()).
				Msg("Browser acquired from pool")

			return browser, nil

		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", types.ErrContextCanceled, ctx.Err())

		case <-time.After(p.config.BrowserPoolTimeout):
			p.stats.Errors.Add(1)
			return nil, types.ErrBrowserPoolTimeout
		}
	}

	// All retries exhausted
	p.stats.Errors.Add(1)
	return nil, fmt.Errorf("%w: all browsers unhealthy after %d retries", types.ErrBrowserUnhealthy, maxRetries)
}

// Release returns a browser to the pool.
// This method cleans up any pages and prepares the browser for reuse.
//
// It is safe to call Release multiple times or on a nil browser.
func (p *Pool) Release(browser *rod.Browser) {
	if browser == nil {
		return
	}

	if p.closed.Load() {
		// Pool is closed, just close the browser
		_ = browser.Close()
		return
	}

	p.stats.Released.Add(1)

	// Clean up all pages before returning to pool
	// This prevents memory accumulation across requests
	pages, err := browser.Pages()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get pages for cleanup")
	} else {
		for _, page := range pages {
			// Navigate to blank to clear page state
			_ = page.Navigate("about:blank")
			_ = page.Close()
		}
	}

	// Return browser to pool
	select {
	case p.available <- browser:
		p.availableCount.Add(1) // Bug 4: Increment atomic counter
		log.Debug().
			Int64("total_released", p.stats.Released.Load()).
			Msg("Browser released to pool")
	default:
		// Pool is full (shouldn't happen with correct usage)
		log.Warn().Msg("Pool is full, closing excess browser")
		_ = browser.Close()
	}
}

// isHealthy checks if a browser is responsive and usable.
func (p *Pool) isHealthy(browser *rod.Browser) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to create and close a page as a health check
	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		log.Debug().Err(err).Msg("Browser health check failed: cannot create page")
		return false
	}

	// Try to navigate to about:blank with context
	err = page.Timeout(5 * time.Second).Navigate("about:blank")
	if err != nil {
		log.Debug().Err(err).Msg("Browser health check failed: cannot navigate")
		_ = page.Close()
		return false
	}

	// Check context wasn't cancelled
	select {
	case <-ctx.Done():
		_ = page.Close()
		return false
	default:
	}

	_ = page.Close()
	return true
}

// recycleBrowser replaces an unhealthy browser with a new one.
// Uses timeouts to prevent deadlocks during browser close/spawn operations.
func (p *Pool) recycleBrowser(oldBrowser *rod.Browser) {
	p.stats.Recycled.Add(1)

	log.Info().
		Int64("total_recycled", p.stats.Recycled.Load()).
		Msg("Recycling browser")

	// Close old browser OUTSIDE lock with timeout
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		if err := oldBrowser.Close(); err != nil {
			log.Warn().Err(err).Msg("Error closing old browser during recycle")
		}
	}()

	select {
	case <-closeDone:
		// Closed successfully
	case <-time.After(10 * time.Second):
		log.Warn().Msg("Browser close timed out during recycle")
	}

	// Spawn new browser OUTSIDE lock with timeout
	var newBrowser *rod.Browser
	var spawnErr error

	spawnDone := make(chan struct{})
	go func() {
		defer close(spawnDone)
		newBrowser, spawnErr = p.spawnBrowser()
	}()

	select {
	case <-spawnDone:
		// Spawn completed
	case <-time.After(30 * time.Second):
		log.Error().Msg("Browser spawn timed out during recycle")
		// Bug 5: Use helper function with defer for safe unlock
		p.removeBrowserEntry(oldBrowser)
		return
	}

	if spawnErr != nil {
		log.Error().Err(spawnErr).Msg("Failed to spawn replacement browser")
		// Bug 5: Use helper function with defer for safe unlock
		p.removeBrowserEntry(oldBrowser)
		return
	}

	// Bug 5: Use helper function with defer for safe unlock
	newEntry := &browserEntry{
		browser:   newBrowser,
		createdAt: time.Now(),
	}
	p.updateBrowserEntry(oldBrowser, newEntry)

	// Add new browser to pool
	select {
	case p.available <- newBrowser:
		p.availableCount.Add(1) // Bug 4: Increment atomic counter
		log.Info().Msg("Replacement browser added to pool")
	default:
		log.Warn().Msg("Could not add replacement browser to pool")
		_ = newBrowser.Close()
	}
}

// monitorMemory periodically checks memory usage and triggers recycling if needed.
func (p *Pool) monitorMemory() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	maxBytes := uint64(p.config.MaxMemoryMB) * 1024 * 1024

	for {
		select {
		case <-p.stopCh:
			log.Debug().Msg("Memory monitor stopping")
			return
		case <-ticker.C:
			if p.closed.Load() {
				return
			}

			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			log.Debug().
				Uint64("alloc_mb", m.Alloc/1024/1024).
				Uint64("sys_mb", m.Sys/1024/1024).
				Int("max_mb", p.config.MaxMemoryMB).
				Msg("Memory stats")

			if m.Alloc > maxBytes {
				log.Warn().
					Uint64("current_mb", m.Alloc/1024/1024).
					Int("max_mb", p.config.MaxMemoryMB).
					Msg("Memory threshold exceeded, recycling browsers")

				p.recycleAll()
			}
		}
	}
}

// healthCheckRoutine periodically verifies browser health and recycles stale browsers.
func (p *Pool) healthCheckRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	maxAge := 30 * time.Minute // Recycle browsers older than this

	for {
		select {
		case <-p.stopCh:
			log.Debug().Msg("Health check routine stopping")
			return
		case <-ticker.C:
			if p.closed.Load() {
				return
			}

			p.mu.Lock()
			now := time.Now()
			var toRecycle []*rod.Browser

			for _, entry := range p.browsers {
				// Recycle old browsers proactively
				if now.Sub(entry.createdAt) > maxAge {
					toRecycle = append(toRecycle, entry.browser)
				}
			}
			p.mu.Unlock()

			// Recycle outside of lock
			for _, browser := range toRecycle {
				log.Info().Msg("Recycling stale browser")
				p.recycleBrowser(browser)
			}
		}
	}
}

// recycleAll recycles all browsers in the pool.
// This is used when memory pressure is detected.
func (p *Pool) recycleAll() {
	p.mu.Lock()
	toRecycle := make([]*rod.Browser, len(p.browsers))
	for i, entry := range p.browsers {
		toRecycle[i] = entry.browser
	}
	p.mu.Unlock()

	log.Info().Int("count", len(toRecycle)).Msg("Recycling all browsers due to memory pressure")

	for _, browser := range toRecycle {
		p.recycleBrowser(browser)
	}
}

// Size returns the configured pool size.
func (p *Pool) Size() int {
	return p.config.BrowserPoolSize
}

// Available returns the number of browsers currently available in the pool.
// Bug 4: Use atomic counter for race-free reads instead of len(p.available).
func (p *Pool) Available() int {
	if p.closed.Load() {
		return 0
	}
	return int(p.availableCount.Load())
}

// PoolStatsSnapshot holds a point-in-time snapshot of pool statistics.
type PoolStatsSnapshot struct {
	Acquired int64
	Released int64
	Recycled int64
	Errors   int64
}

// Stats returns a snapshot of the current pool statistics.
func (p *Pool) Stats() PoolStatsSnapshot {
	return PoolStatsSnapshot{
		Acquired: p.stats.Acquired.Load(),
		Released: p.stats.Released.Load(),
		Recycled: p.stats.Recycled.Load(),
		Errors:   p.stats.Errors.Load(),
	}
}

// GetStats returns the current statistics values.
func (p *Pool) GetStats() (acquired, released, recycled, errors int64) {
	return p.stats.Acquired.Load(),
		p.stats.Released.Load(),
		p.stats.Recycled.Load(),
		p.stats.Errors.Load()
}

// Close shuts down the pool and releases all resources.
// After Close is called, Acquire will return an error.
//
// Close is safe to call multiple times.
// Uses errgroup for parallel browser closing to speed up shutdown.
func (p *Pool) Close() error {
	if p.closed.Swap(true) {
		return nil // Already closed
	}

	log.Info().Msg("Closing browser pool")

	// Signal background goroutines to stop immediately
	close(p.stopCh)

	p.mu.Lock()
	browsers := make([]*browserEntry, len(p.browsers))
	copy(browsers, p.browsers)
	p.browsers = nil
	p.mu.Unlock()

	// Close all browsers in parallel using errgroup
	// Limit concurrent closes to prevent resource exhaustion
	eg := new(errgroup.Group)
	eg.SetLimit(4) // Close up to 4 browsers concurrently

	for _, entry := range browsers {
		browser := entry.browser // Capture for closure
		eg.Go(func() error {
			if err := browser.Close(); err != nil {
				log.Warn().Err(err).Msg("Error closing browser during pool shutdown")
				return err
			}
			return nil
		})
	}

	// Wait for all browsers to close
	closeErr := eg.Wait()

	// Drain and close the available channel
	close(p.available)
	for range p.available {
		// Drain remaining browsers
	}

	log.Info().
		Int64("total_acquired", p.stats.Acquired.Load()).
		Int64("total_released", p.stats.Released.Load()).
		Int64("total_recycled", p.stats.Recycled.Load()).
		Int64("total_errors", p.stats.Errors.Load()).
		Msg("Browser pool closed")

	return closeErr
}

// removeBrowserEntry removes a browser from the tracking slice.
// Bug 5: Uses defer for safe unlock to prevent lock being held on panic.
func (p *Pool) removeBrowserEntry(oldBrowser *rod.Browser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, entry := range p.browsers {
		if entry.browser == oldBrowser {
			p.browsers = append(p.browsers[:i], p.browsers[i+1:]...)
			return
		}
	}
}

// updateBrowserEntry replaces an old browser entry with a new one.
// Bug 5: Uses defer for safe unlock to prevent lock being held on panic.
// Returns true if the entry was found and updated.
func (p *Pool) updateBrowserEntry(oldBrowser *rod.Browser, newEntry *browserEntry) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, entry := range p.browsers {
		if entry.browser == oldBrowser {
			p.browsers[i] = newEntry
			return true
		}
	}
	return false
}

// isARM returns true if running on ARM architecture.
func isARM() bool {
	arch := runtime.GOARCH
	return arch == "arm" || arch == "arm64"
}
