// Package browser provides browser pool management for efficient resource usage.
// The pool maintains a fixed number of browser instances that are reused across requests,
// dramatically reducing memory usage compared to spawning a new browser per request.
package browser

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/security"
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
//
// Lock ordering: mu must be acquired before any browser entry locks.
// Never hold mu while performing slow I/O operations.
type Pool struct {
	mu        sync.Mutex
	browsers  []*browserEntry
	available chan *rod.Browser
	config    *config.Config
	closed    atomic.Bool

	// Stop channel for graceful shutdown of background goroutines
	stopCh chan struct{}

	// WaitGroup to track background goroutines for clean shutdown
	wg sync.WaitGroup

	// Bug 4: Atomic counter for race-free Available() reads
	availableCount atomic.Int32

	// Audit Issue 2: Track leaked goroutines from browser close timeouts
	leakedGoroutines atomic.Int32

	// Issue #10: WaitGroup to track close goroutines for proper cleanup
	closeWg sync.WaitGroup

	// Issue #11: Semaphore to limit concurrent recycles
	recycleSem chan struct{}

	// Control URLs for CDP reconnection support.
	// Maps browser pointer to its WebSocket debugging URL.
	controlURLs sync.Map // map[*rod.Browser]string

	// Launchers per browser, retained so we can call launcher.Cleanup()
	// (which removes /tmp/rod/user-data-<random>) after browser.Close().
	// Without this, Rod's default user-data dirs accumulate on disk and
	// fill the container's writable layer over time (GitHub issue #6).
	launchers sync.Map // map[*rod.Browser]*launcher.Launcher

	// readMemory samples the service's memory usage for monitorMemory.
	// Replaceable in tests.
	readMemory memoryReader

	// Statistics for monitoring
	stats PoolStats
}

// entryState describes where a pooled browser currently is.
type entryState int

const (
	entryIdle      entryState = iota // queued in Pool.available, ready to acquire
	entryInUse                       // checked out via Acquire (request or session)
	entryRecycling                   // being closed and replaced
	entryDead                        // replacement failed; the health routine retries
)

// browserEntry tracks one pool slot. The slot outlives the browser in it:
// recycling replaces entry.browser in place.
type browserEntry struct {
	browser   *rod.Browser // nil while recycling or dead; guarded by Pool.mu
	createdAt time.Time    // guarded by Pool.mu
	useCount  atomic.Int64

	// state and recycleOnRelease are guarded by Pool.mu.
	state entryState
	// recycleOnRelease defers a recycle of an in-use browser until its holder
	// releases it, so a browser is never closed under a running request.
	recycleOnRelease bool
}

// Timeouts for browser lifecycle operations. Every CDP call the pool makes on
// its own behalf is bounded: go-rod applies no timeout of its own.
const (
	browserLaunchTimeout  = 60 * time.Second
	browserRespawnTimeout = 30 * time.Second
	browserCloseTimeout   = 5 * time.Second  // Browser.close CDP call
	browserExitGrace      = 5 * time.Second  // wait for the process to exit after close
	browserKillGrace      = 5 * time.Second  // wait for the process to exit after kill
	healthCheckTimeout    = 10 * time.Second // create + navigate + close a blank page
	releaseCleanupTimeout = 15 * time.Second // close leftover pages on release
	maxBrowserAge         = 30 * time.Minute // idle browsers older than this are recycled
)

// GetControlURL returns the WebSocket debugging URL for a browser instance.
// Used by the solver's disconnect/reconnect bypass to reconnect to a browser
// after temporarily severing the CDP connection.
func (p *Pool) GetControlURL(browser *rod.Browser) (string, bool) {
	val, ok := p.controlURLs.Load(browser)
	if !ok {
		return "", false
	}
	s, ok := val.(string)
	return s, ok
}

// GetBrowserPath returns the configured browser path.
// Used by the solver's two-phase bypass to launch a clean Chrome process.
func (p *Pool) GetBrowserPath() string {
	return p.config.BrowserPath
}

// SandboxEnabled reports whether browsers are launched with Chromium's own
// sandbox (BROWSER_SANDBOX=true), i.e. without --no-sandbox.
func (p *Pool) SandboxEnabled() bool {
	return p.config.BrowserSandbox
}

// DefaultProxyURL returns the proxy every pooled browser is launched with
// (PROXY_URL), or "" if none is configured.
func (p *Pool) DefaultProxyURL() string {
	return p.config.ProxyURL
}

// RecycleBrowser marks a checked-out pooled browser for replacement. The
// recycle happens when the holder calls Release, never while the browser is
// still in use. Browsers the pool does not own (SpawnWithProxy,
// SpawnWithOptions) are ignored: their owner tears them down.
func (p *Pool) RecycleBrowser(browser *rod.Browser) {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry := p.entryFor(browser)
	if entry == nil || entry.state != entryInUse {
		log.Debug().Msg("RecycleBrowser ignored: browser is not a checked-out pool member")
		return
	}
	entry.recycleOnRelease = true
}

// entryFor returns the pool slot holding browser, or nil if the pool does not
// own it. Caller must hold p.mu.
func (p *Pool) entryFor(browser *rod.Browser) *browserEntry {
	if browser == nil {
		return nil
	}
	for _, entry := range p.browsers {
		if entry.browser == browser {
			return entry
		}
	}
	return nil
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
		config:     cfg,
		available:  make(chan *rod.Browser, cfg.BrowserPoolSize),
		browsers:   make([]*browserEntry, 0, cfg.BrowserPoolSize),
		stopCh:     make(chan struct{}),
		recycleSem: make(chan struct{}, 4), // Issue #11: Limit concurrent recycles to 4
		readMemory: systemMemoryReader,
	}

	// Pre-warm the pool by launching all browsers
	log.Info().Int("count", cfg.BrowserPoolSize).Msg("Pre-warming browser pool")

	for i := 0; i < cfg.BrowserPoolSize; i++ {
		browser, err := pool.spawnBrowser(context.Background())
		if err != nil {
			// Clean up any browsers we've already created
			log.Error().Err(err).Int("browser_index", i).Msg("Failed to spawn browser during pool initialization")
			if closeErr := pool.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("Failed to close pool during cleanup")
			}
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

	// Start background routines with WaitGroup tracking for clean shutdown
	pool.wg.Add(2)
	go func() {
		defer pool.wg.Done()
		pool.monitorMemory()
	}()
	go func() {
		defer pool.wg.Done()
		pool.healthCheckRoutine()
	}()

	log.Info().
		Int("pool_size", cfg.BrowserPoolSize).
		Msg("Browser pool initialized successfully")

	return pool, nil
}

// createLauncher creates a configured Rod launcher with optimal settings.
// These flags are tuned for anti-detection, matching techniques used by
// undetected_chromedriver but adapted for Rod/CDP.
//
// Key anti-detection strategies:
// 1. Use Xvfb virtual display (HEADLESS=false) - real headed browser
// 2. Disable automation-controlled blink features
// 3. Use consistent, realistic user agent
// 4. Proper WebGL rendering with SwiftShader
// 5. No flags that reveal automation
//
// The proxyURL parameter sets the --proxy-server flag for Chrome.
// If empty, no proxy is configured.
func (p *Pool) createLauncher(proxyURL string) *launcher.Launcher {
	l := launcher.New()

	// Disable Rod's leakless watchdog (GitHub issue #10).
	// leakless execs a helper binary from $TMPDIR/leakless-* to kill the browser
	// if our process dies unexpectedly. That exec fails with "permission denied"
	// whenever /tmp is mounted noexec (the default for tmpfs, and the norm on
	// Unraid), breaking every browser launch. We don't need it: the container
	// runs dumb-init as PID 1 (reaps orphaned children and forwards signals) and
	// every teardown path goes through CleanupBrowser/l.Kill(), so the browser is
	// always reaped without the fragile exec-on-/tmp dependency.
	l = l.Leakless(false)

	// Custom browser path if specified
	if p.config.BrowserPath != "" {
		l = l.Bin(p.config.BrowserPath)
	}

	// ========================================
	// Display Mode Configuration
	// ========================================
	// HEADLESS=false (default in Docker): Uses Xvfb virtual display
	// This is the BEST option for anti-detection because:
	// - It's a real headed browser, not headless
	// - Full GPU/WebGL rendering pipeline
	// - No "HeadlessChrome" in any detection vectors
	// - Indistinguishable from a real desktop browser
	//
	// HEADLESS=true: Uses --headless=new (Chrome 109+)
	// Only use this when Xvfb is not available
	if p.config.Headless {
		l = l.Set("headless", "new")
	} else {
		// CRITICAL: Rod enables headless by default. We must explicitly disable it
		// when using Xvfb virtual display for anti-detection.
		// Without this, Chrome still runs in headless mode which Cloudflare detects.
		l = l.Headless(false)
	}
	// When HEADLESS=false, Chrome uses DISPLAY env var pointing to Xvfb (:99)

	// ========================================
	// Container Security Flags
	// ========================================
	// Chromium's sandbox is off unless BROWSER_SANDBOX=true: the default Docker
	// runtime grants neither the user namespaces nor the syscalls it needs.
	// go-rod adds --no-sandbox by itself when it detects a container, so the
	// flag has to be removed explicitly when the sandbox is wanted.
	l = l.NoSandbox(!p.config.BrowserSandbox)
	l = l.Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage")

	// ========================================
	// Proxy Configuration
	// ========================================
	if proxyURL != "" {
		l = l.Set("proxy-server", proxyURL)
		// Use redacted proxy URL in logs to prevent credential exposure
		log.Debug().Str("proxy", security.RedactProxyURL(proxyURL)).Msg("Browser proxy configured")
	}

	// ========================================
	// WebRTC Leak Prevention
	// ========================================
	// CRITICAL: Always prevent WebRTC IP leaks, not just when using proxy.
	// WebRTC can reveal the server's real public IP to target sites, which:
	// - Allows fingerprinting and correlation of requests
	// - Leaks internal network topology via ICE candidates
	// - Can be used by bot detection to identify automated traffic
	l = l.Set("force-webrtc-ip-handling-policy", "disable_non_proxied_udp")

	// ========================================
	// CRITICAL: Anti-Detection Flags
	// ========================================

	// 1. Disable AutomationControlled - prevents navigator.webdriver = true
	// This is the most important anti-detection flag
	l = l.Set("disable-blink-features", "AutomationControlled")

	// 2. Disable automation infobar and switches
	// Note: Rod/CDP doesn't use chromedriver, so we don't have those detection vectors
	// But these flags still help prevent other detection methods
	l = l.Delete("enable-automation") // Make sure this is NOT set

	// 3. Disable features that can leak automation or IP information
	// WebRtcHideLocalIpsWithMdns: Prevents mDNS from leaking local IPs
	//
	// DO NOT add "site-per-process" here. go-rod's default launcher disables it,
	// but this Set() replaces that default — keeping site isolation ON. Cloudflare
	// managed challenges render Turnstile in a cross-origin out-of-process iframe
	// (OOPIF); disabling site isolation collapses that iframe into the parent
	// process, so its render params (sitekey/action/cData/chlPageData) can no
	// longer be captured via auto-attach. See internal/captcha/oopif.go and
	// docs/INVESTIGATION-issue-11-oopif-probes.md.
	disabledFeatures := "Translate,TranslateUI,BlinkGenPropertyTrees,WebRtcHideLocalIpsWithMdns"
	l = l.Set("disable-features", disabledFeatures)

	// 4. Enable network service features (normal browser behavior)
	l = l.Set("enable-features", "NetworkService,NetworkServiceInProcess")

	// 5. WebGL — prefer system GPU via ANGLE/Vulkan, fallback to SwiftShader
	// SwiftShader reports "SwiftShader Device (0x0000C0DE)" which is an instant
	// bot detection signal for Cloudflare Enterprise. Using the system's Vulkan
	// driver (via ANGLE) reports the real GPU if available.
	// --ignore-gpu-blocklist allows Chrome to use GPUs it would normally blacklist.
	// --disable-gpu-sandbox is required for GPU access in Docker containers.
	l = l.Set("use-gl", "angle").
		Set("use-angle", "vulkan").
		Set("ignore-gpu-blocklist").
		Set("enable-webgl"). // Explicitly enable WebGL
		Set("enable-webgl2") // Enable WebGL 2.0

	// 6. Ignore certificate errors (like original FlareSolverr)
	// Required for some proxies and helps avoid SSL-related detection
	if p.config.IgnoreCertErrors {
		l = l.Set("ignore-certificate-errors")
		l = l.Set("ignore-ssl-errors")
	}

	// ========================================
	// Browser Behavior (Realistic)
	// ========================================

	// Language — use LANG env var if set, otherwise default to en-US
	acceptLang := "en-US,en;q=0.9"
	if p.config.BrowserLang != "" {
		// Convert locale format (e.g., "en_GB" → "en-GB,en;q=0.9")
		lang := strings.ReplaceAll(p.config.BrowserLang, "_", "-")
		// Strip .UTF-8 or similar suffixes
		if idx := strings.Index(lang, "."); idx > 0 {
			lang = lang[:idx]
		}
		acceptLang = lang + ",en;q=0.9"
	}
	l = l.Set("accept-lang", acceptLang)

	// First-run and dialogs
	l = l.Set("no-first-run").
		Set("no-default-browser-check").
		Set("disable-infobars").
		Set("disable-search-engine-choice-screen")

	// Window size - standard resolution
	l = l.Set("window-size", "1920,1080")

	// ========================================
	// Performance & Stability
	// ========================================
	l = l.Set("disable-background-networking").
		Set("disable-default-apps").
		Set("disable-extensions").
		Set("disable-sync").
		Set("mute-audio").
		Set("no-zygote").
		Set("safebrowsing-disable-auto-update")

	// Memory limits for container environment
	l = l.Set("js-flags", "--max-old-space-size=256").
		Set("disable-ipc-flooding-protection").
		Set("disable-renderer-backgrounding")

	// GPU sandbox - required for container environments
	l = l.Set("disable-gpu-sandbox")

	// ARM-specific: Use software compositing since hardware GPU compositing
	// may not be available on ARM devices (Raspberry Pi, etc.)
	if isARM() {
		l = l.Set("disable-gpu-compositing")
		log.Debug().Msg("ARM detected: using software compositing")
	}

	// The sandbox forks renderers from the zygote process; Chromium refuses to
	// start with "Zygote cannot be disabled if sandbox is enabled" otherwise.
	if p.config.BrowserSandbox {
		l = l.Delete("no-zygote")
	}

	return l
}

// spawnBrowser launches a new browser instance.
// This is an internal method - external code should use Acquire/Release.
// Each call creates a fresh launcher since launchers can only be used once.
// The context parameter allows for cancellation during shutdown.
func (p *Pool) spawnBrowser(ctx context.Context) (*rod.Browser, error) {
	log.Debug().Msg("Spawning new browser instance")

	// Pass the default proxy from config (may be empty)
	browser, err := p.launchAndConnect(ctx, p.createLauncher(p.config.ProxyURL))
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("Browser spawned successfully")
	return browser, nil
}

// launchAndConnect starts the Chrome process for l and connects to it over CDP.
// On every failure path the process is killed and its user-data dir removed.
func (p *Pool) launchAndConnect(ctx context.Context, l *launcher.Launcher) (*rod.Browser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	launchCtx, launchCancel := context.WithTimeout(ctx, browserLaunchTimeout)
	defer launchCancel()

	type launchResult struct {
		url string
		err error
	}
	launched := make(chan launchResult, 1)
	go func() {
		url, err := l.Launch()
		launched <- launchResult{url: url, err: err}
	}()

	var url string
	select {
	case res := <-launched:
		if res.err != nil {
			p.discardLauncher(l)
			return nil, fmt.Errorf("failed to launch browser: %w", res.err)
		}
		url = res.url
	case <-launchCtx.Done():
		// Launch is still blocked waiting for Chrome to report its debugging
		// URL. Kill the process now: that is what unblocks Launch, and a hung
		// Chrome left alive starves every later launch. Then reap again once
		// Launch returns, in case the process only started after the first kill.
		p.closeWg.Add(1)
		go func() {
			defer p.closeWg.Done()
			l.Kill() // no-op if the process has not started yet
			<-launched
			p.discardLauncher(l)
		}()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("browser launch timed out after %v", browserLaunchTimeout)
	}

	// Connect to the browser via CDP
	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		// Chrome is running but unreachable: kill it rather than wait for it.
		log.Warn().Err(err).Str("url", url).Msg("Failed to connect to browser, cleaning up process")
		p.discardLauncher(l)
		return nil, fmt.Errorf("failed to connect to browser: %w", err)
	}

	// Only ignore certificate errors if explicitly configured (security risk)
	if p.config.IgnoreCertErrors {
		log.Warn().Msg("Certificate validation disabled - MITM attacks possible")
		if err := browser.IgnoreCertErrors(true); err != nil {
			log.Warn().Err(err).Msg("Failed to set IgnoreCertErrors")
		}
	}

	// Store control URL for reconnection support
	p.controlURLs.Store(browser, url)
	// Retain the launcher so we can clean its user-data dir on close
	p.launchers.Store(browser, l)

	return browser, nil
}

// discardLauncher kills the process started by l (if any) and removes its
// user-data dir. Used when a launch did not produce a usable browser.
func (p *Pool) discardLauncher(l *launcher.Launcher) {
	l.Kill() // no-op if the process never started
	if dir := l.Get(flags.UserDataDir); dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			log.Warn().Err(err).Str("dir", dir).Msg("Failed to remove browser user-data dir")
		}
	}
}

// LaunchOptions configures a custom browser spawn with per-session overrides.
type LaunchOptions struct {
	ProxyURL   string   // Proxy URL (replaces pool default)
	WindowSize string   // "width,height" e.g. "1280,720"
	Language   string   // Accept-Language e.g. "fr-FR"
	Timezone   string   // Timezone for stealth patches (applied at JS level)
	Headless   *bool    // Override global headless setting
	DisableGPU *bool    // Force software rendering
	ExtraArgs  []string // Pre-validated extra Chrome flags
}

// SpawnWithOptions creates a new browser with custom launch options.
// This browser is NOT pooled and must be cleaned up by the caller.
// Use this when a session requires custom Chrome flags.
//
// The caller MUST call pool.CleanupBrowser(browser) when done — that closes
// the browser AND removes its /tmp/rod/user-data-<random> dir. Plain
// browser.Close() leaks the user-data dir on disk (GitHub issue #6):
//
//	browser, err := pool.SpawnWithOptions(ctx, opts)
//	if err != nil {
//	    return err
//	}
//	defer pool.CleanupBrowser(browser)
func (p *Pool) SpawnWithOptions(ctx context.Context, opts LaunchOptions) (*rod.Browser, error) {
	// Fall back to the configured default proxy: a session with custom flags
	// but no proxy of its own must not bypass PROXY_URL.
	proxyURL := opts.ProxyURL
	if proxyURL == "" {
		proxyURL = p.config.ProxyURL
	}

	log.Debug().
		Str("proxy", security.RedactProxyURL(proxyURL)).
		Str("window_size", opts.WindowSize).
		Str("language", opts.Language).
		Msg("Spawning browser with custom options")

	// Create launcher with proxy
	l := p.createLauncher(proxyURL)

	// Apply per-session overrides
	if opts.WindowSize != "" {
		l = l.Set("window-size", opts.WindowSize)
	}
	if opts.Language != "" {
		lang := strings.ReplaceAll(opts.Language, "_", "-")
		if idx := strings.Index(lang, "."); idx > 0 {
			lang = lang[:idx]
		}
		l = l.Set("accept-lang", lang+",en;q=0.9")
	}
	if opts.Headless != nil {
		if *opts.Headless {
			l = l.Set("headless", "new")
		} else {
			l = l.Headless(false)
		}
	}
	if opts.DisableGPU != nil && *opts.DisableGPU {
		l = l.Set("disable-gpu")
	}
	for _, arg := range opts.ExtraArgs {
		// Strip -- prefix for Rod's Set method
		flagStr := strings.TrimPrefix(arg, "--")
		if parts := strings.SplitN(flagStr, "=", 2); len(parts) == 2 {
			l = l.Set(flags.Flag(parts[0]), parts[1])
		} else {
			l = l.Set(flags.Flag(flagStr))
		}
	}

	browser, err := p.launchAndConnect(ctx, l)
	if err != nil {
		return nil, fmt.Errorf("custom browser spawn failed: %w", err)
	}

	log.Debug().Msg("Browser with custom options spawned successfully")
	return browser, nil
}

// SpawnWithProxy creates a new browser with a specific proxy configuration.
// This browser is NOT pooled and must be cleaned up by the caller.
// Use this when a request specifies a proxy different from the pool default.
//
// The caller MUST call pool.CleanupBrowser(browser) when done — that closes
// the browser AND removes its /tmp/rod/user-data-<random> dir. Plain
// browser.Close() leaks the user-data dir on disk (GitHub issue #6):
//
//	browser, err := pool.SpawnWithProxy(ctx, proxyURL)
//	if err != nil {
//	    return err
//	}
//	defer pool.CleanupBrowser(browser)
func (p *Pool) SpawnWithProxy(ctx context.Context, proxyURL string) (*rod.Browser, error) {
	// Use redacted proxy URL in logs to prevent credential exposure
	log.Debug().Str("proxy", security.RedactProxyURL(proxyURL)).Msg("Spawning browser with custom proxy")

	browser, err := p.launchAndConnect(ctx, p.createLauncher(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("proxy browser spawn failed: %w", err)
	}

	log.Debug().Str("proxy", security.RedactProxyURL(proxyURL)).Msg("Browser with proxy spawned successfully")
	return browser, nil
}

// Acquire obtains a browser from the pool.
// It blocks until a browser is available, the context is canceled,
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
			Int32("available", p.availableCount.Load()). // Fix #7: Use atomic counter instead of len() to avoid race
			Int("retry", retry).
			Msg("Acquiring browser from pool")

		select {
		case browser, ok := <-p.available:
			// Fix #3: Handle closed channel - ok is false when channel is closed
			if !ok || p.closed.Load() {
				// Channel was closed or pool is closing
				p.CleanupBrowser(browser) // safe on nil; also removes user-data dir
				return nil, types.ErrBrowserPoolClosed
			}
			p.availableCount.Add(-1)

			entry := p.checkOut(browser)
			if entry == nil {
				// Token for a browser that is no longer an idle pool member
				log.Warn().Msg("Dequeued a browser the pool no longer tracks as idle, skipping")
				continue
			}
			p.stats.Acquired.Add(1)

			// Verify browser is healthy before returning
			if !p.isHealthy(browser) {
				log.Warn().Int("retry", retry).Msg("Acquired unhealthy browser, recycling")
				p.stats.Errors.Add(1)
				p.mu.Lock()
				p.startRecycleLocked(entry)
				p.mu.Unlock()
				continue // Iterate instead of recurse
			}

			entry.useCount.Add(1)

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

// checkOut marks the slot holding browser as in use. It returns nil if the
// browser is not an idle pool member (the token is stale).
func (p *Pool) checkOut(browser *rod.Browser) *browserEntry {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry := p.entryFor(browser)
	if entry == nil || entry.state != entryIdle {
		return nil
	}
	entry.state = entryInUse
	return entry
}

// Release returns a browser to the pool.
// This method cleans up any pages and prepares the browser for reuse.
//
// It is safe to call Release on a nil browser, and a second Release of the
// same checked-out browser is ignored. A browser the pool does not own is
// closed rather than queued, so it can never be handed to another request.
func (p *Pool) Release(browser *rod.Browser) {
	if browser == nil {
		return
	}

	p.mu.Lock()
	entry := p.entryFor(browser)
	closed := p.closed.Load()
	if entry != nil && entry.state != entryInUse {
		p.mu.Unlock()
		log.Warn().Msg("Ignoring release of a pooled browser that is not checked out (duplicate release)")
		return
	}
	if entry != nil {
		p.stats.Released.Add(1)
	}
	p.mu.Unlock() // Release lock during slow I/O

	if entry == nil {
		// Not a pool member: a dedicated browser, a browser already replaced by
		// a recycle, or any browser after Close(). Tear it down.
		if !closed {
			log.Warn().Msg("Release called for a browser the pool does not own, closing it")
		}
		p.CleanupBrowser(browser)
		return
	}
	if closed {
		p.CleanupBrowser(browser)
		return
	}

	// Clean up all pages before returning to pool
	// This prevents memory accumulation across requests
	cleanupFailed := !p.closeAllPages(browser)

	// Re-acquire lock for the state change and channel send
	p.mu.Lock()

	// Double-check closed flag (may have changed during page cleanup)
	if p.closed.Load() {
		p.mu.Unlock()
		p.CleanupBrowser(browser)
		return
	}

	if cleanupFailed || entry.recycleOnRelease {
		if cleanupFailed {
			log.Warn().Msg("Page cleanup failed, recycling browser instead of returning to pool")
		}
		p.startRecycleLocked(entry)
		p.mu.Unlock()
		return
	}

	p.enqueueLocked(entry)
	p.mu.Unlock()

	log.Debug().
		Int64("total_released", p.stats.Released.Load()).
		Msg("Browser released to pool")
}

// closeAllPages navigates every open page to about:blank and closes it.
// Returns false if any step failed or timed out.
func (p *Pool) closeAllPages(browser *rod.Browser) bool {
	// Requests run inside their own browser context; drop any that were left
	// behind so their cookies and storage cannot reach the next request.
	disposeAllContexts(browser)

	ctx, cancel := context.WithTimeout(context.Background(), releaseCleanupTimeout)
	defer cancel()

	pages, err := browser.Context(ctx).Pages()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get pages for cleanup, browser may be unhealthy")
		return false
	}

	ok := true
	for _, page := range pages {
		page = page.Context(ctx)
		if err := page.Navigate("about:blank"); err != nil {
			log.Warn().Err(err).Msg("Failed to navigate page to blank during cleanup")
			ok = false
		}
		if err := page.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close page during cleanup")
			ok = false
		}
	}
	return ok
}

// enqueueLocked marks entry idle and queues its browser. Caller must hold p.mu
// and must have checked that the pool is not closed.
func (p *Pool) enqueueLocked(entry *browserEntry) {
	entry.state = entryIdle
	entry.recycleOnRelease = false
	select {
	case p.available <- entry.browser:
		p.availableCount.Add(1)
	default:
		// One token per idle slot and capacity == pool size, so this cannot
		// happen unless the accounting is broken. Recover by replacing the slot.
		log.Error().Msg("Pool queue full on enqueue, recycling browser")
		p.startRecycleLocked(entry)
	}
}

// isHealthy checks if a browser is responsive and usable.
// Every CDP call is bound to one deadline so a frozen browser fails the check
// instead of blocking Acquire.
func (p *Pool) isHealthy(browser *rod.Browser) bool {
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()

	// Try to create, navigate and close a page as a health check
	page, err := browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		log.Debug().Err(err).Msg("Browser health check failed: cannot create page")
		return false
	}
	page = page.Context(ctx)

	if err := page.Navigate("about:blank"); err != nil {
		log.Debug().Err(err).Msg("Browser health check failed: cannot navigate")
		// Ignore error: the browser is being recycled anyway
		_ = page.Close()
		return false
	}

	if err := page.Close(); err != nil {
		log.Debug().Err(err).Msg("Browser health check failed: cannot close page")
		return false
	}

	return true
}

// startRecycleLocked moves entry to the recycling state and replaces its
// browser in a tracked background goroutine. Caller must hold p.mu.
func (p *Pool) startRecycleLocked(entry *browserEntry) {
	entry.state = entryRecycling
	entry.recycleOnRelease = false
	if p.closed.Load() {
		return // Close() tears down every tracked browser
	}

	// Add under p.mu with the closed check above, so this never races Close()'s Wait.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.recycleEntry(entry)
	}()
}

// recycleEntry closes the browser in a recycling slot and spawns a replacement.
// If the replacement fails the slot is marked dead and the health routine
// retries, so a transient launch failure does not shrink the pool for good.
// Must NOT be called while holding p.mu.
func (p *Pool) recycleEntry(entry *browserEntry) {
	// Limit concurrent recycles to avoid launching many browsers at once
	select {
	case p.recycleSem <- struct{}{}:
		defer func() { <-p.recycleSem }()
	case <-p.stopCh:
		return
	}

	p.stats.Recycled.Add(1)
	log.Info().
		Int64("total_recycled", p.stats.Recycled.Load()).
		Msg("Recycling browser")

	p.mu.Lock()
	oldBrowser := entry.browser
	entry.browser = nil
	p.mu.Unlock()

	p.CleanupBrowser(oldBrowser) // bounded; safe on nil

	// Spawn the replacement, abandoning the attempt if the pool shuts down
	spawnCtx, spawnCancel := context.WithTimeout(context.Background(), browserRespawnTimeout)
	defer spawnCancel()
	go func() {
		select {
		case <-p.stopCh:
			spawnCancel()
		case <-spawnCtx.Done():
		}
	}()

	newBrowser, err := p.spawnBrowser(spawnCtx)

	p.mu.Lock()
	if err != nil {
		entry.state = entryDead
		p.mu.Unlock()
		log.Error().Err(err).Msg("Failed to spawn replacement browser, will retry on next health check")
		p.stats.Errors.Add(1)
		return
	}
	if p.closed.Load() {
		p.mu.Unlock()
		log.Warn().Msg("Pool closed during recycle, closing replacement browser")
		p.CleanupBrowser(newBrowser)
		return
	}

	entry.browser = newBrowser
	entry.createdAt = time.Now()
	entry.useCount.Store(0)
	p.enqueueLocked(entry)
	p.mu.Unlock()

	log.Info().Msg("Replacement browser added to pool")
}

// CleanupBrowser closes a browser and removes its on-disk user-data dir.
// This is the single chokepoint for browser teardown — every close path
// (internal and external) goes through here so /tmp/rod/user-data-<random>
// is always removed.
//
// External callers (solver, session manager, handlers) must use this method
// instead of browser.Close() for any browser obtained via SpawnWithProxy,
// SpawnWithOptions, or session ownership. Pooled browsers from Acquire()
// continue to use Release(), which routes here on close paths.
//
// The call is bounded: the close request has a deadline, and a process that
// does not exit afterwards is killed. It must not be called while holding p.mu.
//
// Safe to call with a nil browser. Errors are logged but not returned because
// cleanup must not block shutdown paths.
func (p *Pool) CleanupBrowser(browser *rod.Browser) {
	if browser == nil {
		return
	}
	if err := browser.Timeout(browserCloseTimeout).Close(); err != nil {
		log.Warn().Err(err).Msg("Error closing browser")
	}
	if v, ok := p.launchers.LoadAndDelete(browser); ok {
		if l, ok := v.(*launcher.Launcher); ok {
			p.reapLauncher(l)
		}
	}
	p.controlURLs.Delete(browser)
}

// reapLauncher waits for the browser process to exit and removes its user-data
// dir. go-rod's Launcher.Cleanup waits for exit without ever killing, so a
// process that ignores the close request is killed after browserExitGrace.
func (p *Pool) reapLauncher(l *launcher.Launcher) {
	exited := make(chan struct{})
	p.closeWg.Add(1)
	go func() {
		defer p.closeWg.Done()
		defer close(exited)
		l.Cleanup() // waits for process exit, then os.RemoveAll(user-data dir)
	}()

	select {
	case <-exited:
		return
	case <-time.After(browserExitGrace):
	}

	log.Warn().Int("pid", l.PID()).Msg("Browser process did not exit after close, killing it")
	l.Kill()

	select {
	case <-exited:
	case <-time.After(browserKillGrace):
		leaked := p.leakedGoroutines.Add(1)
		p.stats.Errors.Add(1)
		log.Error().
			Int("pid", l.PID()).
			Int32("leaked_count", leaked).
			Msg("Browser process still running after kill - cleanup goroutine leaked")
	}
}

// monitorMemory periodically samples the service's real memory usage and
// recycles idle browsers when it exceeds MAX_MEMORY_MB. See memory.go.
func (p *Pool) monitorMemory() {
	ticker := time.NewTicker(memoryCheckInterval)
	defer ticker.Stop()

	var lastRecycle time.Time

	for {
		select {
		case <-p.stopCh:
			log.Debug().Msg("Memory monitor stopping")
			return
		case <-ticker.C:
			if p.closed.Load() {
				return
			}

			var supported bool
			lastRecycle, supported = p.checkMemory(time.Now(), lastRecycle)
			if !supported {
				log.Debug().Msg("Memory usage cannot be measured on this platform, memory monitor disabled")
				return
			}
		}
	}
}

// healthCheckRoutine periodically recycles stale browsers and retries slots
// whose replacement previously failed.
func (p *Pool) healthCheckRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			log.Debug().Msg("Health check routine stopping")
			return
		case <-ticker.C:
			if p.closed.Load() {
				return
			}

			now := time.Now()
			started := p.recycleWhere(func(entry *browserEntry) bool {
				return now.Sub(entry.createdAt) > maxBrowserAge
			})
			if started > 0 {
				log.Info().Int("count", started).Msg("Recycling stale browsers")
			}
		}
	}
}

// recycleAll recycles all browsers in the pool.
// This is used when memory pressure is detected.
func (p *Pool) recycleAll() {
	started := p.recycleWhere(func(*browserEntry) bool { return true })
	log.Info().Int("count", started).Msg("Recycling browsers due to memory pressure")
}

// recycleWhere recycles every slot for which shouldRecycle returns true and
// returns how many recycles it started. Only idle browsers are recycled
// immediately; a browser that is checked out is flagged and recycled when its
// holder releases it. Dead slots are always retried.
func (p *Pool) recycleWhere(shouldRecycle func(*browserEntry) bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed.Load() {
		return 0
	}

	// Take every queued browser out of the channel. All sends happen under
	// p.mu, so nothing can be queued while we hold it and the refill below
	// cannot block.
	queued := make(map[*rod.Browser]struct{}, cap(p.available))
drain:
	for {
		select {
		case browser, ok := <-p.available:
			if !ok {
				return 0 // channel closed: pool is shutting down
			}
			queued[browser] = struct{}{}
			p.availableCount.Add(-1)
		default:
			break drain
		}
	}

	started := 0
	for _, entry := range p.browsers {
		switch entry.state {
		case entryDead:
			p.startRecycleLocked(entry)
			started++
		case entryIdle:
			_, isQueued := queued[entry.browser]
			switch {
			case !shouldRecycle(entry):
				if isQueued {
					p.enqueueLocked(entry)
				}
			case isQueued:
				p.startRecycleLocked(entry)
				started++
			default:
				// Dequeued by an Acquire that has not marked it in use yet
				entry.recycleOnRelease = true
			}
		case entryInUse:
			if shouldRecycle(entry) {
				entry.recycleOnRelease = true
			}
		case entryRecycling:
			// already being replaced
		}
	}
	return started
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
	Acquired         int64
	Released         int64
	Recycled         int64
	Errors           int64
	LeakedGoroutines int32 // Audit Issue 2: Track browser close timeout goroutine leaks
}

// Stats returns a snapshot of the current pool statistics.
func (p *Pool) Stats() PoolStatsSnapshot {
	return PoolStatsSnapshot{
		Acquired:         p.stats.Acquired.Load(),
		Released:         p.stats.Released.Load(),
		Recycled:         p.stats.Recycled.Load(),
		Errors:           p.stats.Errors.Load(),
		LeakedGoroutines: p.leakedGoroutines.Load(),
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
// Fix #1, #2: Coordinates channel close with Release() using mutex.
// Fix #10: Waits for browser close goroutines to complete.
// Fix #38: Resets stats on close for accurate reporting.
func (p *Pool) Close() error {
	// Fix #2: Set closed flag under lock to coordinate with Release()
	p.mu.Lock()
	if p.closed.Swap(true) {
		p.mu.Unlock()
		return nil // Already closed
	}
	// Close channel while holding lock to prevent send-on-closed-channel panic
	close(p.available)
	p.mu.Unlock()

	log.Info().Msg("Closing browser pool")

	// Signal background goroutines to stop immediately
	close(p.stopCh)

	// Wait for background goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Debug().Msg("Background goroutines stopped")
	case <-time.After(30 * time.Second):
		log.Warn().Msg("Timeout waiting for background goroutines to stop")
	}

	// Fix #10: Wait for any pending close goroutines
	closeWgDone := make(chan struct{})
	go func() {
		p.closeWg.Wait()
		close(closeWgDone)
	}()
	select {
	case <-closeWgDone:
		log.Debug().Msg("Browser close goroutines finished")
	case <-time.After(15 * time.Second):
		log.Warn().Msg("Timeout waiting for browser close goroutines")
	}

	p.mu.Lock()
	browsers := make([]*rod.Browser, 0, len(p.browsers))
	for _, entry := range p.browsers {
		if entry.browser != nil {
			browsers = append(browsers, entry.browser)
		}
	}
	p.browsers = nil
	p.mu.Unlock()

	// Close all browsers in parallel using errgroup
	// Limit concurrent closes to prevent resource exhaustion
	eg := new(errgroup.Group)
	eg.SetLimit(4) // Close up to 4 browsers concurrently

	for _, browser := range browsers {
		eg.Go(func() error {
			// CleanupBrowser closes the browser AND removes its user-data dir.
			// Errors are already logged inside; returning nil keeps the parallel
			// shutdown progressing instead of bailing on the first failure.
			p.CleanupBrowser(browser)
			return nil
		})
	}

	// Wait for all browsers to close
	closeErr := eg.Wait()

	// Drain any remaining items from channel (safe after close)
	for b := range p.available {
		p.CleanupBrowser(b) // safe on nil
	}

	// Fix MEDIUM: Capture stats before resetting so we can log actual values
	finalAcquired := p.stats.Acquired.Load()
	finalReleased := p.stats.Released.Load()
	finalRecycled := p.stats.Recycled.Load()
	finalErrors := p.stats.Errors.Load()

	// Fix #38: Reset stats on close
	p.stats.Acquired.Store(0)
	p.stats.Released.Store(0)
	p.stats.Recycled.Store(0)
	p.stats.Errors.Store(0)

	log.Info().
		Int64("total_acquired", finalAcquired).
		Int64("total_released", finalReleased).
		Int64("total_recycled", finalRecycled).
		Int64("total_errors", finalErrors).
		Msg("Browser pool closed")

	return closeErr
}

// isARM returns true if running on ARM architecture.
func isARM() bool {
	arch := runtime.GOARCH
	return arch == "arm" || arch == "arm64"
}
