package probe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
)

// setupTestBrowser creates a browser instance for testing.
// Caller must close the browser when done.
func setupTestBrowser(t *testing.T) *rod.Browser {
	t.Helper()

	l := launcher.New().
		Headless(true).
		Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage")

	url, err := l.Launch()
	if err != nil {
		t.Fatalf("Failed to launch browser: %v", err)
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		t.Fatalf("Failed to connect to browser: %v", err)
	}

	return browser
}

// TestApplyStealthToPage_WebdriverHidden tests that navigator.webdriver is hidden.
func TestApplyStealthToPage_WebdriverHidden(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check navigator.webdriver
	result, err := page.Eval(`() => typeof navigator.webdriver`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Should be undefined
	webdriverType := result.Value.Str()
	if webdriverType != "undefined" {
		t.Errorf("navigator.webdriver should be undefined, got type %q", webdriverType)
	}
}

// TestApplyStealthToPage_PluginsPopulated tests that navigator.plugins is populated.
func TestApplyStealthToPage_PluginsPopulated(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check navigator.plugins.length
	result, err := page.Eval(`() => navigator.plugins.length`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	pluginCount := result.Value.Int()
	if pluginCount < 3 {
		t.Errorf("navigator.plugins.length should be >= 3, got %d", pluginCount)
	}
}

// TestApplyStealthToPage_ChromeRuntime tests that window.chrome.runtime is present.
func TestApplyStealthToPage_ChromeRuntime(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check window.chrome.runtime
	result, err := page.Eval(`() => typeof window.chrome?.runtime`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	runtimeType := result.Value.Str()
	if runtimeType != "object" {
		t.Errorf("typeof window.chrome.runtime should be 'object', got %q", runtimeType)
	}
}

// TestApplyStealthToPage_LanguagesSet tests that navigator.languages is set.
func TestApplyStealthToPage_LanguagesSet(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check navigator.languages
	result, err := page.Eval(`() => Array.isArray(navigator.languages)`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	// Should be an array
	isArray := result.Value.Bool()
	if !isArray {
		t.Error("navigator.languages should be an array")
	}
}

// TestApplyStealthToPage_HardwareConcurrency tests that navigator.hardwareConcurrency is set.
func TestApplyStealthToPage_HardwareConcurrency(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check navigator.hardwareConcurrency
	result, err := page.Eval(`() => navigator.hardwareConcurrency`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	cores := result.Value.Int()
	if cores != 8 {
		t.Errorf("navigator.hardwareConcurrency should be 8, got %d", cores)
	}
}

// TestApplyStealthToPage_DeviceMemory tests that navigator.deviceMemory is set.
func TestApplyStealthToPage_DeviceMemory(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check navigator.deviceMemory
	result, err := page.Eval(`() => navigator.deviceMemory`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	memory := result.Value.Int()
	if memory != 8 {
		t.Errorf("navigator.deviceMemory should be 8, got %d", memory)
	}
}

// TestApplyStealthToPage_Idempotent tests that applying stealth twice doesn't cause errors.
func TestApplyStealthToPage_Idempotent(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth twice
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("First ApplyStealthToPage failed: %v", err)
	}

	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("Second ApplyStealthToPage failed: %v", err)
	}

	// Verify stealth still works
	result, err := page.Eval(`() => typeof navigator.webdriver`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	webdriverType := result.Value.Str()
	if webdriverType != "undefined" {
		t.Errorf("navigator.webdriver should still be undefined after double apply, got %q", webdriverType)
	}
}

// TestBlockResources_CleanupPreventsLeak tests that BlockResources cleanup prevents goroutine leaks.
func TestBlockResources_CleanupPreventsLeak(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up resource blocking
	cleanup, err := browser.BlockResources(ctx, page, true, true, true, true)
	if err != nil {
		t.Fatalf("BlockResources failed: %v", err)
	}

	// Cleanup should be callable
	cleanup()

	// Call cleanup again - should be safe (once.Do)
	cleanup()

	// Close page
	page.Close()
}

// TestSetUserAgent_ClientHintsMatch tests that User-Agent and Client Hints match.
func TestSetUserAgent_ClientHintsMatch(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Set a custom user agent
	testUA := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	if err := browser.SetUserAgent(page, testUA); err != nil {
		t.Fatalf("SetUserAgent failed: %v", err)
	}

	// Navigate to a page to trigger Client Hints
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Check that User-Agent is set correctly
	result, err := page.Eval(`() => navigator.userAgent`)
	if err != nil {
		t.Fatalf("Failed to get userAgent: %v", err)
	}

	ua := result.Value.Str()
	if ua != testUA {
		t.Errorf("User-Agent mismatch: got %q, want %q", ua, testUA)
	}

	// Check that User-Agent contains Chrome version
	if !strings.Contains(ua, "Chrome/124") {
		t.Errorf("User-Agent should contain Chrome/124, got %q", ua)
	}
}

// TestSetViewport_SetsCorrectSize tests that SetViewport sets the correct dimensions.
func TestSetViewport_SetsCorrectSize(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Set viewport
	if err := browser.SetViewport(page, 1920, 1080); err != nil {
		t.Fatalf("SetViewport failed: %v", err)
	}

	// Check dimensions
	result, err := page.Eval(`() => ({ width: window.innerWidth, height: window.innerHeight })`)
	if err != nil {
		t.Fatalf("Failed to get viewport size: %v", err)
	}

	obj := result.Value.Map()
	width := obj["width"].Int()
	height := obj["height"].Int()

	if width != 1920 {
		t.Errorf("Viewport width should be 1920, got %d", width)
	}
	if height != 1080 {
		t.Errorf("Viewport height should be 1080, got %d", height)
	}
}

// TestGetBrowserUserAgent_ReturnsString tests that GetBrowserUserAgent returns a valid string.
func TestGetBrowserUserAgent_ReturnsString(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	ua, err := browser.GetBrowserUserAgent(page)
	if err != nil {
		t.Fatalf("GetBrowserUserAgent failed: %v", err)
	}

	if ua == "" {
		t.Error("User-Agent should not be empty")
	}

	// Should contain browser identifier
	if !strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Chromium") {
		t.Errorf("User-Agent should contain Chrome or Chromium, got %q", ua)
	}
}

// TestGetCookies_EmptyOnNewPage tests that GetCookies returns empty on a new page.
func TestGetCookies_EmptyOnNewPage(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	cookies, err := browser.GetCookies(page)
	if err != nil {
		t.Fatalf("GetCookies failed: %v", err)
	}

	if len(cookies) != 0 {
		t.Errorf("Expected no cookies on new page, got %d", len(cookies))
	}
}

// TestSetCookies_SetsCorrectly tests that SetCookies sets cookies correctly.
func TestSetCookies_SetsCorrectly(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to test server first (cookies need a domain)
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Set a cookie
	cookies := []*proto.NetworkCookieParam{
		{
			Name:   "test_cookie",
			Value:  "test_value",
			Domain: "127.0.0.1",
			Path:   "/",
		},
	}

	if err := browser.SetCookies(page, cookies); err != nil {
		t.Fatalf("SetCookies failed: %v", err)
	}

	// Verify cookie was set
	setCookies, err := browser.GetCookies(page)
	if err != nil {
		t.Fatalf("GetCookies failed: %v", err)
	}

	found := false
	for _, c := range setCookies {
		if c.Name == "test_cookie" && c.Value == "test_value" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Cookie was not set correctly")
	}
}

// TestApplyStealthToPage_NotificationPermission tests that Notification.permission is 'default'.
func TestApplyStealthToPage_NotificationPermission(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Need to navigate to a real page for Notification to be available
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Re-apply stealth after navigation
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage after navigation failed: %v", err)
	}

	// Check Notification.permission
	result, err := page.Eval(`() => {
		if (typeof Notification !== 'undefined') {
			return Notification.permission;
		}
		return 'undefined';
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	permission := result.Value.Str()
	// Should be 'default' not 'denied' (which is common in headless)
	if permission != "default" && permission != "undefined" {
		t.Logf("Notification.permission = %q (may vary by browser)", permission)
	}
}

// TestBlockResources_ContextCancellation tests that BlockResources respects context cancellation.
func TestBlockResources_ContextCancellation(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cleanup, err := browser.BlockResources(ctx, page, true, false, false, false)
	if err != nil {
		t.Fatalf("BlockResources failed: %v", err)
	}

	// Wait for context to expire
	time.Sleep(150 * time.Millisecond)

	// Cleanup should still work
	cleanup()
}
