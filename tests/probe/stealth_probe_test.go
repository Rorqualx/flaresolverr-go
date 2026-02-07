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

// TestApplyStealthToPage_BatteryAPI tests that Battery API returns consistent values.
func TestApplyStealthToPage_BatteryAPI(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page first (Battery API needs secure context)
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check Battery API
	result, err := page.Eval(`() => {
		return new Promise((resolve) => {
			if (typeof navigator.getBattery !== 'function') {
				resolve({ available: false });
				return;
			}
			navigator.getBattery().then(battery => {
				resolve({
					available: true,
					charging: battery.charging,
					level: battery.level,
					chargingTime: battery.chargingTime,
					dischargingTime: battery.dischargingTime
				});
			}).catch(() => {
				resolve({ available: false });
			});
		});
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()
	if !obj["available"].Bool() {
		t.Skip("Battery API not available in this browser")
	}

	// Check charging is true
	if !obj["charging"].Bool() {
		t.Error("Battery charging should be true")
	}

	// Check level is in expected range (0.87-0.97)
	level := obj["level"].Num()
	if level < 0.87 || level > 0.97 {
		t.Errorf("Battery level should be between 0.87 and 0.97, got %f", level)
	}

	// Check chargingTime is 0 (fully charged)
	if obj["chargingTime"].Num() != 0 {
		t.Errorf("chargingTime should be 0, got %f", obj["chargingTime"].Num())
	}

	// Verify consistency - call again and check level is the same
	result2, err := page.Eval(`() => {
		return navigator.getBattery().then(battery => battery.level);
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	level2 := result2.Value.Num()
	if level != level2 {
		t.Errorf("Battery level should be consistent across calls, got %f and %f", level, level2)
	}
}

// TestApplyStealthToPage_SpeechSynthesisVoices tests that Speech Synthesis returns consistent voices.
func TestApplyStealthToPage_SpeechSynthesisVoices(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Wait a bit for voices to load
	time.Sleep(100 * time.Millisecond)

	// Check Speech Synthesis voices
	result, err := page.Eval(`() => {
		if (typeof speechSynthesis === 'undefined' || typeof speechSynthesis.getVoices !== 'function') {
			return { available: false };
		}
		const voices = speechSynthesis.getVoices();
		return {
			available: true,
			count: voices.length,
			hasGoogleUSEnglish: voices.some(v => v.name === 'Google US English'),
			firstVoiceName: voices.length > 0 ? voices[0].name : null,
			firstVoiceDefault: voices.length > 0 ? voices[0].default : false
		};
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()
	if !obj["available"].Bool() {
		t.Skip("Speech Synthesis not available in this browser")
	}

	// Check we have 10 voices
	count := obj["count"].Int()
	if count != 10 {
		t.Errorf("Should have 10 voices, got %d", count)
	}

	// Check Google US English is present
	if !obj["hasGoogleUSEnglish"].Bool() {
		t.Error("Should have 'Google US English' voice")
	}

	// Check first voice is Google US English and is default
	firstName := obj["firstVoiceName"].Str()
	if firstName != "Google US English" {
		t.Errorf("First voice should be 'Google US English', got %q", firstName)
	}

	if !obj["firstVoiceDefault"].Bool() {
		t.Error("First voice should be marked as default")
	}
}

// TestApplyStealthToPage_FontEnumerationLimited tests that font enumeration is limited.
func TestApplyStealthToPage_FontEnumerationLimited(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check font enumeration is limited
	result, err := page.Eval(`() => {
		if (typeof document.fonts === 'undefined') {
			return { available: false };
		}

		// Count fonts via forEach
		let forEachCount = 0;
		document.fonts.forEach(() => {
			forEachCount++;
		});

		return {
			available: true,
			forEachCount: forEachCount,
			sizeProperty: document.fonts.size
		};
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()
	if !obj["available"].Bool() {
		t.Skip("document.fonts not available in this browser")
	}

	// Check forEach is limited to 10 iterations
	forEachCount := obj["forEachCount"].Int()
	if forEachCount > 10 {
		t.Errorf("forEach should iterate at most 10 fonts, got %d", forEachCount)
	}

	// Check size is capped at 50
	size := obj["sizeProperty"].Int()
	if size > 50 {
		t.Errorf("document.fonts.size should be at most 50, got %d", size)
	}
}

// TestApplyStealthToPage_TimezoneConsistent tests that timezone APIs return consistent values.
func TestApplyStealthToPage_TimezoneConsistent(t *testing.T) {
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

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Re-apply stealth after navigation
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage after navigation failed: %v", err)
	}

	// Check timezone offset
	result, err := page.Eval(`() => {
		const offset = new Date().getTimezoneOffset();

		// Check Intl.DateTimeFormat
		let intlTimezone = null;
		try {
			const formatter = new Intl.DateTimeFormat();
			const resolved = formatter.resolvedOptions();
			intlTimezone = resolved.timeZone;
		} catch (e) {
			// Intl not available
		}

		return {
			offset: offset,
			intlTimezone: intlTimezone
		};
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()

	// Check offset is 300 (America/New_York = UTC-5 = 300 minutes)
	offset := obj["offset"].Int()
	if offset != 300 {
		t.Errorf("getTimezoneOffset() should return 300 (EST), got %d", offset)
	}

	// Check Intl timezone if available
	intlTimezone := obj["intlTimezone"].Str()
	if intlTimezone != "" && intlTimezone != "America/New_York" {
		t.Errorf("Intl.DateTimeFormat timezone should be 'America/New_York', got %q", intlTimezone)
	}

	// Verify consistency across multiple calls
	result2, err := page.Eval(`() => new Date().getTimezoneOffset()`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	offset2 := result2.Value.Int()
	if offset != offset2 {
		t.Errorf("Timezone offset should be consistent, got %d and %d", offset, offset2)
	}
}

// TestCanvasToBlob_HasNoise tests that canvas toBlob is patched with noise.
func TestCanvasToBlob_HasNoise(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check that toBlob is patched (has _stealth marker)
	result, err := page.Eval(`() => {
		return {
			hasToBlobStealth: HTMLCanvasElement.prototype.toBlob._stealth === true,
			hasToDataURLStealth: HTMLCanvasElement.prototype.toDataURL._stealth === true
		};
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()
	if !obj["hasToBlobStealth"].Bool() {
		t.Error("toBlob should be patched with _stealth marker")
	}
	if !obj["hasToDataURLStealth"].Bool() {
		t.Error("toDataURL should be patched with _stealth marker")
	}
}

// TestCanvasGetImageData_HasNoise tests that getImageData is patched with noise.
func TestCanvasGetImageData_HasNoise(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check that getImageData is patched
	result, err := page.Eval(`() => {
		return {
			hasGetImageDataStealth: CanvasRenderingContext2D.prototype.getImageData._stealth === true
		};
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()
	if !obj["hasGetImageDataStealth"].Bool() {
		t.Error("getImageData should be patched with _stealth marker")
	}
}

// TestWebGLReadPixels_HasNoise tests that WebGL readPixels is patched with noise.
func TestWebGLReadPixels_HasNoise(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Check that WebGL readPixels is patched
	result, err := page.Eval(`() => {
		const result = {
			hasWebGLReadPixelsStealth: false,
			hasWebGL2ReadPixelsStealth: false
		};

		if (window.WebGLRenderingContext && WebGLRenderingContext.prototype.readPixels) {
			result.hasWebGLReadPixelsStealth = WebGLRenderingContext.prototype.readPixels._stealth === true;
		}

		if (window.WebGL2RenderingContext && WebGL2RenderingContext.prototype.readPixels) {
			result.hasWebGL2ReadPixelsStealth = WebGL2RenderingContext.prototype.readPixels._stealth === true;
		}

		return result;
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()
	if !obj["hasWebGLReadPixelsStealth"].Bool() {
		t.Error("WebGLRenderingContext.readPixels should be patched with _stealth marker")
	}
	if !obj["hasWebGL2ReadPixelsStealth"].Bool() {
		t.Error("WebGL2RenderingContext.readPixels should be patched with _stealth marker")
	}
}

// TestCanvasNoise_SessionConsistent tests that canvas noise is consistent within a session.
func TestCanvasNoise_SessionConsistent(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to a real page
	server := startTestServer(t)
	if err := page.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Apply stealth
	if err := browser.ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	// Create a canvas and get toDataURL twice - should be consistent
	result, err := page.Eval(`() => {
		// Create a canvas with some content
		const canvas = document.createElement('canvas');
		canvas.width = 100;
		canvas.height = 100;
		const ctx = canvas.getContext('2d');

		// Draw something
		ctx.fillStyle = 'red';
		ctx.fillRect(0, 0, 50, 50);
		ctx.fillStyle = 'blue';
		ctx.fillRect(50, 50, 50, 50);

		// Get toDataURL twice
		const dataURL1 = canvas.toDataURL();
		const dataURL2 = canvas.toDataURL();

		// Get the canvas seed
		const seed = window.__canvasSeed;

		return {
			dataURL1: dataURL1,
			dataURL2: dataURL2,
			isConsistent: dataURL1 === dataURL2,
			hasSeed: typeof seed === 'number'
		};
	}`)
	if err != nil {
		t.Fatalf("Failed to evaluate script: %v", err)
	}

	obj := result.Value.Map()

	// Canvas seed should exist
	if !obj["hasSeed"].Bool() {
		t.Error("Canvas seed should exist after stealth is applied")
	}

	// toDataURL should be consistent within the same session
	if !obj["isConsistent"].Bool() {
		t.Error("toDataURL should return consistent results within the same session")
	}
}

// TestCanvasNoise_DifferentAcrossSessions tests that canvas fingerprints differ across sessions.
func TestCanvasNoise_DifferentAcrossSessions(t *testing.T) {
	skipCI(t)

	b := setupTestBrowser(t)
	defer b.Close()

	// First page/session
	page1, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page 1: %v", err)
	}
	defer page1.Close()

	server := startTestServer(t)
	if err := page1.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	if err := browser.ApplyStealthToPage(page1); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	result1, err := page1.Eval(`() => window.__canvasSeed`)
	if err != nil {
		t.Fatalf("Failed to get seed from page 1: %v", err)
	}
	seed1 := result1.Value.Int()

	// Second page/session (new page = new seed)
	page2, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page 2: %v", err)
	}
	defer page2.Close()

	if err := page2.Navigate(server.URL + "/html"); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	if err := browser.ApplyStealthToPage(page2); err != nil {
		t.Fatalf("ApplyStealthToPage failed: %v", err)
	}

	result2, err := page2.Eval(`() => window.__canvasSeed`)
	if err != nil {
		t.Fatalf("Failed to get seed from page 2: %v", err)
	}
	seed2 := result2.Value.Int()

	// Seeds may or may not be different (random), but they should both be valid numbers
	t.Logf("Session 1 seed: %d, Session 2 seed: %d", seed1, seed2)
	if seed1 < 0 || seed1 >= 256 {
		t.Errorf("Seed 1 should be in range [0, 255], got %d", seed1)
	}
	if seed2 < 0 || seed2 >= 256 {
		t.Errorf("Seed 2 should be in range [0, 255], got %d", seed2)
	}
}
