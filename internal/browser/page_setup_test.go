package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

// pageSetupProbe reads the values the two request paths used to disagree on.
const pageSetupProbe = `() => ({
	userAgent: navigator.userAgent,
	webdriver: navigator.webdriver === false || navigator.webdriver === undefined,
	webdriverOwn: Object.getOwnPropertyNames(navigator).includes('webdriver'),
	pluginArray: Object.prototype.toString.call(navigator.plugins) === '[object PluginArray]',
	innerWidth: window.innerWidth,
	innerHeight: window.innerHeight,
	timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
	customScript: window.__stealthApplied === true,
	languages: navigator.languages.join(','),
	languagesNative: Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages').get.toString().includes('[native code]'),
	holderLeft: '__nativeLanguages' in window,
})`

// TestPreparePage checks, in a real browser, that the shared page setup leaves
// the page in the state both request paths rely on.
func TestPreparePage(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	poolBrowser, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	defer pool.Release(poolBrowser)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><html><body><p>setup</p></body></html>")
	}))
	defer server.Close()

	const testUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"

	tests := []struct {
		name         string
		setup        PageSetup
		wantTimezone string // empty: not checked
		wantLangs    string
	}{
		{name: "user agent only", setup: PageSetup{UserAgent: testUA}, wantLangs: "en-US,en"},
		{name: "user agent and timezone", setup: PageSetup{UserAgent: testUA, Timezone: "Asia/Tokyo"}, wantTimezone: "Asia/Tokyo", wantLangs: "en-US,en"},
		{name: "configured languages", setup: PageSetup{UserAgent: testUA, AcceptLanguages: "fr-FR,fr,en"}, wantLangs: "fr-FR,fr,en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := poolBrowser.Page(proto.TargetCreateTarget{URL: "about:blank"})
			if err != nil {
				t.Fatalf("Failed to create page: %v", err)
			}
			defer func() {
				// Ignore error: cleanup should not affect the test result
				_ = page.Close()
			}()

			if err := PreparePage(page, tt.setup); err != nil {
				t.Fatalf("PreparePage failed: %v", err)
			}
			if err := page.Navigate(server.URL); err != nil {
				t.Fatalf("Navigation failed: %v", err)
			}
			if err := page.WaitLoad(); err != nil {
				t.Fatalf("WaitLoad failed: %v", err)
			}

			res, err := page.Eval(pageSetupProbe)
			if err != nil {
				t.Fatalf("Probe failed: %v", err)
			}
			got := res.Value

			if ua := got.Get("userAgent").Str(); ua != testUA {
				t.Errorf("navigator.userAgent = %q, want %q", ua, testUA)
			}
			if !got.Get("webdriver").Bool() {
				t.Error("navigator.webdriver is not false")
			}
			if got.Get("webdriverOwn").Bool() {
				t.Error("navigator has an own webdriver property; it must stay on the prototype")
			}
			if !got.Get("pluginArray").Bool() {
				t.Error("navigator.plugins is not a PluginArray")
			}
			if w, h := got.Get("innerWidth").Int(), got.Get("innerHeight").Int(); w != DefaultViewportWidth || h != DefaultViewportHeight {
				t.Errorf("viewport = %dx%d, want %dx%d", w, h, DefaultViewportWidth, DefaultViewportHeight)
			}
			if got.Get("customScript").Bool() {
				t.Error("the custom stealth script ran; request pages must use go-rod/stealth only")
			}
			if langs := got.Get("languages").Str(); langs != tt.wantLangs {
				t.Errorf("navigator.languages = %q, want %q", langs, tt.wantLangs)
			}
			if !got.Get("languagesNative").Bool() {
				t.Error("navigator.languages is not Chrome's own getter")
			}
			if got.Get("holderLeft").Bool() {
				t.Error("the temporary languages holder was left on window")
			}
			if tt.wantTimezone != "" {
				if tz := got.Get("timezone").Str(); tz != tt.wantTimezone {
					t.Errorf("timezone = %q, want %q", tz, tt.wantTimezone)
				}
			}
		})
	}
}
