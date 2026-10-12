package humanize

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

func TestDefaultScrollConfig(t *testing.T) {
	config := DefaultScrollConfig()

	if config.MinScrollSteps <= 0 {
		t.Error("MinScrollSteps should be positive")
	}
	if config.MaxScrollSteps < config.MinScrollSteps {
		t.Error("MaxScrollSteps should be >= MinScrollSteps")
	}
	if config.MinStepDelayMs <= 0 {
		t.Error("MinStepDelayMs should be positive")
	}
	if config.MaxStepDelayMs < config.MinStepDelayMs {
		t.Error("MaxStepDelayMs should be >= MinStepDelayMs")
	}
	if config.ScrollMargin < 0 {
		t.Error("ScrollMargin should be non-negative")
	}
	if config.PreScrollDelayMinMs <= 0 {
		t.Error("PreScrollDelayMinMs should be positive")
	}
	if config.PreScrollDelayMaxMs < config.PreScrollDelayMinMs {
		t.Error("PreScrollDelayMaxMs should be >= PreScrollDelayMinMs")
	}
	if config.PostScrollDelayMinMs <= 0 {
		t.Error("PostScrollDelayMinMs should be positive")
	}
	if config.PostScrollDelayMaxMs < config.PostScrollDelayMinMs {
		t.Error("PostScrollDelayMaxMs should be >= PostScrollDelayMinMs")
	}
}

func TestEaseOutCubic(t *testing.T) {
	tests := []struct {
		name string
		t    float64
		want float64
	}{
		{"start", 0.0, 0.0},
		{"end", 1.0, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := easeOutCubic(tt.t)
			if !floatsClose(got, tt.want, 0.001) {
				t.Errorf("easeOutCubic(%v) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}

	// Test that easeOutCubic is faster at the start (deceleration)
	// At t=0.5, easeOutCubic should be > 0.5 (already past halfway)
	midpoint := easeOutCubic(0.5)
	if midpoint <= 0.5 {
		t.Errorf("easeOutCubic(0.5) = %v, expected > 0.5 for deceleration effect", midpoint)
	}

	// Test monotonicity
	prev := 0.0
	for i := 0; i <= 100; i++ {
		tVal := float64(i) / 100.0
		result := easeOutCubic(tVal)
		if result < prev {
			t.Errorf("easeOutCubic is not monotonic: f(%v) = %v < %v", tVal, result, prev)
		}
		prev = result
	}
}

func TestInViewport(t *testing.T) {
	const viewportHeight, margin = 1000.0, 100.0

	tests := []struct {
		name           string
		top, bottom    float64
		viewportHeight float64
		margin         float64
		want           bool
	}{
		{name: "middle of the viewport", top: 400, bottom: 500, viewportHeight: viewportHeight, margin: margin, want: true},
		{name: "exactly at the top margin", top: 100, bottom: 200, viewportHeight: viewportHeight, margin: margin, want: true},
		{name: "exactly at the bottom margin", top: 800, bottom: 900, viewportHeight: viewportHeight, margin: margin, want: true},
		{name: "inside the top margin", top: 99, bottom: 200, viewportHeight: viewportHeight, margin: margin, want: false},
		{name: "inside the bottom margin", top: 800, bottom: 901, viewportHeight: viewportHeight, margin: margin, want: false},
		{name: "above the viewport", top: -300, bottom: -200, viewportHeight: viewportHeight, margin: margin, want: false},
		{name: "below the viewport", top: 1200, bottom: 1300, viewportHeight: viewportHeight, margin: margin, want: false},
		{name: "straddling the bottom edge", top: 950, bottom: 1050, viewportHeight: viewportHeight, margin: margin, want: false},
		{name: "taller than the usable viewport", top: 100, bottom: 950, viewportHeight: viewportHeight, margin: margin, want: false},
		{name: "a point", top: 500, bottom: 500, viewportHeight: viewportHeight, margin: margin, want: true},
		{name: "no margin, touching both edges", top: 0, bottom: 1000, viewportHeight: viewportHeight, margin: 0, want: true},
		{name: "viewport smaller than two margins", top: 80, bottom: 90, viewportHeight: 150, margin: margin, want: false},
		{name: "zero-height viewport", top: 0, bottom: 0, viewportHeight: 0, margin: 0, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inViewport(tt.top, tt.bottom, tt.viewportHeight, tt.margin); got != tt.want {
				t.Errorf("inViewport(%v, %v, %v, %v) = %v, want %v", tt.top, tt.bottom, tt.viewportHeight, tt.margin, got, tt.want)
			}
		})
	}
}

func TestTargetScrollY(t *testing.T) {
	tests := []struct {
		name           string
		centerY        float64 // relative to the viewport
		scrollY        float64
		viewportHeight float64
		contentHeight  float64
		want           float64
	}{
		{name: "element below, page at top", centerY: 2500, scrollY: 0, viewportHeight: 1000, contentHeight: 5000, want: 2000},
		{name: "element below, page already scrolled", centerY: 1500, scrollY: 1000, viewportHeight: 1000, contentHeight: 5000, want: 2000},
		{name: "element above the viewport", centerY: -700, scrollY: 3000, viewportHeight: 1000, contentHeight: 5000, want: 1800},
		{name: "element already centered", centerY: 500, scrollY: 1200, viewportHeight: 1000, contentHeight: 5000, want: 1200},
		{name: "near the top clamps to zero", centerY: 50, scrollY: 0, viewportHeight: 1000, contentHeight: 5000, want: 0},
		{name: "near the bottom clamps to the last position", centerY: 4950, scrollY: 0, viewportHeight: 1000, contentHeight: 5000, want: 4000},
		{name: "content shorter than the viewport cannot scroll", centerY: 300, scrollY: 0, viewportHeight: 1000, contentHeight: 600, want: 0},
		{name: "content exactly the viewport cannot scroll", centerY: 900, scrollY: 0, viewportHeight: 1000, contentHeight: 1000, want: 0},
		{name: "zero-size page", centerY: 0, scrollY: 0, viewportHeight: 0, contentHeight: 0, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetScrollY(tt.centerY, tt.scrollY, tt.viewportHeight, tt.contentHeight)
			if !floatsClose(got, tt.want, 0.001) {
				t.Errorf("targetScrollY(%v, %v, %v, %v) = %v, want %v", tt.centerY, tt.scrollY, tt.viewportHeight, tt.contentHeight, got, tt.want)
			}
		})
	}
}

func TestClampScrollY(t *testing.T) {
	tests := []struct {
		name           string
		y              float64
		viewportHeight float64
		contentHeight  float64
		want           float64
	}{
		{name: "inside the range", y: 1500, viewportHeight: 1000, contentHeight: 5000, want: 1500},
		{name: "negative", y: -40, viewportHeight: 1000, contentHeight: 5000, want: 0},
		{name: "past the end", y: 9000, viewportHeight: 1000, contentHeight: 5000, want: 4000},
		{name: "exactly the end", y: 4000, viewportHeight: 1000, contentHeight: 5000, want: 4000},
		{name: "content shorter than the viewport", y: 200, viewportHeight: 1000, contentHeight: 400, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampScrollY(tt.y, tt.viewportHeight, tt.contentHeight); !floatsClose(got, tt.want, 0.001) {
				t.Errorf("clampScrollY(%v, %v, %v) = %v, want %v", tt.y, tt.viewportHeight, tt.contentHeight, got, tt.want)
			}
		})
	}
}

// scrollState reads the page's scroll position and where the target element
// sits in the viewport.
const scrollState = `() => {
	const r = document.getElementById('target').getBoundingClientRect();
	return { scrollY: window.scrollY, top: r.top, bottom: r.bottom, viewportHeight: window.innerHeight };
}`

// TestScroller_EnsureElementVisible drives a real browser: an element far down
// a tall page must be scrolled into the viewport, and a second call must then
// find it visible and leave the page alone.
func TestScroller_EnsureElementVisible(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}
	binary, found := launcher.LookPath()
	if !found {
		t.Skip("no browser found")
	}

	browserLauncher := launcher.New().Bin(binary).Headless(true).NoSandbox(true).Leakless(false)
	controlURL, err := browserLauncher.Launch()
	if err != nil {
		t.Fatalf("Failed to launch browser: %v", err)
	}
	// Runs after the browser is closed below; removes its user-data dir.
	defer browserLauncher.Cleanup()
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		t.Fatalf("Failed to connect to browser: %v", err)
	}
	defer func() {
		// Ignore error: cleanup should not affect the test result
		_ = browser.Close()
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body style="margin:0">
			<div style="height:3000px"></div>
			<button id="target" style="display:block;height:40px">target</button>
			<div style="height:3000px"></div>
		</body></html>`)
	}))
	defer server.Close()

	page, err := browser.Page(proto.TargetCreateTarget{URL: server.URL})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	if err := page.WaitLoad(); err != nil {
		t.Fatalf("WaitLoad failed: %v", err)
	}
	element, err := page.Element("#target")
	if err != nil {
		t.Fatalf("Failed to find target: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scroller := NewScroller(page)
	margin := scroller.config.ScrollMargin

	scrolled, err := scroller.EnsureElementVisible(ctx, element)
	if err != nil {
		t.Fatalf("EnsureElementVisible failed: %v", err)
	}
	if !scrolled {
		t.Error("first call reported no scroll for an element 3000px down the page")
	}

	res, err := page.Eval(scrollState)
	if err != nil {
		t.Fatalf("Failed to read scroll state: %v", err)
	}
	scrollY := res.Value.Get("scrollY").Num()
	top, bottom := res.Value.Get("top").Num(), res.Value.Get("bottom").Num()
	viewportHeight := res.Value.Get("viewportHeight").Num()
	if scrollY <= 0 {
		t.Errorf("page did not scroll: scrollY = %v", scrollY)
	}
	if !inViewport(top, bottom, viewportHeight, margin) {
		t.Errorf("element not in view after scrolling: top=%v bottom=%v viewport=%v", top, bottom, viewportHeight)
	}

	// The page is now scrolled, which is where page-relative arithmetic on
	// viewport-relative quads went wrong.
	scrolled, err = scroller.EnsureElementVisible(ctx, element)
	if err != nil {
		t.Fatalf("second EnsureElementVisible failed: %v", err)
	}
	if scrolled {
		t.Error("second call scrolled although the element was already in view")
	}
	res, err = page.Eval(scrollState)
	if err != nil {
		t.Fatalf("Failed to read scroll state: %v", err)
	}
	if after := res.Value.Get("scrollY").Num(); !floatsClose(after, scrollY, 0.5) {
		t.Errorf("scroll position moved on the second call: %v -> %v", scrollY, after)
	}
}
