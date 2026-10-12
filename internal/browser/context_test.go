package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// cookieServer sets a long-lived cookie on /set and echoes received cookies on /show.
func cookieServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "owner", Value: r.URL.Query().Get("v"), Path: "/", MaxAge: 3600})
		_, _ = w.Write([]byte("set"))
	})
	mux.HandleFunc("/show", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cookies=[" + r.Header.Get("Cookie") + "]"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// fetchText loads url in a new page of b and returns the body text.
func fetchText(t *testing.T, b *rod.Browser, url string) string {
	t.Helper()
	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("create page: %v", err)
	}
	p := page.Timeout(20 * time.Second)
	if err := p.Navigate(url); err != nil {
		t.Fatalf("navigate %s: %v", url, err)
	}
	if err := p.WaitLoad(); err != nil {
		t.Fatalf("wait load: %v", err)
	}
	res, err := p.Eval(`() => document.body.innerText`)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return res.Value.Str()
}

func contextCount(t *testing.T, b *rod.Browser) int {
	t.Helper()
	res, err := proto.TargetGetBrowserContexts{}.Call(b.Timeout(10 * time.Second))
	if err != nil {
		t.Fatalf("list contexts: %v", err)
	}
	return len(res.BrowserContextIDs)
}

// TestIsolatedContextsDoNotShareCookies reproduces the cross-request leak: a
// cookie with an expiry set by one user of a browser must not be sent for, or
// visible to, the next user of the same browser.
func TestIsolatedContextsDoNotShareCookies(t *testing.T) {
	skipCI(t)
	pool := newTestPool(t)
	server := cookieServer(t)

	b, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer pool.Release(b)

	first, disposeFirst, err := NewIsolatedContext(b, "")
	if err != nil {
		t.Fatalf("NewIsolatedContext: %v", err)
	}
	fetchText(t, first, server.URL+"/set?v=caller-a")
	if got := fetchText(t, first, server.URL+"/show"); !strings.Contains(got, "owner=caller-a") {
		t.Fatalf("context lost its own cookie: %q", got)
	}

	second, disposeSecond, err := NewIsolatedContext(b, "")
	if err != nil {
		t.Fatalf("NewIsolatedContext: %v", err)
	}
	defer disposeSecond()
	if got := fetchText(t, second, server.URL+"/show"); strings.Contains(got, "caller-a") {
		t.Errorf("second context received the first context's cookie: %q", got)
	}

	// After the first context is disposed, a later context still starts clean.
	disposeFirst()
	disposeFirst() // must be safe to call twice
	third, disposeThird, err := NewIsolatedContext(b, "")
	if err != nil {
		t.Fatalf("NewIsolatedContext: %v", err)
	}
	defer disposeThird()
	if got := fetchText(t, third, server.URL+"/show"); strings.Contains(got, "caller-a") {
		t.Errorf("cookie survived disposal of its context: %q", got)
	}
}

// TestReleaseDisposesLeftoverContexts verifies the pool's backstop: a context
// whose owner never disposed it is removed when the browser is released.
func TestReleaseDisposesLeftoverContexts(t *testing.T) {
	skipCI(t)
	cfg := testConfig()
	cfg.BrowserPoolSize = 1 // the same browser is handed out again
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	server := cookieServer(t)

	b, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	leaked, _, err := NewIsolatedContext(b, "") // dispose deliberately not called
	if err != nil {
		t.Fatalf("NewIsolatedContext: %v", err)
	}
	fetchText(t, leaked, server.URL+"/set?v=caller-a")
	if got := contextCount(t, b); got != 1 {
		t.Fatalf("context count = %d before release, want 1", got)
	}
	pool.Release(b)

	again, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer pool.Release(again)
	if again != b {
		t.Fatal("expected the same browser from a one-browser pool")
	}
	if got := contextCount(t, again); got != 0 {
		t.Errorf("context count = %d after release, want 0", got)
	}
}
