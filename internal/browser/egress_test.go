package browser

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/guardproxy"
)

// guardedPool returns a pool with no browsers whose egress guard is running.
func guardedPool(t *testing.T, cfg *config.Config) *Pool {
	t.Helper()
	pool := &Pool{config: cfg}
	if err := pool.startEgressGuard(guardproxy.Options{}); err != nil {
		t.Fatalf("startEgressGuard: %v", err)
	}
	t.Cleanup(pool.stopEgressGuard)
	return pool
}

func TestEgressGuardDisabledByDefault(t *testing.T) {
	pool := &Pool{config: &config.Config{}}
	if pool.EgressGuardEnabled() {
		t.Error("EgressGuardEnabled() = true on a pool without a guard")
	}
	if (*Pool)(nil).EgressGuardEnabled() {
		t.Error("EgressGuardEnabled() = true on a nil pool")
	}
	if _, ok := pool.EgressGuardStats(); ok {
		t.Error("EgressGuardStats() reported a guard on a pool without one")
	}
	if _, err := pool.GuardRoute(nil); err == nil {
		t.Error("GuardRoute() succeeded without a guard")
	}
	pool.stopEgressGuard() // must be a no-op

	// Without the guard the launcher is exactly what it was before.
	flags := pool.createLauncher("").FormatArgs()
	for _, flag := range flags {
		if strings.HasPrefix(flag, "--proxy-server") || strings.HasPrefix(flag, "--proxy-bypass-list") {
			t.Errorf("launcher has %q with the guard disabled and no proxy", flag)
		}
	}
}

func TestGuardRoute(t *testing.T) {
	pool := guardedPool(t, &config.Config{})

	route, err := pool.GuardRoute(nil)
	if err != nil {
		t.Fatalf("GuardRoute(nil): %v", err)
	}
	defer route.Release()

	host, _, err := net.SplitHostPort(strings.TrimPrefix(route.ProxyServer, "http://"))
	if err != nil || host != "127.0.0.1" {
		t.Errorf("ProxyServer = %q, want http://127.0.0.1:<port>", route.ProxyServer)
	}
	if route.BypassList != "<-loopback>" {
		t.Errorf("BypassList = %q, want <-loopback>", route.BypassList)
	}
	if route.ProxyServer != pool.defaultRoute.ProxyServer {
		t.Errorf("default route %q differs from the pool's %q", route.ProxyServer, pool.defaultRoute.ProxyServer)
	}

	route.Release()
	route.Release() // safe to repeat
	(*EgressRoute)(nil).Release()

	stats, ok := pool.EgressGuardStats()
	if !ok || stats.Listeners != 1 {
		t.Errorf("EgressGuardStats() = %+v, %v; want one listener", stats, ok)
	}
}

func TestGuardedLauncherFlags(t *testing.T) {
	pool := guardedPool(t, &config.Config{Headless: true})

	flags := pool.createLauncher(pool.defaultRoute.ProxyServer).FormatArgs()
	want := map[string]bool{
		"--proxy-server=" + pool.defaultRoute.ProxyServer: false,
		"--proxy-bypass-list=<-loopback>":                 false,
	}
	for _, flag := range flags {
		if _, ok := want[flag]; ok {
			want[flag] = true
		}
	}
	for flag, found := range want {
		if !found {
			t.Errorf("launcher is missing %q; flags: %v", flag, flags)
		}
	}
}

// loadText navigates a new page of b to url and returns what it rendered. A
// refused connection is an error page or a navigation error; both are fine,
// the caller only checks what did not happen.
func loadText(t *testing.T, b *rod.Browser, url string) string {
	t.Helper()
	page, err := b.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("create page: %v", err)
	}
	defer page.Close()

	p := page.Timeout(20 * time.Second)
	if err := p.Navigate(url); err != nil {
		return "navigation error: " + err.Error()
	}
	if err := p.WaitLoad(); err != nil {
		return "load error: " + err.Error()
	}
	res, err := p.Eval(`() => document.body ? document.body.innerText : ""`)
	if err != nil {
		return "eval error: " + err.Error()
	}
	return res.Value.Str()
}

// TestEgressGuardCoversEveryBrowser launches each kind of browser the pool
// can produce with the guard enabled and checks that none of them can reach a
// server on this machine: not by address, not by name, and not from a page
// that is already loaded.
func TestEgressGuardCoversEveryBrowser(t *testing.T) {
	skipCI(t)

	const marker = "INTERNAL-SECRET-MARKER"
	var hits atomic.Int64
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte(marker))
	}))
	defer internal.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	cfg.EgressGuard = true
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	pooled, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(pooled)

	isolated, dispose, err := pool.NewEgressContext(pooled, nil)
	if err != nil {
		t.Fatalf("NewEgressContext: %v", err)
	}
	defer dispose()

	withOptions, err := pool.SpawnWithOptions(ctx, LaunchOptions{WindowSize: "1280,720"})
	if err != nil {
		t.Fatalf("SpawnWithOptions: %v", err)
	}
	defer pool.CleanupBrowser(withOptions)

	sessionHost, err := pool.SpawnWithProxy(ctx, cfg.ProxyURL)
	if err != nil {
		t.Fatalf("SpawnWithProxy: %v", err)
	}
	defer pool.CleanupBrowser(sessionHost)

	browsers := []struct {
		name    string
		browser *rod.Browser
	}{
		{name: "pooled browser", browser: pooled},
		{name: "isolated context", browser: isolated},
		{name: "browserFlags browser", browser: withOptions},
		{name: "session browser", browser: sessionHost},
	}
	targets := []string{
		"http://127.0.0.1:" + port + "/",
		"http://localhost:" + port + "/",
		"http://[::1]:" + port + "/",
		"http://0177.0.0.1:" + port + "/",
		"http://2130706433:" + port + "/",
	}

	for _, b := range browsers {
		t.Run(b.name, func(t *testing.T) {
			for _, target := range targets {
				if got := loadText(t, b.browser, target); strings.Contains(got, marker) {
					t.Errorf("%s was loaded: %q", target, got)
				}
			}

			// From a loaded page: fetch, an image and a WebSocket.
			page, err := b.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
			if err != nil {
				t.Fatalf("create page: %v", err)
			}
			defer page.Close()
			_, err = page.Timeout(20*time.Second).Eval(`(port) => {
				const base = "127.0.0.1:" + port;
				const attempts = [
					fetch("http://" + base + "/fetch", {mode: "no-cors"}).catch(() => null),
					new Promise((done) => {
						const img = new Image();
						img.onload = img.onerror = () => done(null);
						img.src = "http://" + base + "/img";
					}),
					new Promise((done) => {
						const ws = new WebSocket("ws://" + base + "/ws");
						ws.onopen = ws.onerror = ws.onclose = () => done(null);
					}),
				];
				return Promise.all(attempts).then(() => "done");
			}`, port)
			if err != nil {
				t.Fatalf("subresource probe: %v", err)
			}
		})
	}

	if got := hits.Load(); got != 0 {
		t.Errorf("the server on this machine received %d requests with the guard enabled, want 0", got)
	}
	stats, ok := pool.EgressGuardStats()
	if !ok {
		t.Fatal("EgressGuardStats() reported no guard")
	}
	if stats.Totals.Blocked < int64(len(browsers)*len(targets)) {
		t.Errorf("guard blocked %d destinations, want at least %d", stats.Totals.Blocked, len(browsers)*len(targets))
	}
}

// testResolver answers every lookup with one address.
type testResolver struct {
	address net.IP
}

func (r testResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return []net.IP{r.address}, nil
}

// TestEgressGuardForwardsAllowedDestinations is the other half: with a guard
// that is told the test server is a public host, a real browser loads it
// through the guard, and the server sees the request a direct connection
// would have carried.
func TestEgressGuardForwardsAllowedDestinations(t *testing.T) {
	skipCI(t)

	headers := make(chan http.Header, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case headers <- r.Header.Clone():
		default:
		}
		_, _ = w.Write([]byte("<html><body>reached " + r.Host + "</body></html>"))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	cfg.EgressGuard = true
	pool, err := newPool(cfg, guardproxy.Options{
		Resolver:   testResolver{address: net.ParseIP("127.0.0.1")},
		ValidateIP: func(net.IP) error { return nil },
	})
	if err != nil {
		t.Fatalf("newPool: %v", err)
	}
	defer pool.Close()

	pooled, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(pooled)
	isolated, dispose, err := pool.NewEgressContext(pooled, nil)
	if err != nil {
		t.Fatalf("NewEgressContext: %v", err)
	}
	defer dispose()

	target := "http://guarded.test:" + port + "/"
	if got := loadText(t, isolated, target); !strings.Contains(got, "reached guarded.test:"+port) {
		t.Fatalf("page through the guard = %q, want the test server's page", got)
	}

	select {
	case got := <-headers:
		for _, name := range []string{"Proxy-Connection", "Proxy-Authorization", "Via", "X-Forwarded-For", "Forwarded"} {
			if got.Get(name) != "" {
				t.Errorf("the destination received %s: %q", name, got.Get(name))
			}
		}
		if got.Get("Connection") != "keep-alive" {
			t.Errorf("Connection = %q, want keep-alive as on a direct connection", got.Get("Connection"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the test server received no request")
	}

	stats, _ := pool.EgressGuardStats()
	if stats.Totals.Requests == 0 || stats.Totals.Blocked != 0 {
		t.Errorf("guard stats = %+v, want forwarded requests and nothing blocked", stats.Totals)
	}
}
