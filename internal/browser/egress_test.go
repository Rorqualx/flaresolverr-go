package browser

import (
	"context"
	"errors"
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
	"github.com/Rorqualx/flaresolverr-go/internal/types"
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
	if route.UpstreamAuthFailures() != 0 || (*EgressRoute)(nil).UpstreamAuthFailures() != 0 {
		t.Error("a direct or nil route reports upstream auth failures")
	}

	route.Release()
	route.Release() // safe to repeat
	(*EgressRoute)(nil).Release()

	stats, ok := pool.EgressGuardStats()
	if !ok || stats.Listeners != 1 {
		t.Errorf("EgressGuardStats() = %+v, %v; want one listener", stats, ok)
	}
}

// Fixture credentials for the upstream-proxy tests; not secrets.
const (
	testProxyUser = "route-user"
	testProxyWord = "r0ute-w0rd-4K"
)

func TestGuardRoute_Upstreams(t *testing.T) {
	pool := guardedPool(t, &config.Config{})
	listeners := func() int {
		stats, _ := pool.EgressGuardStats()
		return stats.Listeners
	}

	proxy := &types.Proxy{URL: "http://gw.example:8080", Username: testProxyUser, Password: testProxyWord}
	first, err := pool.GuardRoute(proxy)
	if err != nil {
		t.Fatalf("GuardRoute: %v", err)
	}
	second, err := pool.GuardRoute(&types.Proxy{URL: proxy.URL, Username: testProxyUser, Password: testProxyWord})
	if err != nil {
		t.Fatalf("GuardRoute: %v", err)
	}
	embedded, err := pool.GuardRoute(&types.Proxy{URL: "socks5://" + testProxyUser + ":" + testProxyWord + "@socks.example:1080"})
	if err != nil {
		t.Fatalf("GuardRoute: %v", err)
	}

	if first.ProxyServer == pool.defaultRoute.ProxyServer {
		t.Error("a request proxy was routed to the direct listener")
	}
	if first.ProxyServer != second.ProxyServer {
		t.Error("the same proxy and credentials got two listeners")
	}
	if embedded.ProxyServer == first.ProxyServer {
		t.Error("two different proxies share a listener")
	}
	for _, route := range []*EgressRoute{first, second, embedded} {
		// What Chrome is given: a loopback address and nothing else.
		host, _, err := net.SplitHostPort(strings.TrimPrefix(route.ProxyServer, "http://"))
		if err != nil || host != "127.0.0.1" {
			t.Errorf("ProxyServer = %q, want http://127.0.0.1:<port>", route.ProxyServer)
		}
		for _, secret := range []string{testProxyUser, testProxyWord, "gw.example", "socks.example"} {
			if strings.Contains(route.ProxyServer, secret) {
				t.Errorf("ProxyServer %q contains %q", route.ProxyServer, secret)
			}
		}
	}
	if got := listeners(); got != 3 {
		t.Errorf("listeners = %d, want direct + 2 upstreams", got)
	}

	first.Release()
	if got := listeners(); got != 3 {
		t.Errorf("listeners = %d after releasing one of two routes, want 3", got)
	}
	second.Release()
	embedded.Release()
	if got := listeners(); got != 1 {
		t.Errorf("listeners = %d after releasing every route, want 1", got)
	}
}

func TestGuardRoute_DefaultProxy(t *testing.T) {
	pool := guardedPool(t, &config.Config{
		ProxyURL:      "http://operator-proxy:3128",
		ProxyUsername: testProxyUser,
		ProxyPassword: testProxyWord,
	})

	// PROXY_URL stands behind the default route: pooled browsers, the session
	// browser and contexts without a proxy of their own all use it.
	stats, _ := pool.EgressGuardStats()
	if stats.Listeners != 2 {
		t.Fatalf("listeners = %d, want the direct one and PROXY_URL's", stats.Listeners)
	}
	route, err := pool.GuardRoute(nil)
	if err != nil {
		t.Fatalf("GuardRoute(nil): %v", err)
	}
	defer route.Release()
	if route.ProxyServer != pool.defaultRoute.ProxyServer {
		t.Errorf("GuardRoute(nil) = %q, want the default route %q", route.ProxyServer, pool.defaultRoute.ProxyServer)
	}
	if strings.Contains(route.ProxyServer, "operator-proxy") || strings.Contains(route.ProxyServer, testProxyWord) {
		t.Errorf("ProxyServer %q exposes the upstream", route.ProxyServer)
	}

	// The launcher gets the listener, never PROXY_URL itself.
	for _, flag := range pool.createLauncher(route.ProxyServer).FormatArgs() {
		if strings.Contains(flag, "operator-proxy") || strings.Contains(flag, testProxyWord) {
			t.Errorf("launcher flag %q exposes the upstream", flag)
		}
	}
}

func TestGuardRejectsUnsupportedProxies(t *testing.T) {
	pool := guardedPool(t, &config.Config{})

	tests := []struct {
		name    string
		proxy   *types.Proxy
		wantErr bool
	}{
		{name: "nil", proxy: nil},
		{name: "empty", proxy: &types.Proxy{}},
		{name: "http", proxy: &types.Proxy{URL: "http://gw.example:8080"}},
		{name: "https", proxy: &types.Proxy{URL: "https://gw.example"}},
		{name: "socks5", proxy: &types.Proxy{URL: "socks5://gw.example:1080"}},
		{name: "socks4", proxy: &types.Proxy{URL: "socks4://gw.example:1080"}, wantErr: true},
		{name: "socks4 with credentials", proxy: &types.Proxy{URL: "socks4://gw.example:1080", Username: testProxyUser, Password: testProxyWord}, wantErr: true},
		{name: "no scheme", proxy: &types.Proxy{URL: "gw.example:8080"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pool.CheckGuardProxy(tt.proxy)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckGuardProxy() = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, guardproxy.ErrUnsupportedUpstream) {
				t.Errorf("error %v does not wrap ErrUnsupportedUpstream", err)
			}
			if strings.Contains(err.Error(), testProxyWord) {
				t.Errorf("error %q contains the password", err)
			}
			if _, routeErr := pool.GuardRoute(tt.proxy); routeErr == nil {
				t.Error("GuardRoute() accepted a proxy CheckGuardProxy refused")
			}
		})
	}

	// A socks4 PROXY_URL stops the server at startup instead of silently
	// leaving the guard out of the path.
	socks4 := &Pool{config: &config.Config{ProxyURL: "socks4://operator-proxy:1080"}}
	err := socks4.startEgressGuard(guardproxy.Options{})
	if err == nil {
		socks4.stopEgressGuard()
		t.Fatal("startEgressGuard() accepted a socks4 PROXY_URL")
	}
	if !strings.Contains(err.Error(), "socks4") || !strings.Contains(err.Error(), "PROXY_URL") {
		t.Errorf("error %q does not say what is wrong", err)
	}
}

func TestOperatorProxyURLs(t *testing.T) {
	cfg := &config.Config{
		ProxyURL: "http://default-proxy:3128",
		ProxyList: "http://a.example:8080, socks5://" + testProxyUser + ":" + testProxyWord + "@b.example:1080\n" +
			"# a comment\n" +
			"c.example:3128\n" +
			"://broken",
	}
	got := operatorProxyURLs(cfg)
	want := []string{
		"http://default-proxy:3128",
		"http://a.example:8080",
		"socks5://b.example:1080", // credentials split out, as the solver does
		"http://c.example:3128",   // default scheme
	}
	if len(got) != len(want) {
		t.Errorf("operatorProxyURLs() = %v, want %v", got, want)
	}
	for _, url := range want {
		if !got[url] {
			t.Errorf("operatorProxyURLs() is missing %q: %v", url, got)
		}
	}
	if len(operatorProxyURLs(&config.Config{})) != 0 {
		t.Error("operatorProxyURLs() is not empty without configuration")
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

// authProxy is an upstream HTTP proxy that demands credentials and answers
// plain requests itself, naming the host it was asked for.
type authProxy struct {
	requests atomic.Int64
	accepted atomic.Int64
}

func (p *authProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	user, word, ok := parseProxyBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok || user != testProxyUser || word != testProxyWord {
		w.Header().Set("Proxy-Authenticate", `Basic realm="upstream"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	p.accepted.Add(1)
	_, _ = w.Write([]byte("<html><body>via upstream: " + r.Host + "</body></html>"))
}

// parseProxyBasicAuth decodes a "Basic ..." Proxy-Authorization value.
func parseProxyBasicAuth(header string) (user, word string, ok bool) {
	request := &http.Request{Header: http.Header{"Authorization": []string{header}}}
	return request.BasicAuth()
}

// TestEgressGuardChainsToAuthenticatedProxy drives a real browser context
// through the guard to an upstream proxy that requires credentials. Nothing
// is installed on the page: the guard authenticates, and Chrome is only ever
// given a loopback address.
func TestEgressGuardChainsToAuthenticatedProxy(t *testing.T) {
	skipCI(t)

	upstream := &authProxy{}
	server := httptest.NewServer(upstream)
	defer server.Close()

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	cfg.EgressGuard = true
	cfg.AllowLocalProxies = true // the fake upstream is on loopback
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	pooled, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(pooled)

	t.Run("right credentials", func(t *testing.T) {
		proxy := &types.Proxy{URL: server.URL, Username: testProxyUser, Password: testProxyWord}
		isolated, dispose, err := pool.NewEgressContext(pooled, proxy)
		if err != nil {
			t.Fatalf("NewEgressContext: %v", err)
		}
		defer dispose()

		got := loadText(t, isolated, "http://chained-target.test/")
		if !strings.Contains(got, "via upstream: chained-target.test") {
			t.Fatalf("page = %q, want the upstream proxy's answer", got)
		}
		if upstream.accepted.Load() == 0 {
			t.Error("the upstream proxy accepted no request")
		}
	})

	t.Run("wrong credentials", func(t *testing.T) {
		proxy := &types.Proxy{URL: server.URL, Username: testProxyUser, Password: "wr0ng-w0rd-1X"}
		route, err := pool.GuardRoute(proxy)
		if err != nil {
			t.Fatalf("GuardRoute: %v", err)
		}
		defer route.Release()

		isolated, dispose, err := pool.NewEgressContext(pooled, proxy)
		if err != nil {
			t.Fatalf("NewEgressContext: %v", err)
		}
		defer dispose()

		before := upstream.accepted.Load()
		got := loadText(t, isolated, "http://chained-target.test/")
		if strings.Contains(got, "via upstream") {
			t.Fatalf("page = %q: the request got through with wrong credentials", got)
		}
		if strings.Contains(got, "wr0ng-w0rd-1X") || strings.Contains(got, testProxyUser) {
			t.Errorf("page %q contains the credentials", got)
		}
		if upstream.accepted.Load() != before {
			t.Error("the upstream proxy accepted a request with wrong credentials")
		}
		if route.UpstreamAuthFailures() == 0 {
			t.Error("the route did not record the upstream's refusal")
		}
	})

	// With both contexts disposed only the direct listener is left.
	waitForListeners(t, pool, 1)
}

// waitForListeners waits for the guard to be down to want listeners.
func waitForListeners(t *testing.T, pool *Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stats, _ := pool.EgressGuardStats()
		if stats.Listeners == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard has %d listeners, want %d", stats.Listeners, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
