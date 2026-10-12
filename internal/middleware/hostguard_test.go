package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// guarded runs one request through HostGuard and reports the status code and
// whether the wrapped handler was reached.
func guarded(t *testing.T, cfg HostGuardConfig, method, host, origin string) (status int, reached bool) {
	t.Helper()
	handler := HostGuard(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(method, "/v1", nil)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code, reached
}

func TestHostGuard_Host(t *testing.T) {
	ownHostname, _ := os.Hostname()

	tests := []struct {
		name    string
		allowed []string
		host    string
		want    bool
	}{
		// Accepted with no configuration
		{name: "loopback IPv4 with port", host: "127.0.0.1:8191", want: true},
		{name: "loopback IPv4 no port", host: "127.0.0.1", want: true},
		{name: "LAN IPv4", host: "192.168.50.185:8191", want: true},
		{name: "IPv6 loopback with port", host: "[::1]:8191", want: true},
		{name: "IPv6 loopback no port", host: "[::1]", want: true},
		{name: "IPv6 global with port", host: "[2001:db8::1]:8191", want: true},
		{name: "IPv6 link-local with zone", host: "[fe80::1%eth0]:8191", want: true},
		{name: "localhost", host: "localhost:8191", want: true},
		{name: "localhost mixed case", host: "LocalHost:8191", want: true},
		{name: "localhost trailing dot", host: "localhost.:8191", want: true},
		{name: "compose service name", host: "flaresolverr:8191", want: true},
		{name: "single label no port", host: "flaresolverr", want: true},
		{name: "container name with dash", host: "fs-agent-b:8191", want: true},
		{name: "this machine's hostname", host: ownHostname + ":8191", want: true},

		// Rejected without configuration: names an attacker could own
		{name: "attacker domain", host: "evil.example:8191", want: false},
		{name: "attacker domain no port", host: "evil.example", want: false},
		{name: "rebinding service style", host: "7f000001.c0a80001.rbndr.us:8191", want: false},
		{name: "subdomain of localhost", host: "foo.localhost:8191", want: false},
		{name: "dotted name that embeds an IP", host: "127.0.0.1.evil.example", want: false},
		{name: "missing host", host: "", want: false},
		{name: "only a port", host: ":8191", want: false},

		// ALLOWED_HOSTS
		{name: "listed name", allowed: []string{"solver.internal.example"}, host: "solver.internal.example:8191", want: true},
		{name: "listed name, other case and trailing dot", allowed: []string{"Solver.Internal.Example"}, host: "solver.internal.example.:443", want: true},
		{name: "listed with port in config", allowed: []string{"solver.internal.example:8191"}, host: "solver.internal.example:8191", want: true},
		{name: "unlisted sibling", allowed: []string{"solver.internal.example"}, host: "other.internal.example", want: false},
		{name: "listed name is not a suffix match", allowed: []string{"internal.example"}, host: "evil-internal.example", want: false},
		{name: "suffix entry matches subdomain", allowed: []string{".internal.example"}, host: "solver.internal.example:8191", want: true},
		{name: "suffix entry matches the domain itself", allowed: []string{".internal.example"}, host: "internal.example", want: true},
		{name: "suffix entry does not match lookalike", allowed: []string{".internal.example"}, host: "notinternal.example", want: false},
		{name: "lone dot entry is ignored", allowed: []string{"."}, host: "evil.example", want: false},
		{name: "wildcard disables the check", allowed: []string{"*"}, host: "evil.example:8191", want: true},
		{name: "wildcard allows a missing host", allowed: []string{"*"}, host: "", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := guarded(t, HostGuardConfig{AllowedHosts: tt.allowed}, http.MethodPost, tt.host, "")
			if reached != tt.want {
				t.Errorf("Host %q: reached handler = %v, want %v (status %d)", tt.host, reached, tt.want, status)
			}
			if !tt.want && status != http.StatusForbidden {
				t.Errorf("Host %q: status = %d, want 403", tt.host, status)
			}
		})
	}
}

func TestHostGuard_Origin(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		method  string
		origin  string
		want    bool
	}{
		{name: "no origin (non-browser client)", method: http.MethodPost, origin: "", want: true},
		{name: "cross-site POST", method: http.MethodPost, origin: "http://evil.example", want: false},
		{name: "cross-site preflight", method: http.MethodOptions, origin: "http://evil.example", want: false},
		{name: "cross-site GET", method: http.MethodGet, origin: "https://evil.example", want: false},
		{name: "opaque origin", method: http.MethodPost, origin: "null", want: false},
		{name: "same host is still a web page", method: http.MethodPost, origin: "http://127.0.0.1:8191", want: false},
		{name: "listed origin POST", allowed: []string{"https://app.example"}, method: http.MethodPost, origin: "https://app.example", want: true},
		{name: "listed origin preflight", allowed: []string{"https://app.example"}, method: http.MethodOptions, origin: "https://app.example", want: true},
		{name: "scheme must match", allowed: []string{"https://app.example"}, method: http.MethodPost, origin: "http://app.example", want: false},
		{name: "port must match", allowed: []string{"https://app.example"}, method: http.MethodPost, origin: "https://app.example:8443", want: false},
		{name: "prefix lookalike", allowed: []string{"https://app.example"}, method: http.MethodPost, origin: "https://app.example.evil.test", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := guarded(t, HostGuardConfig{AllowedOrigins: tt.allowed}, tt.method, "127.0.0.1:8191", tt.origin)
			if reached != tt.want {
				t.Errorf("Origin %q: reached handler = %v, want %v (status %d)", tt.origin, reached, tt.want, status)
			}
			if !tt.want && status != http.StatusForbidden {
				t.Errorf("Origin %q: status = %d, want 403", tt.origin, status)
			}
		})
	}
}

// TestHostGuard_RejectionNamesTheFix verifies an operator who is locked out is
// told exactly which setting lets them back in.
func TestHostGuard_RejectionNamesTheFix(t *testing.T) {
	handler := HostGuard(HostGuardConfig{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequest(http.MethodPost, "/v1", nil)
	req.Host = "solver.internal.example:8191"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if body := w.Body.String(); !strings.Contains(body, "ALLOWED_HOSTS=solver.internal.example") {
		t.Errorf("rejection does not name the fix: %s", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHostOnly(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"example.com:8191", "example.com"},
		{"127.0.0.1:8191", "127.0.0.1"},
		{"[::1]:8191", "::1"},
		{"[::1]", "::1"},
		{"::1", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"", ""},
		{":8191", ""},
		{" host:1 ", "host"},
	}
	for _, tt := range tests {
		if got := hostOnly(tt.in); got != tt.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", cidr, err)
		}
		out = append(out, prefix)
	}
	return out
}

func TestClientKey(t *testing.T) {
	proxies := func(t *testing.T) []netip.Prefix { return mustPrefixes(t, "10.0.0.0/8", "fd00::/8") }

	tests := []struct {
		name       string
		enabled    bool
		trusted    bool // use the trusted-proxy list
		remoteAddr string
		xff        []string
		xRealIP    string
		want       string
	}{
		// Headers off: only the TCP peer counts
		{name: "headers ignored when trust is off", remoteAddr: "203.0.113.7:5555", xff: []string{"1.2.3.4"}, xRealIP: "5.6.7.8", want: "203.0.113.7"},
		{name: "ipv4-mapped peer", remoteAddr: "[::ffff:203.0.113.7]:5555", want: "203.0.113.7"},
		{name: "ipv6 peer keyed by /64", remoteAddr: "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:5555", want: "2001:db8:1:2::/64"},
		{name: "ipv6 peers in one /64 share a key", remoteAddr: "[2001:db8:1:2::1]:5555", want: "2001:db8:1:2::/64"},
		{name: "ipv6 peer in another /64", remoteAddr: "[2001:db8:1:3::1]:5555", want: "2001:db8:1:3::/64"},
		{name: "unparsable peer falls back to raw value", remoteAddr: "not-an-address", want: "not-an-address"},

		// Legacy: trust on, no proxy list
		{name: "legacy takes leftmost entry", enabled: true, remoteAddr: "203.0.113.7:5555", xff: []string{"1.2.3.4, 10.0.0.1"}, want: "1.2.3.4"},
		{name: "legacy non-IP entry falls back to peer", enabled: true, remoteAddr: "203.0.113.7:5555", xff: []string{strings.Repeat("A", 4096)}, want: "203.0.113.7"},
		{name: "legacy X-Real-IP when no XFF", enabled: true, remoteAddr: "203.0.113.7:5555", xRealIP: "5.6.7.8", want: "5.6.7.8"},
		{name: "legacy non-IP X-Real-IP falls back", enabled: true, remoteAddr: "203.0.113.7:5555", xRealIP: "junk", want: "203.0.113.7"},
		{name: "legacy ipv6 entry keyed by /64", enabled: true, remoteAddr: "203.0.113.7:5555", xff: []string{"2001:db8:9:9::5"}, want: "2001:db8:9:9::/64"},

		// Trusted proxies configured
		{name: "untrusted peer cannot set the header", enabled: true, trusted: true, remoteAddr: "203.0.113.7:5555", xff: []string{"1.2.3.4"}, xRealIP: "5.6.7.8", want: "203.0.113.7"},
		{name: "trusted peer, single hop", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"198.51.100.9"}, want: "198.51.100.9"},
		{name: "client-prepended entries are ignored", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"1.1.1.1, 2.2.2.2, 198.51.100.9"}, want: "198.51.100.9"},
		{name: "skips trusted hops from the right", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"6.6.6.6, 198.51.100.9, 10.0.0.2, 10.0.0.3"}, want: "198.51.100.9"},
		{name: "multiple header lines are joined in order", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"6.6.6.6", "198.51.100.9, 10.0.0.2"}, want: "198.51.100.9"},
		{name: "all hops trusted uses the leftmost", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"10.0.0.9, 10.0.0.2"}, want: "10.0.0.9"},
		{name: "malformed hop falls back to peer", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"198.51.100.9, garbage"}, want: "10.0.0.1"},
		{name: "malformed entry left of the client is never reached", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"garbage, 198.51.100.9"}, want: "198.51.100.9"},
		{name: "hop with port", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{"198.51.100.9:4711"}, want: "198.51.100.9"},
		{name: "ipv6 client behind trusted proxy", enabled: true, trusted: true, remoteAddr: "[fd00::1]:5555", xff: []string{"2001:db8:5:6::77"}, want: "2001:db8:5:6::/64"},
		{name: "trusted peer, no XFF, X-Real-IP", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xRealIP: "198.51.100.9", want: "198.51.100.9"},
		{name: "trusted peer, no headers", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", want: "10.0.0.1"},
		{name: "empty XFF entries are skipped", enabled: true, trusted: true, remoteAddr: "10.0.0.1:5555", xff: []string{" , 198.51.100.9, "}, want: "198.51.100.9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trust := ProxyTrust{Enabled: tt.enabled}
			if tt.trusted {
				trust.Proxies = proxies(t)
			}

			req := httptest.NewRequest(http.MethodPost, "/v1", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, value := range tt.xff {
				req.Header.Add("X-Forwarded-For", value)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			if got := clientKey(req, trust); got != tt.want {
				t.Errorf("clientKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRateLimit_SpoofedForwardedForDoesNotMintKeys verifies that with a trusted
// proxy list, a direct client rotating X-Forwarded-For stays on one bucket.
func TestRateLimit_SpoofedForwardedForDoesNotMintKeys(t *testing.T) {
	limiter := NewRateLimitMiddleware(3, ProxyTrust{Enabled: true, Proxies: mustPrefixes(t, "10.0.0.0/8")})
	defer limiter.Close()

	handler := limiter.Handler()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1", nil)
		req.RemoteAddr = "203.0.113.7:5555"
		req.Header.Set("X-Forwarded-For", netip.AddrFrom4([4]byte{1, 2, 3, byte(i)}).String())
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("%d of 10 requests allowed with a rotating X-Forwarded-For, want 3 (the limit)", allowed)
	}
}

// TestRateLimiter_LegacyConstructor keeps the boolean constructor working.
func TestRateLimiter_LegacyConstructor(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute, true)
	defer rl.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1", nil)
	req.RemoteAddr = "203.0.113.7:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := rl.GetClientIP(req); got != "1.2.3.4" {
		t.Errorf("GetClientIP() = %q, want 1.2.3.4 (legacy trust-any-peer behavior)", got)
	}
}
