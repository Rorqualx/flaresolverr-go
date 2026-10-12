package solver

import (
	"context"
	"strings"
	"testing"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Fixture credentials; not secrets.
const (
	guardTestUser = "bypass-user"
	guardTestWord = "byp4ss-w0rd-6T"
)

// emptyPool returns a pool with no browsers, which is all these tests need:
// they only look at how traffic would be routed.
func emptyPool(t *testing.T, cfg *config.Config) *browser.Pool {
	t.Helper()
	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return pool
}

func TestBypassProxyArgs(t *testing.T) {
	authenticated := &types.Proxy{URL: "http://gw.example:8080", Username: guardTestUser, Password: guardTestWord}

	tests := []struct {
		name     string
		guard    bool
		proxyURL string // PROXY_URL
		proxy    *types.Proxy
		wantErr  bool
		check    func(t *testing.T, args []string)
	}{
		{
			name: "guard off, no proxy",
			check: func(t *testing.T, args []string) {
				if len(args) != 0 {
					t.Errorf("args = %v, want none", args)
				}
			},
		},
		{
			name:  "guard off, request proxy",
			proxy: &types.Proxy{URL: "http://gw.example:8080"},
			check: func(t *testing.T, args []string) {
				if len(args) != 1 || args[0] != "--proxy-server=http://gw.example:8080" {
					t.Errorf("args = %v, want only the proxy itself, as before", args)
				}
			},
		},
		{
			name:     "guard off, default proxy",
			proxyURL: "http://default.example:3128",
			check: func(t *testing.T, args []string) {
				if len(args) != 1 || args[0] != "--proxy-server=http://default.example:3128" {
					t.Errorf("args = %v, want only PROXY_URL, as before", args)
				}
			},
		},
		{name: "guard off, authenticated proxy is still refused", proxy: authenticated, wantErr: true},
		{
			name:  "guard on, no proxy",
			guard: true,
			check: checkGuardArgs,
		},
		{
			name:  "guard on, request proxy",
			guard: true,
			proxy: &types.Proxy{URL: "socks5://gw.example:1080"},
			check: checkGuardArgs,
		},
		{
			// The bypass drives Chrome without CDP and so could never answer a
			// proxy challenge. With the guard there is none to answer.
			name:  "guard on, authenticated proxy is allowed",
			guard: true,
			proxy: authenticated,
			check: checkGuardArgs,
		},
		{
			name:     "guard on, default proxy",
			guard:    true,
			proxyURL: "http://default.example:3128",
			check:    checkGuardArgs,
		},
		{name: "guard on, socks4 proxy", guard: true, proxy: &types.Proxy{URL: "socks4://gw.example:1080"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := emptyPool(t, &config.Config{EgressGuard: tt.guard, ProxyURL: tt.proxyURL})
			s := &Solver{pool: pool}

			args, release, err := s.bypassProxyArgs(&SolveOptions{Proxy: tt.proxy})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("bypassProxyArgs() = %v, want an error (must never fall back to no proxy)", args)
				}
				if strings.Contains(err.Error(), guardTestWord) {
					t.Errorf("error %q contains the password", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("bypassProxyArgs() error = %v", err)
			}
			tt.check(t, args)

			if tt.guard {
				stats, _ := pool.EgressGuardStats()
				held := stats.Listeners
				release()
				release() // must be safe to repeat
				stats, _ = pool.EgressGuardStats()
				if tt.proxy != nil && stats.Listeners != held-1 {
					t.Errorf("listeners = %d after release, want %d: the request's listener was not closed", stats.Listeners, held-1)
				}
				return
			}
			release()
		})
	}
}

// checkGuardArgs asserts the bypass was pointed at a guard listener: a
// loopback proxy with loopback bypass disabled and nothing else.
func checkGuardArgs(t *testing.T, args []string) {
	t.Helper()
	if len(args) != 2 {
		t.Fatalf("args = %v, want --proxy-server and --proxy-bypass-list", args)
	}
	if !strings.HasPrefix(args[0], "--proxy-server=http://127.0.0.1:") {
		t.Errorf("args[0] = %q, want a loopback guard listener", args[0])
	}
	if args[1] != "--proxy-bypass-list=<-loopback>" {
		t.Errorf("args[1] = %q, want --proxy-bypass-list=<-loopback>", args[1])
	}
	for _, arg := range args {
		for _, secret := range []string{guardTestUser, guardTestWord, "gw.example", "default.example"} {
			if strings.Contains(arg, secret) {
				t.Errorf("argument %q exposes %q on the command line", arg, secret)
			}
		}
	}
}

func TestSetupProxyAuth_SkippedWithGuard(t *testing.T) {
	pool := emptyPool(t, &config.Config{EgressGuard: true})
	s := &Solver{pool: pool}

	// A nil page proves nothing is installed on it: the guard authenticates
	// to the proxy, so no Fetch domain is enabled for proxy authentication.
	cleanup, err := s.setupProxyAuth(context.Background(), nil, &types.Proxy{
		URL: "http://gw.example:8080", Username: guardTestUser, Password: guardTestWord,
	})
	if err != nil {
		t.Fatalf("setupProxyAuth() error = %v", err)
	}
	cleanup()
}
