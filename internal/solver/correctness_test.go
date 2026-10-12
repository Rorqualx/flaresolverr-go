package solver

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestProxyID_Credentials(t *testing.T) {
	tests := []struct {
		name      string
		proxy     *types.Proxy
		want      string // exact value, when set
		sameAs    *types.Proxy
		differsTo *types.Proxy
	}{
		{name: "nil proxy", proxy: nil, want: "direct"},
		{name: "empty URL", proxy: &types.Proxy{}, want: "direct"},
		{name: "no credentials", proxy: &types.Proxy{URL: "http://gw.example:8080"}, want: "gw.example:8080"},
		{
			name:      "different usernames on one gateway are different egresses",
			proxy:     &types.Proxy{URL: "http://gw.example:8080", Username: "user-session-a"},
			differsTo: &types.Proxy{URL: "http://gw.example:8080", Username: "user-session-b"},
		},
		{
			name:      "username distinguishes from anonymous use of the same gateway",
			proxy:     &types.Proxy{URL: "http://gw.example:8080", Username: "user-session-a"},
			differsTo: &types.Proxy{URL: "http://gw.example:8080"},
		},
		{
			name:   "username in the URL equals username in the field",
			proxy:  &types.Proxy{URL: "http://user-session-a:secret@gw.example:8080"},
			sameAs: &types.Proxy{URL: "http://gw.example:8080", Username: "user-session-a", Password: "secret"},
		},
		{
			name:   "password does not change the egress",
			proxy:  &types.Proxy{URL: "http://gw.example:8080", Username: "u", Password: "one"},
			sameAs: &types.Proxy{URL: "http://gw.example:8080", Username: "u", Password: "two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := proxyID(tt.proxy)
			if tt.want != "" && got != tt.want {
				t.Errorf("proxyID() = %q, want %q", got, tt.want)
			}
			if tt.sameAs != nil && got != proxyID(tt.sameAs) {
				t.Errorf("proxyID() = %q, want it equal to %q", got, proxyID(tt.sameAs))
			}
			if tt.differsTo != nil && got == proxyID(tt.differsTo) {
				t.Errorf("proxyID() = %q for both proxies, want different identities", got)
			}
			if tt.proxy != nil && tt.proxy.Username != "" && containsSecret(got, tt.proxy.Username) {
				t.Errorf("proxyID() = %q exposes the proxy username", got)
			}
		})
	}
}

func containsSecret(s, secret string) bool {
	for i := 0; i+len(secret) <= len(s); i++ {
		if s[i:i+len(secret)] == secret {
			return true
		}
	}
	return false
}

func TestClearanceCacheDelete(t *testing.T) {
	cache := NewClearanceCache(time.Hour, 0)
	cookies := []*proto.NetworkCookie{{
		Name:    "cf_clearance",
		Value:   "clearance-value-long-enough-to-look-like-a-real-cookie-0123456789",
		Domain:  ".example.com",
		Path:    "/",
		Expires: proto.TimeSinceEpoch(float64(time.Now().Add(time.Hour).Unix())),
	}}

	cache.Put("example.com", "direct", "UA/1.0", cookies)
	cache.Put("example.com", "gw.example:8080", "UA/1.0", cookies)
	if cache.Get("example.com", "direct") == nil {
		t.Fatal("expected a cached entry after Put")
	}

	cache.Delete("example.com", "direct")
	if cache.Get("example.com", "direct") != nil {
		t.Error("entry still cached after Delete")
	}
	if cache.Get("example.com", "gw.example:8080") == nil {
		t.Error("Delete removed the entry of a different egress")
	}

	// Safe on a missing key, an empty domain and a nil cache
	cache.Delete("example.com", "direct")
	cache.Delete("", "direct")
	var none *ClearanceCache
	none.Delete("example.com", "direct")
}

func TestBypassProxyServer(t *testing.T) {
	tests := []struct {
		name         string
		proxy        *types.Proxy
		defaultProxy string
		want         string
		wantErr      bool
	}{
		{name: "no proxy anywhere", want: ""},
		{name: "request proxy", proxy: &types.Proxy{URL: "http://gw.example:8080"}, want: "http://gw.example:8080"},
		{name: "socks proxy keeps its scheme", proxy: &types.Proxy{URL: "socks5://gw.example:1080"}, want: "socks5://gw.example:1080"},
		{name: "falls back to configured default", defaultProxy: "http://default.example:3128", want: "http://default.example:3128"},
		{
			name:         "request proxy wins over default",
			proxy:        &types.Proxy{URL: "http://gw.example:8080"},
			defaultProxy: "http://default.example:3128",
			want:         "http://gw.example:8080",
		},
		{name: "credentials in field", proxy: &types.Proxy{URL: "http://gw.example:8080", Username: "u", Password: "p"}, wantErr: true},
		{name: "credentials in URL", proxy: &types.Proxy{URL: "http://u:p@gw.example:8080"}, wantErr: true},
		{name: "credentials in default", defaultProxy: "http://u:p@default.example:3128", wantErr: true},
		{name: "unparseable proxy", proxy: &types.Proxy{URL: "://nope"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bypassProxyServer(&SolveOptions{Proxy: tt.proxy}, tt.defaultProxy)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("bypassProxyServer() = %q, want an error (must never fall back to no proxy)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("bypassProxyServer() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("bypassProxyServer() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsBodylessHTTPError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "empty error response", err: errors.New("navigation failed: net::ERR_HTTP_RESPONSE_CODE_FAILURE"), want: true},
		{name: "wrapped", err: fmt.Errorf("navigate: %w", errors.New("navigation failed: net::ERR_HTTP_RESPONSE_CODE_FAILURE")), want: true},
		{name: "dns failure", err: errors.New("navigation failed: net::ERR_NAME_NOT_RESOLVED"), want: false},
		{name: "proxy failure", err: errors.New("navigation failed: net::ERR_PROXY_CONNECTION_FAILED"), want: false},
		{name: "timeout", err: errors.New("context deadline exceeded"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBodylessHTTPError(tt.err); got != tt.want {
				t.Errorf("isBodylessHTTPError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
