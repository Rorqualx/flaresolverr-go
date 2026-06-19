package solver

import (
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func clearanceCookies() []*proto.NetworkCookie {
	return []*proto.NetworkCookie{
		{Name: "cf_clearance", Value: "abc123", Domain: ".filecrypt.cc", Path: "/", Secure: true, HTTPOnly: true},
		{Name: "cf_bm", Value: "bm456", Domain: ".filecrypt.cc", Path: "/"},
		{Name: "sessionid", Value: "irrelevant", Domain: ".filecrypt.cc", Path: "/"},
	}
}

func TestRegistrableDomain(t *testing.T) {
	tests := []struct{ url, want string }{
		{"https://filecrypt.cc/Container/ABC.html", "filecrypt.cc"},
		{"https://www.filecrypt.cc/", "filecrypt.cc"},
		{"https://a.b.example.co.uk/x", "example.co.uk"},
		{"not a url", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := registrableDomain(tt.url); got != tt.want {
			t.Errorf("registrableDomain(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestProxyID(t *testing.T) {
	if got := proxyID(nil); got != "direct" {
		t.Errorf("proxyID(nil) = %q, want direct", got)
	}
	if got := proxyID(&types.Proxy{}); got != "direct" {
		t.Errorf("proxyID(empty) = %q, want direct", got)
	}
	if got := proxyID(&types.Proxy{URL: "http://10.0.0.1:8080"}); got != "10.0.0.1:8080" {
		t.Errorf("proxyID(proxy) = %q, want 10.0.0.1:8080", got)
	}
}

func TestClearanceCache_PutGet(t *testing.T) {
	c := NewClearanceCache(25*time.Minute, 0)
	c.Put("filecrypt.cc", "direct", "UA/1.0", clearanceCookies())

	e := c.Get("filecrypt.cc", "direct")
	if e == nil {
		t.Fatal("expected cache hit")
	}
	if e.userAgent != "UA/1.0" {
		t.Errorf("userAgent = %q", e.userAgent)
	}
	// Only Cloudflare cookies are carried forward (cf_clearance + cf_bm, not sessionid).
	names := map[string]bool{}
	for _, ck := range e.cookies {
		names[ck.Name] = true
	}
	if !names["cf_clearance"] || !names["cf_bm"] {
		t.Errorf("expected cf_clearance and cf_bm, got %v", names)
	}
	if names["sessionid"] {
		t.Error("non-CF cookie sessionid should not be cached")
	}
}

func TestClearanceCache_KeyIsolation(t *testing.T) {
	c := NewClearanceCache(25*time.Minute, 0)
	c.Put("filecrypt.cc", "proxyA", "UA/1.0", clearanceCookies())

	// Different egress must not reuse another egress's clearance (IP-bound).
	if c.Get("filecrypt.cc", "proxyB") != nil {
		t.Error("clearance leaked across egress identities")
	}
	if c.Get("other.com", "proxyA") != nil {
		t.Error("clearance leaked across domains")
	}
	if c.Get("filecrypt.cc", "proxyA") == nil {
		t.Error("expected hit for matching domain+egress")
	}
}

func TestClearanceCache_NoClearanceCookie(t *testing.T) {
	c := NewClearanceCache(25*time.Minute, 0)
	// No cf_clearance present → must not cache (avoids polluting on non-CF solves).
	c.Put("example.com", "direct", "UA/1.0", []*proto.NetworkCookie{
		{Name: "sessionid", Value: "x", Domain: "example.com", Path: "/"},
	})
	if c.Get("example.com", "direct") != nil {
		t.Error("cached an entry with no cf_clearance")
	}
}

func TestClearanceCache_Expiry(t *testing.T) {
	c := NewClearanceCache(25*time.Minute, 0)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	c.Put("filecrypt.cc", "direct", "UA/1.0", clearanceCookies())

	if c.Get("filecrypt.cc", "direct") == nil {
		t.Fatal("expected hit before expiry")
	}
	// Advance past the TTL ceiling.
	c.now = func() time.Time { return base.Add(26 * time.Minute) }
	if c.Get("filecrypt.cc", "direct") != nil {
		t.Error("expected miss after TTL expiry")
	}
}

func TestClearanceCache_HonorsShorterCookieExpiry(t *testing.T) {
	c := NewClearanceCache(25*time.Minute, 0)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	// Cookie expires in 5 min, shorter than the 25 min TTL ceiling.
	cookies := []*proto.NetworkCookie{
		{Name: "cf_clearance", Value: "v", Domain: ".x.com", Path: "/", Expires: proto.TimeSinceEpoch(base.Add(5 * time.Minute).Unix())},
	}
	c.Put("x.com", "direct", "UA/1.0", cookies)

	c.now = func() time.Time { return base.Add(6 * time.Minute) }
	if c.Get("x.com", "direct") != nil {
		t.Error("entry should have expired with the cookie at 5 min, not the 25 min ceiling")
	}
}

func TestClearanceCache_Eviction(t *testing.T) {
	c := NewClearanceCache(25*time.Minute, 2)
	c.Put("a.com", "direct", "UA", clearanceCookies())
	c.Put("b.com", "direct", "UA", clearanceCookies())
	c.Put("c.com", "direct", "UA", clearanceCookies()) // exceeds max=2

	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	if n > 2 {
		t.Errorf("cache exceeded max: %d entries", n)
	}
}
