package solver

import (
	"testing"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestParseEgressStrategy(t *testing.T) {
	tests := []struct {
		in   string
		want EgressStrategy
	}{
		{"sticky-domain", EgressStickyDomain},
		{"round-robin", EgressRoundRobin},
		{"per-request", EgressPerRequest},
		{"  ROUND-ROBIN ", EgressRoundRobin},
		{"", EgressStickyDomain},
		{"garbage", EgressStickyDomain},
	}
	for _, tt := range tests {
		if got := ParseEgressStrategy(tt.in); got != tt.want {
			t.Errorf("ParseEgressStrategy(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseProxyList(t *testing.T) {
	raw := `
		http://user:pass@10.0.0.1:8080,
		socks5://10.0.0.2:1080
		# a comment
		10.0.0.3:3128
	`
	proxies := ParseProxyList(raw)
	if len(proxies) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(proxies))
	}
	// Credentials split out of the URL; scheme defaulted for the bare host:port.
	if proxies[0].URL != "http://10.0.0.1:8080" || proxies[0].Username != "user" || proxies[0].Password != "pass" {
		t.Errorf("entry 0 = %+v", proxies[0])
	}
	if proxies[1].URL != "socks5://10.0.0.2:1080" {
		t.Errorf("entry 1 URL = %q", proxies[1].URL)
	}
	if proxies[2].URL != "http://10.0.0.3:3128" {
		t.Errorf("entry 2 URL = %q (scheme should default to http)", proxies[2].URL)
	}

	if ParseProxyList("") != nil || ParseProxyList("   \n  ") != nil {
		t.Error("blank PROXY_LIST should parse to nil")
	}
}

func TestEgressPool_Empty(t *testing.T) {
	if NewEgressPool(nil, EgressStickyDomain) != nil {
		t.Error("empty proxy list should yield a nil pool")
	}
	var p *EgressPool
	if p.Select("example.com") != nil {
		t.Error("nil pool Select should return nil")
	}
	if p.Size() != 0 {
		t.Error("nil pool Size should be 0")
	}
}

func proxies3() []*types.Proxy {
	return []*types.Proxy{
		{URL: "http://p0:8080"},
		{URL: "http://p1:8080"},
		{URL: "http://p2:8080"},
	}
}

func TestEgressPool_StickyDomainIsStable(t *testing.T) {
	p := NewEgressPool(proxies3(), EgressStickyDomain)
	// Same domain -> same egress every time.
	first := p.Select("filecrypt.cc")
	for i := 0; i < 10; i++ {
		if got := p.Select("filecrypt.cc"); got != first {
			t.Fatalf("sticky-domain not stable: got %v want %v", got.URL, first.URL)
		}
	}
	// Different domains should be able to land on different egresses (not a hard
	// guarantee, but across several domains we expect >1 distinct proxy used).
	seen := map[string]bool{}
	for _, d := range []string{"a.com", "b.com", "c.org", "d.net", "e.io", "f.co"} {
		seen[p.Select(d).URL] = true
	}
	if len(seen) < 2 {
		t.Errorf("sticky-domain mapped 6 domains to only %d egress(es)", len(seen))
	}
}

func TestEgressPool_RoundRobin(t *testing.T) {
	p := NewEgressPool(proxies3(), EgressRoundRobin)
	got := []string{
		p.Select("x").URL, p.Select("x").URL, p.Select("x").URL, p.Select("x").URL,
	}
	want := []string{"http://p0:8080", "http://p1:8080", "http://p2:8080", "http://p0:8080"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("round-robin[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
