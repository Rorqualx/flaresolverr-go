package solver

import (
	"hash/fnv"
	"net/url"
	"strings"
	"sync"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Layer-1 of the clean-egress path: a pool of egress proxies with a selection
// strategy. The default strategy maps each registrable domain to a STABLE proxy
// so the same site always exits the same IP — which is what keeps the Layer-2
// cf_clearance cache valid (clearance is IP-bound). See clearance_cache.go.

// EgressStrategy selects how a request is mapped to a proxy.
type EgressStrategy string

const (
	// EgressStickyDomain maps each registrable domain to a stable proxy (default).
	EgressStickyDomain EgressStrategy = "sticky-domain"
	// EgressRoundRobin rotates through proxies per request.
	EgressRoundRobin EgressStrategy = "round-robin"
	// EgressPerRequest picks a proxy pseudo-randomly per request.
	EgressPerRequest EgressStrategy = "per-request"
)

// ParseEgressStrategy normalizes a strategy string, defaulting to sticky-domain.
func ParseEgressStrategy(s string) EgressStrategy {
	switch EgressStrategy(strings.ToLower(strings.TrimSpace(s))) {
	case EgressRoundRobin:
		return EgressRoundRobin
	case EgressPerRequest:
		return EgressPerRequest
	default:
		return EgressStickyDomain
	}
}

// EgressPool holds the egress proxies and selection strategy.
type EgressPool struct {
	proxies  []*types.Proxy
	strategy EgressStrategy
	mu       sync.Mutex
	rr       int // round-robin cursor
}

// NewEgressPool creates a pool. Returns nil if there are no proxies, so callers
// can treat "no pool" and "empty pool" identically.
func NewEgressPool(proxies []*types.Proxy, strategy EgressStrategy) *EgressPool {
	if len(proxies) == 0 {
		return nil
	}
	return &EgressPool{proxies: proxies, strategy: strategy}
}

// Select returns the egress proxy for a request to the given registrable domain,
// or nil if the pool is empty. sticky-domain is deterministic per domain.
func (p *EgressPool) Select(domain string) *types.Proxy {
	if p == nil || len(p.proxies) == 0 {
		return nil
	}
	switch p.strategy {
	case EgressRoundRobin:
		p.mu.Lock()
		proxy := p.proxies[p.rr%len(p.proxies)]
		p.rr++
		p.mu.Unlock()
		return proxy
	case EgressPerRequest:
		// Vary by domain + cursor so it spreads without needing a RNG (Math.random
		// is intentionally avoided project-wide). Not cryptographic; just spread.
		p.mu.Lock()
		idx := (hashString(domain) + uint32(p.rr)) % uint32(len(p.proxies))
		p.rr++
		p.mu.Unlock()
		return p.proxies[idx]
	default: // EgressStickyDomain
		if domain == "" {
			return p.proxies[0]
		}
		return p.proxies[hashString(domain)%uint32(len(p.proxies))]
	}
}

// Size returns the number of proxies in the pool.
func (p *EgressPool) Size() int {
	if p == nil {
		return 0
	}
	return len(p.proxies)
}

// hashString returns a stable FNV-1a hash of s.
func hashString(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// ParseProxyList parses a PROXY_LIST value (comma- and/or newline-separated proxy
// URLs, optionally with embedded user:pass) into proxies. Embedded credentials
// are split out into Username/Password so the launcher gets a clean host:port and
// auth flows through the proxy-auth path. Blank lines and #-comments are skipped.
func ParseProxyList(raw string) []*types.Proxy {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	var proxies []*types.Proxy
	for _, f := range fields {
		entry := strings.TrimSpace(f)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if proxy := parseProxyEntry(entry); proxy != nil {
			proxies = append(proxies, proxy)
		}
	}
	return proxies
}

// parseProxyEntry parses a single proxy URL, splitting embedded credentials out.
func parseProxyEntry(entry string) *types.Proxy {
	if !strings.Contains(entry, "://") {
		entry = "http://" + entry // default scheme
	}
	u, err := url.Parse(entry)
	if err != nil || u.Host == "" {
		return nil
	}
	proxy := &types.Proxy{}
	if u.User != nil {
		proxy.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			proxy.Password = pw
		}
		u.User = nil // strip creds from the URL the launcher sees
	}
	proxy.URL = u.String()
	return proxy
}
