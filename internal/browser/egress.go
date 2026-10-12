package browser

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-rod/rod"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/guardproxy"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// guardBypassList is the proxy bypass list for anything routed through the
// egress guard. Chrome connects to loopback destinations directly even when
// a proxy is configured; "<-loopback>" removes that implicit rule, so a page
// asking for http://127.0.0.1/ reaches the guard (and is refused) instead of
// a service on this machine.
const guardBypassList = "<-loopback>"

// EgressRoute is where a browser or browser context sends its traffic when
// the egress guard is enabled. Release it when that browser or context is
// gone.
type EgressRoute struct {
	// ProxyServer is the --proxy-server / context proxyServer value. It is a
	// loopback address and never contains credentials.
	ProxyServer string
	// BypassList is the matching proxy bypass list.
	BypassList string

	lease *guardproxy.Lease
}

// Release gives the route's guard listener back. It is safe to call on a nil
// route and more than once.
func (r *EgressRoute) Release() {
	if r == nil || r.lease == nil {
		return
	}
	r.lease.Release()
}

// UpstreamAuthFailures returns how many connections the route's upstream
// proxy has refused for bad or missing credentials. Comparing the value
// before and after a request tells a failed navigation caused by wrong proxy
// credentials from any other.
func (r *EgressRoute) UpstreamAuthFailures() int64 {
	if r == nil || r.lease == nil {
		return 0
	}
	return r.lease.UpstreamAuthFailures()
}

// EgressGuardEnabled reports whether browsers are routed through the egress
// guard (EGRESS_GUARD).
func (p *Pool) EgressGuardEnabled() bool {
	return p != nil && p.guard != nil
}

// EgressGuardStats returns the guard's counters. ok is false when the guard
// is disabled.
func (p *Pool) EgressGuardStats() (stats guardproxy.ManagerStats, ok bool) {
	if p.guard == nil {
		return guardproxy.ManagerStats{}, false
	}
	return p.guard.Stats(), true
}

// CheckGuardProxy reports whether the egress guard can route through proxy.
// It lets a request be refused with a clear message before any browser work
// starts. A nil or empty proxy is always fine.
func (p *Pool) CheckGuardProxy(proxy *types.Proxy) error {
	if proxy == nil || proxy.URL == "" {
		return nil
	}
	_, err := guardproxy.ParseUpstream(proxy.URL, proxy.Username, proxy.Password)
	return err
}

// GuardRoute returns the guard listener for traffic that should leave
// through proxy, or through the configured default egress (PROXY_URL, or
// direct) when proxy is nil. It must only be called when the guard is
// enabled.
//
// The guard authenticates to the proxy itself, so the route's ProxyServer is
// safe to log and to put on a command line.
func (p *Pool) GuardRoute(proxy *types.Proxy) (*EgressRoute, error) {
	if p.guard == nil {
		return nil, errors.New("egress guard is not enabled")
	}

	var upstream *guardproxy.Upstream // nil: no upstream, the guard dials directly
	switch {
	case proxy != nil && proxy.URL != "":
		parsed, err := guardproxy.ParseUpstream(proxy.URL, proxy.Username, proxy.Password)
		if err != nil {
			return nil, err
		}
		// A proxy named by an API caller was validated when the request came
		// in, but its name is resolved again when the guard connects to it.
		// Unless local proxies are allowed, hold it to a public address then
		// too. The operator's own proxies are trusted wherever they live.
		if !p.config.AllowLocalProxies && !p.operatorProxies[proxy.URL] {
			parsed = parsed.RequirePublic()
		}
		upstream = parsed
	case p.config.ProxyURL != "":
		parsed, err := guardproxy.ParseUpstream(p.config.ProxyURL, p.config.ProxyUsername, p.config.ProxyPassword)
		if err != nil {
			return nil, fmt.Errorf("PROXY_URL: %w", err)
		}
		upstream = parsed
	}

	lease, err := p.guard.Acquire(upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to route through the egress guard: %w", err)
	}
	return &EgressRoute{ProxyServer: lease.ProxyServer(), BypassList: guardBypassList, lease: lease}, nil
}

// operatorProxyURLs returns the proxy URLs the operator configured (PROXY_URL
// and PROXY_LIST), in the form they have once credentials are split out of
// them: the form a request's proxy URL has when it was chosen from that
// configuration.
func operatorProxyURLs(cfg *config.Config) map[string]bool {
	urls := make(map[string]bool)
	if cfg.ProxyURL != "" {
		urls[cfg.ProxyURL] = true
	}
	entries := strings.FieldsFunc(cfg.ProxyList, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if !strings.Contains(entry, "://") {
			entry = "http://" + entry
		}
		parsed, err := url.Parse(entry)
		if err != nil || parsed.Host == "" {
			continue
		}
		parsed.User = nil
		urls[parsed.String()] = true
	}
	return urls
}

// NewEgressContext creates an isolated browser context on b (see
// NewIsolatedContext) whose traffic leaves through proxy, or through the
// browser's default egress when proxy is nil.
//
// With the egress guard enabled the context is pointed at a guard listener,
// which is released when the context is disposed. Without it the proxy URL
// is given to Chrome as is, as before.
func (p *Pool) NewEgressContext(b *rod.Browser, proxy *types.Proxy) (isolated *rod.Browser, dispose func(), err error) {
	if p.guard == nil {
		proxyServer := ""
		if proxy != nil {
			proxyServer = proxy.URL
		}
		return NewIsolatedContext(b, proxyServer)
	}

	route, err := p.GuardRoute(proxy)
	if err != nil {
		return nil, nil, err
	}
	isolated, disposeContext, err := newIsolatedContext(b, route.ProxyServer, route.BypassList)
	if err != nil {
		route.Release()
		return nil, nil, err
	}
	return isolated, func() {
		disposeContext()
		route.Release()
	}, nil
}
