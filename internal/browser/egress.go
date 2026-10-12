package browser

import (
	"errors"
	"fmt"

	"github.com/go-rod/rod"

	"github.com/Rorqualx/flaresolverr-go/internal/guardproxy"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// guardBypassList is the proxy bypass list for anything routed through the
// egress guard. Chrome connects to loopback destinations directly even when
// a proxy is configured; "<-loopback>" removes that implicit rule, so a page
// asking for http://127.0.0.1/ reaches the guard (and is refused) instead of
// a service on this machine.
const guardBypassList = "<-loopback>"

// ErrGuardUpstreamUnsupported is returned when the egress guard is asked to
// route through an upstream proxy.
var ErrGuardUpstreamUnsupported = errors.New("upstream proxies are not supported with EGRESS_GUARD")

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

// GuardRoute returns the guard listener for traffic that should leave
// through proxy, or through the configured default egress when proxy is nil.
// It must only be called when the guard is enabled.
func (p *Pool) GuardRoute(proxy *types.Proxy) (*EgressRoute, error) {
	if p.guard == nil {
		return nil, errors.New("egress guard is not enabled")
	}
	if (proxy != nil && proxy.URL != "") || p.config.ProxyURL != "" {
		return nil, ErrGuardUpstreamUnsupported
	}

	lease, err := p.guard.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to route through the egress guard: %w", err)
	}
	return &EgressRoute{ProxyServer: lease.ProxyServer(), BypassList: guardBypassList, lease: lease}, nil
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
