package guardproxy

import (
	"errors"
	"fmt"
	"sync"
)

// maxUpstreamListeners bounds how many distinct upstream proxies can be in
// use at once.
const maxUpstreamListeners = 128

// ErrTooManyUpstreams is returned when that many distinct upstream proxies
// are already in use.
var ErrTooManyUpstreams = errors.New("too many distinct upstream proxies in use")

// Manager owns the guard listeners of one server: the direct one, which
// exists for the manager's whole life, and one per distinct upstream proxy,
// created when first needed and closed when nothing uses it any more.
//
// A listener per upstream is what lets Chrome be given a proxy address with
// no credentials in it: which upstream to use, and how to authenticate to it,
// is a property of the listener.
type Manager struct {
	opts Options

	mu      sync.Mutex
	direct  *Proxy
	chained map[upstreamKey]*chainedListener
	closed  bool
}

// chainedListener is the listener for one upstream and the number of leases
// on it.
type chainedListener struct {
	proxy  *Proxy
	dialer *chainedDialer
	leases int
}

// NewManager starts the direct listener.
func NewManager(opts Options) (*Manager, error) {
	opts = opts.withDefaults()
	direct, err := start(opts, newDirectDialer(opts))
	if err != nil {
		return nil, err
	}
	return &Manager{opts: opts, direct: direct, chained: make(map[upstreamKey]*chainedListener)}, nil
}

// Lease is the right to use one guard listener. Release it when the browser
// or browser context that was pointed at the listener is gone.
type Lease struct {
	proxyServer  string
	authFailures func() int64
	release      func()
	once         sync.Once
}

// ProxyServer returns the proxy server value to give Chrome. It is a loopback
// address and never contains credentials.
func (l *Lease) ProxyServer() string {
	return l.proxyServer
}

// UpstreamAuthFailures returns how many connections the listener's upstream
// proxy has refused for bad or missing credentials. It is always zero for the
// direct listener.
func (l *Lease) UpstreamAuthFailures() int64 {
	if l.authFailures == nil {
		return 0
	}
	return l.authFailures()
}

// Release gives the lease back. It is safe to call more than once.
func (l *Lease) Release() {
	l.once.Do(func() {
		if l.release != nil {
			l.release()
		}
	})
}

// Acquire returns a lease on the listener for upstream, starting it if this
// is its first user. A nil upstream means the direct listener.
func (m *Manager) Acquire(upstream *Upstream) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if upstream == nil {
		return &Lease{proxyServer: m.direct.ProxyServer()}, nil
	}

	key := upstream.key()
	listener, ok := m.chained[key]
	if !ok {
		if len(m.chained) >= maxUpstreamListeners {
			return nil, ErrTooManyUpstreams
		}
		dialer := newChainedDialer(m.opts, upstream)
		proxy, err := start(m.opts, dialer)
		if err != nil {
			return nil, err
		}
		listener = &chainedListener{proxy: proxy, dialer: dialer}
		m.chained[key] = listener
	}
	listener.leases++

	return &Lease{
		proxyServer:  listener.proxy.ProxyServer(),
		authFailures: listener.dialer.authFailures.Load,
		release:      func() { m.release(key, listener) },
	}, nil
}

// release drops one lease on listener and closes it when it was the last.
func (m *Manager) release(key upstreamKey, listener *chainedListener) {
	m.mu.Lock()
	listener.leases--
	last := listener.leases <= 0 && m.chained[key] == listener
	if last {
		delete(m.chained, key)
	}
	m.mu.Unlock()

	if last {
		// Outside the lock: Close waits for the listener's connections.
		// Ignore error: nothing uses the listener any more
		_ = listener.proxy.Close()
	}
}

// ManagerStats is a snapshot of every listener a manager owns.
type ManagerStats struct {
	Listeners int   // listeners open now, the direct one included
	Totals    Stats // counters summed over the open listeners
}

// Stats returns a snapshot of the manager's listeners.
func (m *Manager) Stats() ManagerStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ManagerStats{}
	}

	stats := ManagerStats{Listeners: 1 + len(m.chained), Totals: m.direct.Stats()}
	for _, listener := range m.chained {
		stats.Totals = stats.Totals.plus(listener.proxy.Stats())
	}
	return stats
}

// plus returns the field-wise sum of two snapshots.
func (s Stats) plus(other Stats) Stats {
	return Stats{
		Accepted:      s.Accepted + other.Accepted,
		Active:        s.Active + other.Active,
		Tunnels:       s.Tunnels + other.Tunnels,
		Requests:      s.Requests + other.Requests,
		Blocked:       s.Blocked + other.Blocked,
		Failed:        s.Failed + other.Failed,
		RejectedPeers: s.RejectedPeers + other.RejectedPeers,
		RejectedBusy:  s.RejectedBusy + other.RejectedBusy,
	}
}

// Close stops every listener and waits for their goroutines. Outstanding
// leases become no-ops. It is safe to call more than once.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	proxies := []*Proxy{m.direct}
	for key, listener := range m.chained {
		proxies = append(proxies, listener.proxy)
		delete(m.chained, key)
	}
	m.mu.Unlock()

	var failures []error
	for _, proxy := range proxies {
		if err := proxy.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("failed to close the egress guard: %w", errors.Join(failures...))
	}
	return nil
}
