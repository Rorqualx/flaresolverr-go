package guardproxy

import (
	"fmt"
	"sync"
)

// Manager owns the guard listeners of one server: the direct one, which
// exists for the manager's whole life, and those created on demand for
// traffic that must leave through an upstream proxy.
type Manager struct {
	opts Options

	mu     sync.Mutex
	direct *Proxy
	closed bool
}

// NewManager starts the direct listener.
func NewManager(opts Options) (*Manager, error) {
	direct, err := New(opts)
	if err != nil {
		return nil, err
	}
	return &Manager{opts: opts, direct: direct}, nil
}

// Lease is the right to use one guard listener. Release it when the browser
// or browser context that was pointed at the listener is gone.
type Lease struct {
	proxyServer string
	release     func()
	once        sync.Once
}

// ProxyServer returns the proxy server value to give Chrome. It never
// contains credentials.
func (l *Lease) ProxyServer() string {
	return l.proxyServer
}

// Release gives the lease back. It is safe to call more than once.
func (l *Lease) Release() {
	l.once.Do(func() {
		if l.release != nil {
			l.release()
		}
	})
}

// Acquire returns a lease on the direct listener.
func (m *Manager) Acquire() (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	return &Lease{proxyServer: m.direct.ProxyServer()}, nil
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
	return ManagerStats{Listeners: 1, Totals: m.direct.Stats()}
}

// Close stops every listener and waits for their goroutines. It is safe to
// call more than once.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	direct := m.direct
	m.mu.Unlock()

	if err := direct.Close(); err != nil {
		return fmt.Errorf("failed to close the egress guard: %w", err)
	}
	return nil
}
