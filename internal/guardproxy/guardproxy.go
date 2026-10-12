// Package guardproxy is an in-process forward proxy that the browsers are
// pointed at so that every connection they make is checked before it leaves
// the machine.
//
// Validating a URL before navigating to it is not enough to keep a browser
// away from internal services: the page it loads can redirect, fetch, embed
// or open a WebSocket to any address, and a hostname can resolve to a public
// address when it is validated and a private one when Chrome connects. The
// guard closes that gap at the only place every one of those requests passes
// through: the connection itself. For each destination it
//
//  1. refuses names and address literals the URL validator refuses,
//  2. resolves the name once, in this process,
//  3. requires every returned address to be public, and
//  4. dials the validated address literal, so nothing can be re-resolved
//     between the check and the connection.
//
// HTTPS and WebSocket traffic arrives as CONNECT and is relayed as an opaque
// byte tunnel: TLS is never terminated, so the browser's TLS and HTTP/2
// fingerprints reach the target unchanged. Plain HTTP arrives in absolute
// form and is forwarded with its header block untouched (see writeHead for
// the two hop-by-hop exceptions).
package guardproxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/security"
)

// Limits applied when Options leaves a field at its zero value.
const (
	defaultMaxConns       = 512
	defaultDialTimeout    = 15 * time.Second
	defaultIdleTimeout    = 5 * time.Minute
	defaultHeaderTimeout  = 30 * time.Second
	defaultMaxHeaderBytes = 64 << 10

	relayBufferSize = 32 << 10
	refusalTimeout  = 5 * time.Second
	listenNetwork   = "tcp4"
	listenAddress   = "127.0.0.1:0"
)

// Errors the guard reports for a destination it will not or cannot reach.
var (
	// ErrBlocked means the destination is not a public address.
	ErrBlocked = errors.New("destination is not allowed")
	// ErrResolve means the destination name did not resolve.
	ErrResolve = errors.New("destination did not resolve")
	// ErrDial means no validated address accepted the connection.
	ErrDial = errors.New("destination is unreachable")
	// ErrClosed is returned by operations on a proxy that has been closed.
	ErrClosed = errors.New("egress guard is closed")
)

// Resolver looks a hostname up. *net.Resolver satisfies it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// DialFunc opens a connection to address, which is always an IP literal and
// port when the guard dials a destination directly.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Options configures a Proxy. The zero value is a direct-mode guard with the
// default limits, the system resolver and the URL validator's address rules.
type Options struct {
	// Resolution and dialing (replaceable in tests)
	Resolver   Resolver
	Dial       DialFunc
	ValidateIP func(net.IP) error

	// Limits
	MaxConns       int           // simultaneous client connections
	DialTimeout    time.Duration // resolve + connect, per destination
	IdleTimeout    time.Duration // no bytes in either direction
	HeaderTimeout  time.Duration // receiving one request head
	MaxHeaderBytes int           // size of one request head

	// UpstreamRootCAs verifies an https upstream proxy's certificate. Nil
	// means the system roots.
	UpstreamRootCAs *x509.CertPool
}

// withDefaults returns o with every unset field filled in.
func (o Options) withDefaults() Options {
	if o.Resolver == nil {
		o.Resolver = &net.Resolver{}
	}
	if o.ValidateIP == nil {
		o.ValidateIP = security.ValidateIP
	}
	if o.MaxConns <= 0 {
		o.MaxConns = defaultMaxConns
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = defaultDialTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.HeaderTimeout <= 0 {
		o.HeaderTimeout = defaultHeaderTimeout
	}
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	return o
}

// Stats is a snapshot of a proxy's counters.
type Stats struct {
	Accepted      int64 // client connections accepted
	Active        int64 // client connections open now
	Tunnels       int64 // CONNECT tunnels established
	Requests      int64 // plain HTTP requests forwarded
	Blocked       int64 // destinations refused by the address rules
	Failed        int64 // destinations that did not resolve or connect
	RejectedPeers int64 // connections from a non-loopback peer
	RejectedBusy  int64 // connections refused at the connection limit
}

type counters struct {
	accepted      atomic.Int64
	active        atomic.Int64
	tunnels       atomic.Int64
	requests      atomic.Int64
	blocked       atomic.Int64
	failed        atomic.Int64
	rejectedPeers atomic.Int64
	rejectedBusy  atomic.Int64
}

// Proxy is one guard listener. Create it with New and stop it with Close.
type Proxy struct {
	opts     Options
	listener net.Listener
	origin   originDialer

	// ctx is canceled by Close; every dial derives from it.
	ctx    context.Context
	cancel context.CancelFunc

	// slots bounds the number of client connections.
	slots chan struct{}

	// wg tracks the accept loop and every connection goroutine.
	wg sync.WaitGroup

	mu     sync.Mutex
	conns  map[net.Conn]struct{} // every open client and origin connection
	closed bool

	stats counters
}

// New starts a direct-mode guard on an ephemeral loopback port.
func New(opts Options) (*Proxy, error) {
	opts = opts.withDefaults()
	return start(opts, newDirectDialer(opts))
}

// start opens the listener and the accept loop for a guard that reaches
// destinations through origin.
func start(opts Options, origin originDialer) (*Proxy, error) {
	listener, err := net.Listen(listenNetwork, listenAddress)
	if err != nil {
		return nil, fmt.Errorf("egress guard: failed to listen on loopback: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		opts:     opts,
		listener: listener,
		origin:   origin,
		ctx:      ctx,
		cancel:   cancel,
		slots:    make(chan struct{}, opts.MaxConns),
		conns:    make(map[net.Conn]struct{}),
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop()
	}()
	return p, nil
}

// Addr returns the listener's address as host:port.
func (p *Proxy) Addr() string {
	return p.listener.Addr().String()
}

// ProxyServer returns the value to give Chrome as its proxy server.
func (p *Proxy) ProxyServer() string {
	return "http://" + p.Addr()
}

// Stats returns a snapshot of the proxy's counters.
func (p *Proxy) Stats() Stats {
	return Stats{
		Accepted:      p.stats.accepted.Load(),
		Active:        p.stats.active.Load(),
		Tunnels:       p.stats.tunnels.Load(),
		Requests:      p.stats.requests.Load(),
		Blocked:       p.stats.blocked.Load(),
		Failed:        p.stats.failed.Load(),
		RejectedPeers: p.stats.rejectedPeers.Load(),
		RejectedBusy:  p.stats.rejectedBusy.Load(),
	}
}

// Close stops the listener, closes every open connection and waits for all
// of the proxy's goroutines to exit. It is safe to call more than once.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	open := make([]net.Conn, 0, len(p.conns))
	for conn := range p.conns {
		open = append(open, conn)
	}
	p.mu.Unlock()

	p.cancel()
	err := p.listener.Close()
	for _, conn := range open {
		// Ignore error: closing only unblocks the goroutine relaying on it
		_ = conn.Close()
	}
	p.wg.Wait()
	if err != nil {
		return fmt.Errorf("egress guard: failed to close listener: %w", err)
	}
	return nil
}

// track registers conn so Close can interrupt it. It reports false, and
// closes conn, when the proxy is already closed.
func (p *Proxy) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		// Ignore error: the connection was never used
		_ = conn.Close()
		return false
	}
	p.conns[conn] = struct{}{}
	return true
}

// drop closes conn and stops tracking it.
func (p *Proxy) drop(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
	// Ignore error: a second close of a relayed connection is expected
	_ = conn.Close()
}

// acceptLoop accepts client connections until the listener is closed.
func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("Egress guard accept failed")
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}

		select {
		case p.slots <- struct{}{}:
		default:
			p.stats.rejectedBusy.Add(1)
			// Ignore error: the connection is being refused
			_ = conn.Close()
			continue
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.slots }()
			p.serveConn(conn)
		}()
	}
}

// loopbackPeer reports whether addr is a loopback TCP address. The listener
// is bound to 127.0.0.1, so anything else means the socket is reachable in a
// way it must never be.
func loopbackPeer(addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	return ok && tcpAddr.IP != nil && tcpAddr.IP.IsLoopback()
}

// serveConn handles one client connection until it ends.
func (p *Proxy) serveConn(conn net.Conn) {
	if !loopbackPeer(conn.RemoteAddr()) {
		p.stats.rejectedPeers.Add(1)
		log.Warn().Msg("Egress guard refused a connection from a non-loopback peer")
		// Ignore error: the connection is being refused
		_ = conn.Close()
		return
	}
	if !p.track(conn) {
		return
	}
	defer p.drop(conn)

	p.stats.accepted.Add(1)
	p.stats.active.Add(1)
	defer p.stats.active.Add(-1)

	client := &clientConn{Conn: conn, reader: bufio.NewReader(conn)}
	head, err := p.readHead(client, p.opts.HeaderTimeout)
	if err != nil {
		p.refuseBadRequest(conn, err)
		return
	}

	if head.method == methodConnect {
		p.serveConnect(client, head)
		return
	}
	p.servePlain(client, head)
}

// clientConn is a client connection together with the buffered reader its
// request heads are parsed from. Bytes the reader has buffered belong to the
// stream, so everything read from the client goes through reader.
type clientConn struct {
	net.Conn
	reader *bufio.Reader
}

// serveConnect establishes and relays one CONNECT tunnel.
func (p *Proxy) serveConnect(client *clientConn, head *requestHead) {
	dest, err := parseConnectTarget(head.target)
	if err != nil {
		p.refuseBadRequest(client.Conn, err)
		return
	}

	origin, _, err := p.open(dest, true)
	if err != nil {
		p.refuse(client.Conn, dest, err)
		return
	}
	defer p.drop(origin)

	if err := writeAll(client.Conn, []byte(connectEstablished), p.opts.IdleTimeout); err != nil {
		return
	}
	p.stats.tunnels.Add(1)

	activity := newActivity()
	done := make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer close(done)
		p.relay(client.Conn, origin, origin, activity)
		// The origin is finished; closing the client ends the other direction.
		// Ignore error: drop closes it again
		_ = client.Close()
	}()

	p.relay(origin, client.reader, client.Conn, activity)
	// Ignore error: drop closes it again
	_ = origin.Close()
	<-done
}

// open resolves, validates and dials dest within the dial timeout, counting
// the outcome.
func (p *Proxy) open(dest destination, tunnel bool) (conn net.Conn, absoluteForm bool, err error) {
	ctx, cancel := context.WithTimeout(p.ctx, p.opts.DialTimeout)
	defer cancel()

	conn, absoluteForm, err = p.origin.open(ctx, dest, tunnel)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			p.stats.blocked.Add(1)
		} else {
			p.stats.failed.Add(1)
		}
		return nil, false, err
	}
	if !p.track(conn) {
		return nil, false, ErrClosed
	}
	return conn, absoluteForm, nil
}

// activity is the time of the last byte relayed on a connection in either
// direction, shared by both relay loops so that a quiet direction is not
// mistaken for an idle connection.
type activity struct {
	last atomic.Int64
}

func newActivity() *activity {
	a := &activity{}
	a.touch()
	return a
}

func (a *activity) touch() {
	a.last.Store(time.Now().UnixNano())
}

func (a *activity) idleFor() time.Duration {
	return time.Since(time.Unix(0, a.last.Load()))
}

// byteReader is the read half of a connection: the connection itself, or the
// buffered reader in front of a client connection.
type byteReader interface {
	Read(p []byte) (int, error)
}

// relay copies src to dst unmodified until src ends, either side fails, or
// the connection has been idle in both directions for the idle timeout.
// srcConn is the connection src reads from; its read deadline is what bounds
// each read.
func (p *Proxy) relay(dst net.Conn, src byteReader, srcConn net.Conn, act *activity) {
	buf := make([]byte, relayBufferSize)
	idle := p.opts.IdleTimeout
	for {
		if err := srcConn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return
		}
		n, err := src.Read(buf)
		if n > 0 {
			act.touch()
			if writeErr := writeAll(dst, buf[:n], idle); writeErr != nil {
				return
			}
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && act.idleFor() < idle {
				continue // only this direction was quiet
			}
			return
		}
	}
}

// writeAll writes data to conn within timeout.
func writeAll(conn net.Conn, data []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}
