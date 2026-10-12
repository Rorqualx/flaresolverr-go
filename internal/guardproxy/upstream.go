package guardproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Rorqualx/flaresolverr-go/internal/security"
)

// Upstream proxy schemes the guard can chain to.
const (
	schemeHTTP   = "http"
	schemeHTTPS  = "https"
	schemeSOCKS5 = "socks5"
)

// maxUpstreamResponseBytes bounds the upstream proxy's answer to CONNECT.
const maxUpstreamResponseBytes = 16 << 10

// ErrUnsupportedUpstream is returned for an upstream proxy the guard cannot
// chain to.
var ErrUnsupportedUpstream = errors.New("unsupported upstream proxy")

// Upstream is a proxy the guard reaches destinations through. Build one with
// ParseUpstream.
type Upstream struct {
	scheme   string
	address  string // host:port
	hostname string // for TLS to an https proxy
	username string
	password string

	// requirePublic makes the guard refuse to connect to the proxy itself at
	// a non-public address. It is set for proxies named by an API caller and
	// left off for the operator's own.
	requirePublic bool
}

// ParseUpstream builds an Upstream from a proxy URL and optional credentials.
// Credentials given separately win over ones embedded in the URL. The error
// never contains the URL, which may carry credentials.
//
// socks4 is refused: it cannot carry a hostname for the proxy to resolve
// (that is socks4a, which Chrome does not speak either), so the guard could
// not hand name resolution to it.
func ParseUpstream(rawURL, username, password string) (*Upstream, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: the proxy URL is not valid", ErrUnsupportedUpstream)
	}

	upstream := &Upstream{hostname: parsed.Hostname(), username: username, password: password}
	var defaultPort string
	switch strings.ToLower(parsed.Scheme) {
	case schemeHTTP:
		upstream.scheme, defaultPort = schemeHTTP, "80"
	case schemeHTTPS:
		upstream.scheme, defaultPort = schemeHTTPS, "443"
	case schemeSOCKS5, "socks5h":
		upstream.scheme, defaultPort = schemeSOCKS5, "1080"
	case "socks4", "socks4a":
		return nil, fmt.Errorf("%w: socks4 proxies cannot be used with EGRESS_GUARD (use http, https or socks5)", ErrUnsupportedUpstream)
	default:
		return nil, fmt.Errorf("%w: the proxy scheme must be http, https or socks5", ErrUnsupportedUpstream)
	}

	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return nil, fmt.Errorf("%w: the proxy port is not valid", ErrUnsupportedUpstream)
	}
	upstream.address = net.JoinHostPort(upstream.hostname, port)

	if upstream.username == "" && upstream.password == "" && parsed.User != nil {
		upstream.username = parsed.User.Username()
		upstream.password, _ = parsed.User.Password()
	}
	return upstream, nil
}

// RequirePublic returns a copy of u that the guard will only connect to at a
// public address.
func (u *Upstream) RequirePublic() *Upstream {
	clone := *u
	clone.requirePublic = true
	return &clone
}

// String describes the upstream without its credentials.
func (u *Upstream) String() string {
	return u.scheme + "://" + u.address
}

// hasCredentials reports whether the guard authenticates to the upstream.
func (u *Upstream) hasCredentials() bool {
	return u.username != "" || u.password != ""
}

// upstreamKey identifies an upstream for listener sharing. Two requests share
// a listener only if they would authenticate identically.
type upstreamKey struct {
	scheme, address, username, password string
	requirePublic                       bool
}

func (u *Upstream) key() upstreamKey {
	return upstreamKey{
		scheme:        u.scheme,
		address:       u.address,
		username:      u.username,
		password:      u.password,
		requirePublic: u.requirePublic,
	}
}

// chainedDialer reaches destinations through an upstream proxy, doing the
// CONNECT or SOCKS5 handshake and the authentication itself.
type chainedDialer struct {
	upstream *Upstream
	dial     DialFunc       // connects to the upstream proxy
	rootCAs  *x509.CertPool // verifies an https upstream; nil = system roots

	// authFailures counts connections the upstream refused for bad or
	// missing credentials.
	authFailures atomic.Int64
}

// newChainedDialer builds the dialer for a guard in front of upstream.
func newChainedDialer(opts Options, upstream *Upstream) *chainedDialer {
	dial := opts.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: opts.DialTimeout}
		if upstream.requirePublic {
			dialer.Control = func(_, address string, _ syscall.RawConn) error {
				return checkSocketAddress(address, opts.ValidateIP)
			}
		}
		dial = dialer.DialContext
	}
	return &chainedDialer{upstream: upstream, dial: dial, rootCAs: opts.UpstreamRootCAs}
}

// open implements originDialer.
//
// The upstream resolves destination names, so the guard cannot check the
// address a name leads to. It refuses what it can classify without
// resolving: private and special-purpose address literals in every encoding,
// localhost names and cloud metadata names.
func (d *chainedDialer) open(ctx context.Context, dest destination, tunnel bool) (net.Conn, bool, error) {
	if _, err := security.ClassifyEgressHost(dest.host); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrBlocked, err)
	}

	if d.upstream.scheme == schemeSOCKS5 {
		conn, err := d.openSOCKS5(ctx, dest)
		return conn, false, err
	}

	conn, err := d.connectUpstream(ctx)
	if err != nil {
		return nil, false, err
	}
	if !tunnel {
		// Plain HTTP goes to an HTTP proxy in absolute form, as a browser
		// would send it: many proxies refuse CONNECT to port 80.
		return conn, true, nil
	}

	tunneled, err := d.handshakeCONNECT(ctx, conn, dest)
	if err != nil {
		// Ignore error: the connection is unusable
		_ = conn.Close()
		return nil, false, err
	}
	return tunneled, false, nil
}

// proxyHeader implements originDialer: the credentials for a plain request
// forwarded to an HTTP upstream.
func (d *chainedDialer) proxyHeader() []byte {
	if d.upstream.scheme == schemeSOCKS5 || !d.upstream.hasCredentials() {
		return nil
	}
	return []byte("Proxy-Authorization: " + d.basicAuth() + "\r\n")
}

// noteAuthFailure implements originDialer.
func (d *chainedDialer) noteAuthFailure() {
	d.authFailures.Add(1)
}

// basicAuth returns the Proxy-Authorization value for the upstream.
func (d *chainedDialer) basicAuth() string {
	credentials := d.upstream.username + ":" + d.upstream.password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// connectUpstream opens a connection to an http or https upstream proxy.
func (d *chainedDialer) connectUpstream(ctx context.Context) (net.Conn, error) {
	conn, err := d.dial(ctx, "tcp", d.upstream.address)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			return nil, fmt.Errorf("%w: the upstream proxy is not at a public address", ErrBlocked)
		}
		return nil, fmt.Errorf("%w: could not connect to it", ErrUpstream)
	}
	if d.upstream.scheme != schemeHTTPS {
		return conn, nil
	}

	secured := tls.Client(conn, &tls.Config{
		ServerName: d.upstream.hostname,
		RootCAs:    d.rootCAs,
		MinVersion: tls.VersionTLS12,
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		// Ignore error: the connection is unusable
		_ = conn.Close()
		return nil, fmt.Errorf("%w: TLS handshake with it failed", ErrUpstream)
	}
	return secured, nil
}

// handshakeCONNECT asks an HTTP upstream for a tunnel to dest over conn.
func (d *chainedDialer) handshakeCONNECT(ctx context.Context, conn net.Conn, dest destination) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
		}
	}

	target := dest.address()
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if d.upstream.hasCredentials() {
		request += "Proxy-Authorization: " + d.basicAuth() + "\r\n"
	}
	request += "\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil, fmt.Errorf("%w: could not send CONNECT", ErrUpstream)
	}

	reader := bufio.NewReader(conn)
	status, err := readResponseStatus(reader, maxUpstreamResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: no valid answer to CONNECT", ErrUpstream)
	}
	switch {
	case status == 407:
		d.authFailures.Add(1)
		return nil, ErrUpstreamAuth
	case status < 200 || status > 299:
		return nil, fmt.Errorf("%w: it answered CONNECT with status %d", ErrUpstream, status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	// Bytes the proxy sent after its answer belong to the tunnel.
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// readResponseStatus reads one response head of at most maxBytes and returns
// its status code.
func readResponseStatus(reader *bufio.Reader, maxBytes int) (int, error) {
	budget := maxBytes
	line, err := readLine(reader, &budget)
	if err != nil {
		return 0, err
	}
	status, err := parseStatusLine(line)
	if err != nil {
		return 0, err
	}
	for {
		line, err := readLine(reader, &budget)
		if err != nil {
			return 0, err
		}
		if len(strings.TrimRight(string(line), "\r\n")) == 0 {
			return status, nil
		}
	}
}

// parseStatusLine returns the status code of "HTTP/1.x NNN reason".
func parseStatusLine(line []byte) (int, error) {
	fields := strings.SplitN(strings.TrimRight(string(line), "\r\n"), " ", 3)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") || len(fields[1]) != 3 || !allDigits(fields[1]) {
		return 0, fmt.Errorf("%w: status line", errMalformedHead)
	}
	return strconv.Atoi(fields[1])
}

// bufferedConn is a connection whose first bytes have already been read into
// reader.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// contextDialer adapts a DialFunc to the dialer interfaces x/net/proxy wants.
type contextDialer struct {
	dial DialFunc
}

func (d contextDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(context.Background(), network, address)
}

func (d contextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

// openSOCKS5 asks a SOCKS5 upstream for a connection to dest. The name is
// sent to the proxy unresolved.
func (d *chainedDialer) openSOCKS5(ctx context.Context, dest destination) (net.Conn, error) {
	var auth *proxy.Auth
	if d.upstream.hasCredentials() {
		auth = &proxy.Auth{User: d.upstream.username, Password: d.upstream.password}
	}
	dialer, err := proxy.SOCKS5("tcp", d.upstream.address, auth, contextDialer{dial: d.dial})
	if err != nil {
		return nil, fmt.Errorf("%w: SOCKS5 setup failed", ErrUpstream)
	}
	withContext, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("%w: SOCKS5 dialer has no context support", ErrUpstream)
	}

	conn, err := withContext.DialContext(ctx, "tcp", dest.address())
	if err == nil {
		return conn, nil
	}
	// The library's error text names only the proxy address and the failure;
	// it is classified here and not passed on.
	text := err.Error()
	switch {
	case errors.Is(err, ErrBlocked):
		return nil, fmt.Errorf("%w: the upstream proxy is not at a public address", ErrBlocked)
	case strings.Contains(text, "authentication failed"), strings.Contains(text, "no acceptable authentication methods"):
		d.authFailures.Add(1)
		return nil, ErrUpstreamAuth
	default:
		return nil, fmt.Errorf("%w: SOCKS5 connection through it failed", ErrUpstream)
	}
}
