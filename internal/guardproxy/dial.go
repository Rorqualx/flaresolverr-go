package guardproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/Rorqualx/flaresolverr-go/internal/security"
)

// maxDialAttempts bounds how many of a name's validated addresses are tried.
const maxDialAttempts = 4

// Errors for a destination reached through an upstream proxy.
var (
	// ErrUpstream means the upstream proxy refused or failed the connection.
	ErrUpstream = errors.New("upstream proxy failed")
	// ErrUpstreamAuth means the upstream proxy rejected the credentials.
	ErrUpstreamAuth = errors.New("upstream proxy rejected the credentials")
)

// originDialer opens the connection a request is forwarded on.
type originDialer interface {
	// open returns a connection for dest. tunnel is true for CONNECT. When
	// absoluteForm is true the connection leads to another HTTP proxy and
	// plain requests must keep their absolute-form target.
	open(ctx context.Context, dest destination, tunnel bool) (conn net.Conn, absoluteForm bool, err error)

	// proxyHeader returns header lines to add to a plain request sent in
	// absolute form, or nil.
	proxyHeader() []byte
}

// directDialer connects straight to destinations it has validated itself.
type directDialer struct {
	resolver   Resolver
	dial       DialFunc
	validateIP func(net.IP) error
}

// newDirectDialer builds the dialer for a guard with no upstream proxy.
func newDirectDialer(opts Options) *directDialer {
	dial := opts.Dial
	if dial == nil {
		dialer := &net.Dialer{
			Timeout: opts.DialTimeout,
			// Checked again on the socket about to connect: whatever path led
			// here, a non-public address is never dialed.
			Control: func(_, address string, _ syscall.RawConn) error {
				return checkSocketAddress(address, opts.ValidateIP)
			},
		}
		dial = dialer.DialContext
	}
	return &directDialer{resolver: opts.Resolver, dial: dial, validateIP: opts.ValidateIP}
}

// checkSocketAddress validates the ip:port a socket is about to connect to.
func checkSocketAddress(address string, validateIP func(net.IP) error) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: not an address literal", ErrBlocked)
	}
	if err := validateIP(ip); err != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	return nil
}

// open validates dest and connects to the first of its addresses that
// answers.
func (d *directDialer) open(ctx context.Context, dest destination, _ bool) (net.Conn, bool, error) {
	addresses, err := d.resolve(ctx, dest.host)
	if err != nil {
		return nil, false, err
	}

	var lastErr error
	for i, ip := range addresses {
		if i >= maxDialAttempts {
			break
		}
		// The literal that was validated is what gets dialed: the name is
		// never handed to anything that could resolve it again.
		conn, err := d.dial(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(dest.port)))
		if err == nil {
			return conn, false, nil
		}
		if errors.Is(err, ErrBlocked) {
			return nil, false, err
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, false, fmt.Errorf("%w: %v", ErrDial, lastErr)
}

// proxyHeader implements originDialer: a direct connection needs none.
func (d *directDialer) proxyHeader() []byte {
	return nil
}

// resolve returns the addresses host may be reached at, every one of them
// validated. The name is looked up exactly once.
func (d *directDialer) resolve(ctx context.Context, host string) ([]net.IP, error) {
	literal, err := security.ClassifyEgressHost(host)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	if literal != nil {
		// ClassifyEgressHost applies the default rules; the configured ones
		// may be stricter.
		if err := d.validateIP(literal); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBlocked, err)
		}
		return []net.IP{literal}, nil
	}

	addresses, err := d.resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrResolve
	}
	// All of them, not just the one that will be dialed: a name that answers
	// with a private address alongside a public one is not a public name.
	for _, ip := range addresses {
		if err := d.validateIP(ip); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBlocked, err)
		}
	}
	return addresses, nil
}
