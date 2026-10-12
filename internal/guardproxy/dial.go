package guardproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/security"
)

const (
	// maxDialAttempts bounds how many of a name's validated addresses are tried.
	maxDialAttempts = 4
	// minDialAttempt is the least time one of those attempts is given.
	minDialAttempt = 2 * time.Second
)

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

	// noteAuthFailure records that an upstream proxy refused the credentials
	// on a request forwarded in absolute form.
	noteAuthFailure()
}

// directDialer connects straight to destinations it has validated itself.
type directDialer struct {
	resolver   Resolver
	dial       DialFunc
	validateIP func(net.IP) error

	// minAttempt is the least time one dial attempt is given.
	minAttempt time.Duration
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
	return &directDialer{resolver: opts.Resolver, dial: dial, validateIP: opts.ValidateIP, minAttempt: minDialAttempt}
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

	attempts := len(addresses)
	if attempts > maxDialAttempts {
		attempts = maxDialAttempts
	}

	var lastErr error
	for i, ip := range addresses[:attempts] {
		// The literal that was validated is what gets dialed: the name is
		// never handed to anything that could resolve it again.
		conn, err := d.dialAttempt(ctx, attempts-i, net.JoinHostPort(ip.String(), strconv.Itoa(dest.port)))
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

// dialAttempt dials address with a share of the time ctx has left, so that
// one unresponsive address (an unroutable IPv6 answer, typically) cannot use
// up the whole budget before the next one is tried.
func (d *directDialer) dialAttempt(ctx context.Context, attemptsLeft int, address string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok || attemptsLeft <= 1 {
		return d.dial(ctx, "tcp", address)
	}
	share := time.Until(deadline) / time.Duration(attemptsLeft)
	if share < d.minAttempt {
		share = d.minAttempt
	}
	attemptCtx, cancel := context.WithTimeout(ctx, share)
	defer cancel()
	return d.dial(attemptCtx, "tcp", address)
}

// proxyHeader implements originDialer: a direct connection needs none.
func (d *directDialer) proxyHeader() []byte {
	return nil
}

// noteAuthFailure implements originDialer: there is no upstream to refuse.
func (d *directDialer) noteAuthFailure() {}

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
