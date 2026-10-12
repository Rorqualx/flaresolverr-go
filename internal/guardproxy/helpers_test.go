package guardproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Addresses used as stand-ins for real public hosts. Nothing is ever sent to
// them: the fake network maps each to a listener on this machine.
const (
	publicIP      = "93.184.216.34"
	otherPublicIP = "151.101.1.69"
	privateIP     = "10.99.0.2"
)

const testTimeout = 5 * time.Second

// fakeResolver answers lookups from a script: each call for a name consumes
// the next answer, and the last answer repeats.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]string
	calls   map[string]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]string{}, calls: map[string]int{}}
}

// set scripts the successive answers for name.
func (r *fakeResolver) set(name string, answers ...[]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[name] = answers
}

func (r *fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	script, ok := r.answers[host]
	if !ok || len(script) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	index := r.calls[host]
	r.calls[host]++
	if index >= len(script) {
		index = len(script) - 1
	}
	ips := make([]net.IP, 0, len(script[index]))
	for _, text := range script[index] {
		ips = append(ips, net.ParseIP(text))
	}
	return ips, nil
}

func (r *fakeResolver) callCount(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[name]
}

// fakeNetwork stands in for the internet: it maps "ip:port" to a listener on
// this machine and records every address the guard dialed.
type fakeNetwork struct {
	mu     sync.Mutex
	routes map[string]string
	dialed []string
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{routes: map[string]string{}}
}

// route makes address reachable at the real listener address target.
func (n *fakeNetwork) route(address, target string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes[address] = target
}

func (n *fakeNetwork) dial(ctx context.Context, network, address string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, address)
	target, ok := n.routes[address]
	n.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fake network: no route to %s", address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, target)
}

func (n *fakeNetwork) dials() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dialed...)
}

// testEnv is a guard wired to a fake resolver and a fake network.
type testEnv struct {
	proxy    *Proxy
	resolver *fakeResolver
	network  *fakeNetwork
}

// newTestEnv starts a direct-mode guard. adjust may change its options.
func newTestEnv(t *testing.T, adjust func(*Options)) *testEnv {
	t.Helper()
	env := &testEnv{resolver: newFakeResolver(), network: newFakeNetwork()}
	opts := Options{Resolver: env.resolver, Dial: env.network.dial}
	if adjust != nil {
		adjust(&opts)
	}
	proxy, err := New(opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	env.proxy = proxy
	t.Cleanup(func() {
		if err := proxy.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return env
}

// connect opens a client connection to the guard.
func (e *testEnv) connect(t *testing.T) net.Conn {
	t.Helper()
	return dialTCP(t, e.proxy.Addr())
}

func dialTCP(t *testing.T, address string) net.Conn {
	t.Helper()
	dialer := net.Dialer{Timeout: testTimeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	return conn
}

// reply is the part of a response the tests look at.
type reply struct {
	status int
	body   string
}

// roundTrip writes raw to conn and reads one response head from it, plus the
// body when the response declares its length. Nothing beyond that is
// consumed, so the bytes of a tunnel that follow a 200 stay in reader.
func roundTrip(t *testing.T, conn net.Conn, reader *bufio.Reader, raw string) reply {
	t.Helper()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") {
		t.Fatalf("malformed status line %q", statusLine)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("malformed status in %q", statusLine)
	}

	length := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response header: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		name, value, _ := strings.Cut(line, ":")
		if strings.EqualFold(name, "Content-Length") {
			if length, err = strconv.Atoi(strings.TrimSpace(value)); err != nil {
				t.Fatalf("malformed Content-Length in %q", line)
			}
		}
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return reply{status: status, body: string(body)}
}

// rawServer is a TCP server whose handler sees the exact bytes the guard
// sent, which is what the header-preservation tests need.
type rawServer struct {
	listener net.Listener
	wg       sync.WaitGroup

	mu       sync.Mutex
	accepted int
}

// newRawServer starts a server that runs handle for each connection.
func newRawServer(t *testing.T, handle func(conn net.Conn)) *rawServer {
	t.Helper()
	var config net.ListenConfig
	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &rawServer{listener: listener}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.accepted++
			server.mu.Unlock()
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * testTimeout))
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		server.wg.Wait()
	})
	return server
}

func (s *rawServer) addr() string {
	return s.listener.Addr().String()
}

func (s *rawServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// readRawHead reads a request head (through the blank line) byte for byte.
func readRawHead(reader *bufio.Reader) (string, error) {
	var head strings.Builder
	for {
		line, err := reader.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			return head.String(), err
		}
		if line == "\r\n" {
			return head.String(), nil
		}
	}
}

// waitFor polls until condition holds or the test timeout passes.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// expectClosed asserts that the other side has closed conn.
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	// Bytes the proxy delivered before it closed (a response that was in
	// flight) are still readable; the connection is closed when reading ends.
	_, err := io.Copy(io.Discard, conn)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection was not closed (read timed out)")
	}
}

// settledGoroutines returns the goroutine count once it has stopped falling.
func settledGoroutines() int {
	count := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		next := runtime.NumGoroutine()
		if next >= count && i > 5 {
			return next
		}
		count = next
	}
	return count
}
