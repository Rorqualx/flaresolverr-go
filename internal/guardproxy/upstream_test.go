package guardproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Credentials the fake upstream proxies expect. Named neutrally: they are
// test fixtures, not secrets.
const (
	upstreamUser  = "guard-user"
	upstreamWord  = "s3cr3t-w0rd-7Q"
	wrongWord     = "n0t-the-w0rd-9Z"
	chainedTarget = "chained.test"
)

// echoServer returns a server that sends back whatever it receives.
func echoServer(t *testing.T) *rawServer {
	t.Helper()
	return newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
}

// fakeHTTPProxy is an upstream HTTP proxy that tunnels CONNECT requests to
// local backends and records what it was asked.
type fakeHTTPProxy struct {
	requireAuth bool

	mu       sync.Mutex
	backends map[string]string // CONNECT target -> real address
	targets  []string
	auths    []string
}

func (p *fakeHTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.targets = append(p.targets, r.Method+" "+r.RequestURI)
	p.auths = append(p.auths, r.Header.Get("Proxy-Authorization"))
	backend := p.backends[r.RequestURI]
	p.mu.Unlock()

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+upstreamWord))
	if p.requireAuth && r.Header.Get("Proxy-Authorization") != want {
		w.Header().Set("Proxy-Authenticate", `Basic realm="upstream"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect || backend == "" {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	var dialer net.Dialer
	origin, err := dialer.DialContext(r.Context(), "tcp", backend)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer origin.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(client, origin)
		_ = client.Close()
	}()
	_, _ = io.Copy(origin, buffered)
	_ = origin.Close()
	<-done
}

func (p *fakeHTTPProxy) seen() (targets, auths []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...), append([]string(nil), p.auths...)
}

// fakeSOCKS5 is an upstream SOCKS5 proxy with optional username/password
// authentication. It records the destinations it was asked for, exactly as
// they arrived (a name stays a name).
type fakeSOCKS5 struct {
	server      *rawServer
	requireAuth bool

	mu       sync.Mutex
	backends map[string]string
	targets  []string
}

func newFakeSOCKS5(t *testing.T, requireAuth bool, backends map[string]string) *fakeSOCKS5 {
	t.Helper()
	proxy := &fakeSOCKS5{requireAuth: requireAuth, backends: backends}
	proxy.server = newRawServer(t, proxy.handle)
	return proxy
}

func (p *fakeSOCKS5) handle(conn net.Conn) {
	reader := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	if p.requireAuth {
		if !bytes.Contains(methods, []byte{2}) {
			_, _ = conn.Write([]byte{5, 0xff})
			return
		}
		_, _ = conn.Write([]byte{5, 2})
		user, word, err := readSOCKS5Credentials(reader)
		if err != nil {
			return
		}
		if user != upstreamUser || word != upstreamWord {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		_, _ = conn.Write([]byte{1, 0})
	} else {
		_, _ = conn.Write([]byte{5, 0})
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil {
		return
	}
	var host string
	switch request[3] {
	case 1:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return
		}
		host = net.IP(raw).String()
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			return
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return
		}
		host = string(raw)
	case 4:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return
		}
		host = net.IP(raw).String()
	default:
		return
	}
	rawPort := make([]byte, 2)
	if _, err := io.ReadFull(reader, rawPort); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(rawPort[0])<<8|int(rawPort[1])))

	p.mu.Lock()
	p.targets = append(p.targets, target)
	backend := p.backends[target]
	p.mu.Unlock()

	var dialer net.Dialer
	origin, err := dialer.DialContext(context.Background(), "tcp", backend)
	if backend == "" || err != nil {
		_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer origin.Close()
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(conn, origin)
		_ = conn.Close()
	}()
	_, _ = io.Copy(origin, reader)
	_ = origin.Close()
	<-done
}

func readSOCKS5Credentials(reader *bufio.Reader) (user, word string, err error) {
	version, err := reader.ReadByte()
	if err != nil || version != 1 {
		return "", "", errors.New("bad auth version")
	}
	fields := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		length, err := reader.ReadByte()
		if err != nil {
			return "", "", err
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", "", err
		}
		fields = append(fields, string(raw))
	}
	return fields[0], fields[1], nil
}

func (p *fakeSOCKS5) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// chainedEnv is a manager with one lease on the listener for an upstream.
type chainedEnv struct {
	manager  *Manager
	lease    *Lease
	resolver *fakeResolver
}

func newChainedEnv(t *testing.T, upstream *Upstream, adjust func(*Options)) *chainedEnv {
	t.Helper()
	resolver := newFakeResolver()
	opts := Options{Resolver: resolver}
	if adjust != nil {
		adjust(&opts)
	}
	manager, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	lease, err := manager.Acquire(upstream)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	return &chainedEnv{manager: manager, lease: lease, resolver: resolver}
}

func (e *chainedEnv) connect(t *testing.T) net.Conn {
	t.Helper()
	return dialTCP(t, strings.TrimPrefix(e.lease.ProxyServer(), "http://"))
}

func mustUpstream(t *testing.T, rawURL, user, word string) *Upstream {
	t.Helper()
	upstream, err := ParseUpstream(rawURL, user, word)
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	return upstream
}

// expectEcho sends a probe through an established tunnel and expects it back.
func expectEcho(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	probe := []byte{0x16, 0x03, 0x01, 0x00, 0xff, 0x00, 0x0d, 0x0a, 0x80}
	if _, err := conn.Write(probe); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	got := make([]byte, len(probe))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if !bytes.Equal(got, probe) {
		t.Errorf("tunnel returned %v, want %v", got, probe)
	}
}

// assertNoCredentials fails if any of the texts contains a credential.
func assertNoCredentials(t *testing.T, texts ...string) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(upstreamUser + ":" + wrongWord))
	for _, text := range texts {
		for _, secret := range []string{upstreamWord, wrongWord, upstreamUser, encoded} {
			if strings.Contains(text, secret) {
				t.Errorf("credential %q leaked into %q", secret, text)
			}
		}
	}
}

func TestChained_HTTPUpstream(t *testing.T) {
	tests := []struct {
		name        string
		secure      bool // https upstream
		requireAuth bool
		user, word  string
		wantStatus  int
		wantAuth    string // Proxy-Authorization the upstream should receive
	}{
		{name: "http without auth", wantStatus: 200},
		{name: "http with auth", requireAuth: true, user: upstreamUser, word: upstreamWord, wantStatus: 200,
			wantAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+upstreamWord))},
		{name: "http wrong credentials", requireAuth: true, user: upstreamUser, word: wrongWord, wantStatus: 502,
			wantAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+wrongWord))},
		{name: "http missing credentials", requireAuth: true, wantStatus: 502},
		{name: "https without auth", secure: true, wantStatus: 200},
		{name: "https with auth", secure: true, requireAuth: true, user: upstreamUser, word: upstreamWord, wantStatus: 200,
			wantAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+upstreamWord))},
		{name: "https wrong credentials", secure: true, requireAuth: true, user: upstreamUser, word: wrongWord, wantStatus: 502,
			wantAuth: "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+wrongWord))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := echoServer(t)
			proxy := &fakeHTTPProxy{
				requireAuth: tt.requireAuth,
				backends:    map[string]string{chainedTarget + ":443": backend.addr()},
			}

			var server *httptest.Server
			var roots *x509.CertPool
			scheme := "http://"
			if tt.secure {
				server = httptest.NewTLSServer(proxy)
				roots = x509.NewCertPool()
				roots.AddCert(server.Certificate())
				scheme = "https://"
			} else {
				server = httptest.NewServer(proxy)
			}
			defer server.Close()

			upstream := mustUpstream(t, scheme+server.Listener.Addr().String(), tt.user, tt.word)
			env := newChainedEnv(t, upstream, func(o *Options) { o.UpstreamRootCAs = roots })

			conn := env.connect(t)
			reader := bufio.NewReader(conn)
			resp := roundTrip(t, conn, reader, "CONNECT "+chainedTarget+":443 HTTP/1.1\r\nHost: "+chainedTarget+":443\r\n\r\n")
			if resp.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", resp.status, tt.wantStatus, resp.body)
			}

			targets, auths := proxy.seen()
			if len(targets) != 1 || targets[0] != "CONNECT "+chainedTarget+":443" {
				t.Errorf("upstream was asked %v, want one CONNECT for the unresolved name", targets)
			}
			if len(auths) != 1 || auths[0] != tt.wantAuth {
				t.Errorf("upstream received Proxy-Authorization %q, want %q", auths, tt.wantAuth)
			}
			// The upstream resolves the name; the guard must not.
			if calls := env.resolver.callCount(chainedTarget); calls != 0 {
				t.Errorf("the guard resolved the name %d times in chained mode, want 0", calls)
			}

			if tt.wantStatus == 200 {
				expectEcho(t, conn, reader)
				if failures := env.lease.UpstreamAuthFailures(); failures != 0 {
					t.Errorf("UpstreamAuthFailures = %d, want 0", failures)
				}
				return
			}

			// A refusal is reported as such, without the credentials.
			if !strings.Contains(resp.body, "rejected the configured credentials") {
				t.Errorf("refusal body = %q, want it to name the credentials as the cause", resp.body)
			}
			assertNoCredentials(t, resp.body, env.lease.ProxyServer(), upstream.String())
			if failures := env.lease.UpstreamAuthFailures(); failures != 1 {
				t.Errorf("UpstreamAuthFailures = %d, want 1", failures)
			}
		})
	}
}

func TestChained_SOCKS5Upstream(t *testing.T) {
	tests := []struct {
		name        string
		requireAuth bool
		user, word  string
		wantStatus  int
	}{
		{name: "without auth", wantStatus: 200},
		{name: "with auth", requireAuth: true, user: upstreamUser, word: upstreamWord, wantStatus: 200},
		{name: "wrong credentials", requireAuth: true, user: upstreamUser, word: wrongWord, wantStatus: 502},
		{name: "missing credentials", requireAuth: true, wantStatus: 502},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := echoServer(t)
			proxy := newFakeSOCKS5(t, tt.requireAuth, map[string]string{chainedTarget + ":443": backend.addr()})

			upstream := mustUpstream(t, "socks5://"+proxy.server.addr(), tt.user, tt.word)
			env := newChainedEnv(t, upstream, nil)

			conn := env.connect(t)
			reader := bufio.NewReader(conn)
			resp := roundTrip(t, conn, reader, "CONNECT "+chainedTarget+":443 HTTP/1.1\r\n\r\n")
			if resp.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", resp.status, tt.wantStatus, resp.body)
			}
			if calls := env.resolver.callCount(chainedTarget); calls != 0 {
				t.Errorf("the guard resolved the name %d times in chained mode, want 0", calls)
			}

			if tt.wantStatus == 200 {
				// The proxy was given the name, not an address.
				if targets := proxy.seen(); len(targets) != 1 || targets[0] != chainedTarget+":443" {
					t.Errorf("SOCKS5 proxy was asked for %v, want the unresolved name", targets)
				}
				expectEcho(t, conn, reader)
				return
			}

			if !strings.Contains(resp.body, "rejected the configured credentials") {
				t.Errorf("refusal body = %q, want it to name the credentials as the cause", resp.body)
			}
			assertNoCredentials(t, resp.body, env.lease.ProxyServer(), upstream.String())
			if failures := env.lease.UpstreamAuthFailures(); failures != 1 {
				t.Errorf("UpstreamAuthFailures = %d, want 1", failures)
			}
			if targets := proxy.seen(); len(targets) != 0 {
				t.Errorf("SOCKS5 proxy connected to %v without valid credentials", targets)
			}
		})
	}
}

func TestChained_PlainHTTPThroughSOCKS5(t *testing.T) {
	received := make(chan string, 1)
	backend := newRawServer(t, func(conn net.Conn) {
		head, err := readRawHead(bufio.NewReader(conn))
		if err != nil {
			return
		}
		received <- head
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	proxy := newFakeSOCKS5(t, false, map[string]string{chainedTarget + ":80": backend.addr()})
	env := newChainedEnv(t, mustUpstream(t, "socks5://"+proxy.server.addr(), "", ""), nil)

	conn := env.connect(t)
	resp := roundTrip(t, conn, bufio.NewReader(conn),
		"GET http://"+chainedTarget+"/page HTTP/1.1\r\nHost: "+chainedTarget+"\r\nProxy-Connection: keep-alive\r\n\r\n")
	if resp.status != 200 || resp.body != "ok" {
		t.Fatalf("response = %+v, want 200 ok", resp)
	}

	// SOCKS leads to the destination itself, so the request is origin-form.
	want := "GET /page HTTP/1.1\r\nHost: " + chainedTarget + "\r\nConnection: keep-alive\r\n\r\n"
	select {
	case got := <-received:
		if got != want {
			t.Errorf("destination received %q, want %q", got, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("destination never received the request")
	}
}

func TestChained_PlainHTTPThroughHTTPUpstream(t *testing.T) {
	goodAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+upstreamWord))

	tests := []struct {
		name       string
		word       string
		wantStatus int
	}{
		{name: "accepted", word: upstreamWord, wantStatus: 200},
		{name: "wrong credentials", word: wrongWord, wantStatus: 502},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received := make(chan string, 1)
			upstreamProxy := newRawServer(t, func(conn net.Conn) {
				head, err := readRawHead(bufio.NewReader(conn))
				if err != nil {
					return
				}
				received <- head
				if !strings.Contains(head, "Proxy-Authorization: "+goodAuth+"\r\n") {
					_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
						"Proxy-Authenticate: Basic realm=\"upstream\"\r\nContent-Length: 0\r\n\r\n")
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			})

			upstream := mustUpstream(t, "http://"+upstreamProxy.addr(), upstreamUser, tt.word)
			env := newChainedEnv(t, upstream, nil)

			// The browser's own Proxy-Authorization (it has none to give, but a
			// page cannot be allowed to supply one) must not reach the upstream.
			request := "GET http://" + chainedTarget + "/page?q=1 HTTP/1.1\r\n" +
				"Host: " + chainedTarget + "\r\n" +
				"Proxy-Connection: keep-alive\r\n" +
				"Proxy-Authorization: Basic ZnJvbTpicm93c2Vy\r\n" +
				"zeta: 1\r\n" +
				"Accept: */*\r\n" +
				"\r\n"
			conn := env.connect(t)
			resp := roundTrip(t, conn, bufio.NewReader(conn), request)
			if resp.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.status, tt.wantStatus)
			}

			sentAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamUser+":"+tt.word))
			want := "GET http://" + chainedTarget + "/page?q=1 HTTP/1.1\r\n" +
				"Host: " + chainedTarget + "\r\n" +
				"Proxy-Connection: keep-alive\r\n" +
				"zeta: 1\r\n" +
				"Accept: */*\r\n" +
				"Proxy-Authorization: " + sentAuth + "\r\n" +
				"\r\n"
			select {
			case got := <-received:
				if got != want {
					t.Errorf("upstream received:\n%q\nwant:\n%q", got, want)
				}
			case <-time.After(testTimeout):
				t.Fatal("upstream never received the request")
			}

			if tt.wantStatus == 200 {
				if resp.body != "ok" {
					t.Errorf("body = %q, want ok", resp.body)
				}
				return
			}
			// The upstream's 407 must not reach the browser as a challenge.
			if !strings.Contains(resp.body, "rejected the configured credentials") {
				t.Errorf("refusal body = %q, want it to name the credentials as the cause", resp.body)
			}
			assertNoCredentials(t, resp.body)
			if failures := env.lease.UpstreamAuthFailures(); failures != 1 {
				t.Errorf("UpstreamAuthFailures = %d, want 1", failures)
			}
		})
	}
}

func TestChained_RefusesWhatItCanClassify(t *testing.T) {
	hosts := []struct {
		name string
		host string
	}{
		{name: "private literal", host: privateIP},
		{name: "loopback literal", host: "127.0.0.1"},
		{name: "cloud metadata", host: "169.254.169.254"},
		{name: "cgnat", host: "100.64.0.1"},
		{name: "octal host", host: "01230600002"},
		{name: "hex host", host: "0x7f000001"},
		{name: "ipv6 loopback", host: "[::1]"},
		{name: "ipv6 mapped private", host: "[::ffff:10.99.0.2]"},
		{name: "localhost", host: "localhost"},
		{name: "localhost subdomain", host: "app.localhost"},
		{name: "metadata name", host: "metadata.google.internal"},
	}
	forms := []struct {
		name    string
		request func(host string) string
	}{
		{name: "CONNECT", request: func(host string) string {
			return "CONNECT " + host + ":443 HTTP/1.1\r\n\r\n"
		}},
		{name: "absolute-form", request: func(host string) string {
			return "GET http://" + host + "/secret HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		}},
	}
	upstreams := []struct {
		name   string
		scheme string
	}{
		{name: "http upstream", scheme: "http://"},
		{name: "socks5 upstream", scheme: "socks5://"},
	}

	for _, up := range upstreams {
		// Whatever reaches the upstream is a failure, so it only counts.
		upstreamProxy := newRawServer(t, func(conn net.Conn) {
			_, _ = io.Copy(io.Discard, conn)
		})
		env := newChainedEnv(t, mustUpstream(t, up.scheme+upstreamProxy.addr(), "", ""), nil)

		for _, form := range forms {
			for _, host := range hosts {
				t.Run(up.name+"/"+form.name+"/"+host.name, func(t *testing.T) {
					conn := env.connect(t)
					resp := roundTrip(t, conn, bufio.NewReader(conn), form.request(host.host))
					if resp.status != http.StatusForbidden {
						t.Errorf("status = %d, want 403", resp.status)
					}
				})
			}
		}
		if got := upstreamProxy.connections(); got != 0 {
			t.Errorf("%s received %d connections for refused destinations, want 0", up.name, got)
		}
	}
}

func TestChained_RequirePublicUpstream(t *testing.T) {
	// The upstream proxy is on loopback. Marked as caller-supplied, the guard
	// must not connect to it, whatever its name resolved to earlier.
	upstreamProxy := newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})

	for _, scheme := range []string{"http://", "socks5://"} {
		t.Run(scheme, func(t *testing.T) {
			upstream := mustUpstream(t, scheme+upstreamProxy.addr(), "", "").RequirePublic()
			env := newChainedEnv(t, upstream, nil)

			conn := env.connect(t)
			resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT "+chainedTarget+":443 HTTP/1.1\r\n\r\n")
			if resp.status != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.status)
			}
		})
	}
	if got := upstreamProxy.connections(); got != 0 {
		t.Errorf("the loopback upstream received %d connections, want 0", got)
	}
}

func TestChained_UpstreamFailures(t *testing.T) {
	t.Run("upstream is down", func(t *testing.T) {
		dead := newRawServer(t, func(net.Conn) {})
		address := dead.addr()
		_ = dead.listener.Close()

		env := newChainedEnv(t, mustUpstream(t, "http://"+address, "", ""), nil)
		conn := env.connect(t)
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT "+chainedTarget+":443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", resp.status)
		}
	})

	t.Run("upstream refuses the destination", func(t *testing.T) {
		proxy := &fakeHTTPProxy{backends: map[string]string{}}
		server := httptest.NewServer(proxy)
		defer server.Close()

		env := newChainedEnv(t, mustUpstream(t, server.URL, "", ""), nil)
		conn := env.connect(t)
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT "+chainedTarget+":443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", resp.status)
		}
		if failures := env.lease.UpstreamAuthFailures(); failures != 0 {
			t.Errorf("UpstreamAuthFailures = %d for a non-auth failure, want 0", failures)
		}
	})

	t.Run("upstream answers garbage", func(t *testing.T) {
		garbage := newRawServer(t, func(conn net.Conn) {
			_, _ = io.WriteString(conn, strings.Repeat("x", 64<<10))
		})
		env := newChainedEnv(t, mustUpstream(t, "http://"+garbage.addr(), "", ""), nil)
		conn := env.connect(t)
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT "+chainedTarget+":443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", resp.status)
		}
	})

	t.Run("https upstream with an untrusted certificate", func(t *testing.T) {
		server := httptest.NewTLSServer(&fakeHTTPProxy{})
		defer server.Close()

		upstream := mustUpstream(t, "https://"+server.Listener.Addr().String(), "", "")
		env := newChainedEnv(t, upstream, nil) // system roots: the test certificate is unknown
		conn := env.connect(t)
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT "+chainedTarget+":443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", resp.status)
		}
	})
}

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		user, word  string
		wantString  string
		wantUser    string
		wantWord    string
		wantErr     bool
		wantErrText string
	}{
		{name: "http", url: "http://gw.example:8080", wantString: "http://gw.example:8080"},
		{name: "http default port", url: "http://gw.example", wantString: "http://gw.example:80"},
		{name: "https default port", url: "https://gw.example", wantString: "https://gw.example:443"},
		{name: "socks5 default port", url: "socks5://gw.example", wantString: "socks5://gw.example:1080"},
		{name: "socks5h", url: "socks5h://gw.example:9050", wantString: "socks5://gw.example:9050"},
		{name: "uppercase scheme", url: "HTTP://gw.example:3128", wantString: "http://gw.example:3128"},
		{name: "ipv6 host", url: "http://[2001:db8::1]:3128", wantString: "http://[2001:db8::1]:3128"},
		{name: "credentials in fields", url: "http://gw.example:8080", user: upstreamUser, word: upstreamWord,
			wantString: "http://gw.example:8080", wantUser: upstreamUser, wantWord: upstreamWord},
		{name: "credentials in url", url: "http://" + upstreamUser + ":" + upstreamWord + "@gw.example:8080",
			wantString: "http://gw.example:8080", wantUser: upstreamUser, wantWord: upstreamWord},
		{name: "fields win over url", url: "http://other:" + wrongWord + "@gw.example:8080", user: upstreamUser, word: upstreamWord,
			wantString: "http://gw.example:8080", wantUser: upstreamUser, wantWord: upstreamWord},
		{name: "socks4", url: "socks4://gw.example:1080", wantErr: true, wantErrText: "socks4"},
		{name: "socks4a", url: "socks4a://gw.example:1080", wantErr: true, wantErrText: "socks4"},
		{name: "ftp", url: "ftp://gw.example", wantErr: true},
		{name: "no scheme", url: "gw.example:8080", wantErr: true},
		{name: "no host", url: "http://:8080", wantErr: true},
		{name: "empty", url: "", wantErr: true},
		{name: "bad port", url: "http://gw.example:99999", wantErr: true},
		{name: "unparseable", url: "http://" + upstreamUser + ":" + upstreamWord + "@gw.example:80%zz", wantErr: true},
		{name: "socks4 with credentials", url: "socks4://" + upstreamUser + ":" + upstreamWord + "@gw.example:1080", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := ParseUpstream(tt.url, tt.user, tt.word)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseUpstream(%q) succeeded, want an error", tt.url)
				}
				if !errors.Is(err, ErrUnsupportedUpstream) {
					t.Errorf("error %v does not wrap ErrUnsupportedUpstream", err)
				}
				if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("error %q does not mention %q", err, tt.wantErrText)
				}
				assertNoCredentials(t, err.Error())
				return
			}
			if err != nil {
				t.Fatalf("ParseUpstream(%q) error = %v", tt.url, err)
			}
			if got := upstream.String(); got != tt.wantString {
				t.Errorf("String() = %q, want %q", got, tt.wantString)
			}
			if upstream.username != tt.wantUser || upstream.password != tt.wantWord {
				t.Errorf("credentials = %q/%q, want %q/%q", upstream.username, upstream.password, tt.wantUser, tt.wantWord)
			}
			assertNoCredentials(t, upstream.String())
		})
	}
}

func TestManager_ListenersAreSharedAndCounted(t *testing.T) {
	before := settledGoroutines()

	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}

	direct, err := manager.Acquire(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := manager.Stats().Listeners; got != 1 {
		t.Fatalf("Listeners = %d with only the direct listener, want 1", got)
	}

	first := mustUpstream(t, "http://gw-one.example:8080", upstreamUser, upstreamWord)
	sameAgain := mustUpstream(t, "http://gw-one.example:8080", upstreamUser, upstreamWord)
	otherWord := mustUpstream(t, "http://gw-one.example:8080", upstreamUser, wrongWord)
	otherHost := mustUpstream(t, "socks5://gw-two.example:1080", "", "")

	leaseA, err := manager.Acquire(first)
	if err != nil {
		t.Fatal(err)
	}
	leaseB, err := manager.Acquire(sameAgain)
	if err != nil {
		t.Fatal(err)
	}
	leaseC, err := manager.Acquire(otherWord)
	if err != nil {
		t.Fatal(err)
	}
	leaseD, err := manager.Acquire(otherHost)
	if err != nil {
		t.Fatal(err)
	}

	if leaseA.ProxyServer() != leaseB.ProxyServer() {
		t.Error("two leases for the same upstream and credentials got different listeners")
	}
	servers := map[string]bool{direct.ProxyServer(): true, leaseA.ProxyServer(): true, leaseC.ProxyServer(): true, leaseD.ProxyServer(): true}
	if len(servers) != 4 {
		t.Errorf("distinct upstreams share a listener: %v", servers)
	}
	for server := range servers {
		host, _, err := net.SplitHostPort(strings.TrimPrefix(server, "http://"))
		if err != nil || host != "127.0.0.1" {
			t.Errorf("listener %q is not a loopback address", server)
		}
		assertNoCredentials(t, server)
	}
	if got := manager.Stats().Listeners; got != 4 {
		t.Fatalf("Listeners = %d, want 4", got)
	}

	reachable := func(server string) bool {
		dialer := net.Dialer{Timeout: time.Second}
		conn, err := dialer.DialContext(context.Background(), "tcp", strings.TrimPrefix(server, "http://"))
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	// One of two leases gone: the listener stays.
	leaseA.Release()
	leaseA.Release() // releasing twice must not drop the second lease
	if got := manager.Stats().Listeners; got != 4 {
		t.Errorf("Listeners = %d after releasing one of two leases, want 4", got)
	}
	if !reachable(leaseB.ProxyServer()) {
		t.Error("the listener closed while a lease on it was still held")
	}

	// The last lease gone: the listener is closed.
	leaseB.Release()
	if got := manager.Stats().Listeners; got != 3 {
		t.Errorf("Listeners = %d after the last lease was released, want 3", got)
	}
	if reachable(leaseB.ProxyServer()) {
		t.Error("the listener still accepts connections after its last lease was released")
	}

	// Asking again starts a fresh one.
	leaseE, err := manager.Acquire(first)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable(leaseE.ProxyServer()) {
		t.Error("a re-acquired upstream has no listener")
	}

	// The direct listener is never closed by a release.
	direct.Release()
	if !reachable(direct.ProxyServer()) {
		t.Error("releasing a direct lease closed the direct listener")
	}

	if err := manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for _, server := range []string{direct.ProxyServer(), leaseC.ProxyServer(), leaseD.ProxyServer(), leaseE.ProxyServer()} {
		if reachable(server) {
			t.Errorf("listener %s still open after Close", server)
		}
	}
	// Leases outliving the manager are harmless.
	leaseC.Release()
	leaseD.Release()
	leaseE.Release()
	if _, err := manager.Acquire(first); !errors.Is(err, ErrClosed) {
		t.Errorf("Acquire after Close: error = %v, want ErrClosed", err)
	}
	if got := manager.Stats(); got.Listeners != 0 {
		t.Errorf("Stats after Close = %+v, want none", got)
	}

	waitFor(t, "goroutines to exit", func() bool { return settledGoroutines() <= before })
}

func TestManager_BoundsDistinctUpstreams(t *testing.T) {
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	leases := make([]*Lease, 0, maxUpstreamListeners)
	for i := 0; i < maxUpstreamListeners; i++ {
		lease, err := manager.Acquire(mustUpstream(t, "http://gw.example:"+strconv.Itoa(10000+i), "", ""))
		if err != nil {
			t.Fatalf("Acquire %d: %v", i, err)
		}
		leases = append(leases, lease)
	}
	if _, err := manager.Acquire(mustUpstream(t, "http://one-too-many.example:8080", "", "")); !errors.Is(err, ErrTooManyUpstreams) {
		t.Fatalf("Acquire past the limit: error = %v, want ErrTooManyUpstreams", err)
	}

	// An upstream already in use is still available at the limit.
	if lease, err := manager.Acquire(mustUpstream(t, "http://gw.example:10000", "", "")); err != nil {
		t.Errorf("Acquire of an in-use upstream at the limit: %v", err)
	} else {
		lease.Release()
	}

	// Releasing one makes room again.
	leases[0].Release()
	lease, err := manager.Acquire(mustUpstream(t, "http://one-too-many.example:8080", "", ""))
	if err != nil {
		t.Fatalf("Acquire after a release: %v", err)
	}
	lease.Release()
}

func TestManager_ConcurrentAcquireRelease(t *testing.T) {
	before := settledGoroutines()
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				upstream, err := ParseUpstream("http://gw.example:"+strconv.Itoa(20000+i%3), "", "")
				if err != nil {
					t.Error(err)
					return
				}
				lease, err := manager.Acquire(upstream)
				if err != nil {
					t.Error(err)
					return
				}
				_ = lease.ProxyServer()
				_ = manager.Stats()
				lease.Release()
			}
		}()
	}
	wg.Wait()

	if got := manager.Stats().Listeners; got != 1 {
		t.Errorf("Listeners = %d after every lease was released, want only the direct one", got)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "goroutines to exit", func() bool { return settledGoroutines() <= before })
}
