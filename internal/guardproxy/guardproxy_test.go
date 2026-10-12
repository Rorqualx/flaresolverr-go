package guardproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConnect_TunnelsBytesUnmodified(t *testing.T) {
	// Both ends send bytes that are not valid text, HTTP or TLS, so anything
	// that inspected or rewrote the stream would corrupt them.
	fromClient := make([]byte, 1<<20)
	fromServer := make([]byte, 1<<20)
	if _, err := rand.Read(fromClient); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(fromServer); err != nil {
		t.Fatal(err)
	}

	serverGot := make(chan []byte, 1)
	origin := newRawServer(t, func(conn net.Conn) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = conn.Write(fromServer)
		}()
		got := make([]byte, len(fromClient))
		_, _ = io.ReadFull(conn, got)
		wg.Wait()
		serverGot <- got
	})

	env := newTestEnv(t, nil)
	env.resolver.set("public.test", []string{publicIP})
	env.network.route(publicIP+":443", origin.addr())

	conn := env.connect(t)
	reader := bufio.NewReader(conn)
	resp := roundTrip(t, conn, reader, "CONNECT public.test:443 HTTP/1.1\r\nHost: public.test:443\r\n\r\n")
	if resp.status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.status)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(fromClient)
		writeDone <- err
	}()
	clientGot := make([]byte, len(fromServer))
	if _, err := io.ReadFull(reader, clientGot); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write tunnel: %v", err)
	}

	if !bytes.Equal(clientGot, fromServer) {
		t.Error("bytes from the server were modified in the tunnel")
	}
	select {
	case got := <-serverGot:
		if !bytes.Equal(got, fromClient) {
			t.Error("bytes from the client were modified in the tunnel")
		}
	case <-time.After(testTimeout):
		t.Fatal("server never received the client's bytes")
	}

	if got := env.network.dials(); len(got) != 1 || got[0] != publicIP+":443" {
		t.Errorf("dialed %v, want only the validated literal %s:443", got, publicIP)
	}
	if stats := env.proxy.Stats(); stats.Tunnels != 1 || stats.Blocked != 0 {
		t.Errorf("stats = %+v, want 1 tunnel and nothing blocked", stats)
	}
}

func TestPlainHTTP_PreservesHeaderBytesAndOrder(t *testing.T) {
	const response = "HTTP/1.1 200 OK\r\nX-Zeta: 1\r\nContent-Length: 5\r\nx-alpha: 2\r\n\r\nhello"

	received := make(chan string, 1)
	origin := newRawServer(t, func(conn net.Conn) {
		head, err := readRawHead(bufio.NewReader(conn))
		if err != nil {
			return
		}
		received <- head
		_, _ = io.WriteString(conn, response)
	})

	env := newTestEnv(t, nil)
	env.resolver.set("plain.test", []string{publicIP})
	env.network.route(publicIP+":8080", origin.addr())

	// Deliberately unsorted, mixed-case, with a duplicate: a proxy built on
	// net/http would canonicalize, sort and merge these.
	request := "GET http://plain.test:8080/a/b?x=1&y=%20z HTTP/1.1\r\n" +
		"Host: plain.test:8080\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"zeta-header: last-first\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n" +
		"accept: text/html\r\n" +
		"X-Dup: one\r\n" +
		"Proxy-Authorization: Basic c2hvdWxkOm5vdGxlYWs=\r\n" +
		"X-Dup: two\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"\r\n"
	want := "GET /a/b?x=1&y=%20z HTTP/1.1\r\n" +
		"Host: plain.test:8080\r\n" +
		"Connection: keep-alive\r\n" +
		"zeta-header: last-first\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n" +
		"accept: text/html\r\n" +
		"X-Dup: one\r\n" +
		"X-Dup: two\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"\r\n"

	conn := env.connect(t)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		if got != want {
			t.Errorf("origin received:\n%q\nwant:\n%q", got, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("origin never received the request")
	}

	// The response comes back byte for byte too.
	got := make([]byte, len(response))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != response {
		t.Errorf("client received %q, want %q", got, response)
	}
}

func TestRefusesNonPublicDestinations(t *testing.T) {
	destinations := []struct {
		name string
		host string // as it appears in the request target
	}{
		{name: "private literal", host: privateIP},
		{name: "loopback literal", host: "127.0.0.1"},
		{name: "loopback range", host: "127.8.8.8"},
		{name: "cloud metadata", host: "169.254.169.254"},
		{name: "alibaba metadata", host: "100.100.100.200"},
		{name: "cgnat", host: "100.64.0.1"},
		{name: "octal host", host: "01230600002"},
		{name: "dotted octal", host: "0177.0.0.1"},
		{name: "hex host", host: "0x7f000001"},
		{name: "decimal host", host: "2130706433"},
		{name: "short form", host: "127.1"},
		{name: "ipv6 loopback", host: "[::1]"},
		{name: "ipv6 mapped private", host: "[::ffff:10.99.0.2]"},
		{name: "ipv6 mapped loopback", host: "[::ffff:7f00:1]"},
		{name: "ipv6 unique local", host: "[fd00::1]"},
		{name: "nat64 private", host: "[64:ff9b::a63:2]"},
		{name: "unspecified", host: "0.0.0.0"},
		{name: "localhost", host: "localhost"},
		{name: "localhost uppercase", host: "LOCALHOST"},
		{name: "localhost trailing dot", host: "localhost."},
		{name: "localhost subdomain", host: "app.localhost"},
		{name: "metadata name", host: "metadata.google.internal"},
		{name: "name resolving private", host: "private.test"},
		{name: "name resolving loopback", host: "loop.test"},
		{name: "name resolving metadata", host: "meta.test"},
		{name: "name resolving cgnat", host: "cgnat.test"},
		{name: "name resolving mapped", host: "mapped.test"},
		{name: "name with one private answer", host: "mixed.test"},
	}
	forms := []struct {
		name    string
		request func(host string) string
	}{
		{name: "CONNECT", request: func(host string) string {
			return "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n\r\n"
		}},
		{name: "absolute-form", request: func(host string) string {
			return "GET http://" + host + "/secret HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		}},
	}

	for _, form := range forms {
		for _, dest := range destinations {
			t.Run(form.name+"/"+dest.name, func(t *testing.T) {
				env := newTestEnv(t, nil)
				env.resolver.set("private.test", []string{privateIP})
				env.resolver.set("loop.test", []string{"127.0.0.1"})
				env.resolver.set("meta.test", []string{"169.254.169.254"})
				env.resolver.set("cgnat.test", []string{"100.64.0.9"})
				env.resolver.set("mapped.test", []string{"::ffff:10.99.0.2"})
				env.resolver.set("mixed.test", []string{publicIP, privateIP})

				conn := env.connect(t)
				resp := roundTrip(t, conn, bufio.NewReader(conn), form.request(dest.host))
				if resp.status != http.StatusForbidden {
					t.Errorf("status = %d, want 403", resp.status)
				}
				if dialed := env.network.dials(); len(dialed) != 0 {
					t.Errorf("the guard dialed %v for a refused destination", dialed)
				}
				if stats := env.proxy.Stats(); stats.Blocked != 1 {
					t.Errorf("Blocked = %d, want 1", stats.Blocked)
				}
			})
		}
	}
}

func TestRebinding_DialsTheAnswerItValidated(t *testing.T) {
	origin := newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})

	env := newTestEnv(t, nil)
	// A rebinding name: public when it is checked, private the next time it
	// is asked about.
	env.resolver.set("rebind.test", []string{publicIP}, []string{privateIP})
	env.network.route(publicIP+":443", origin.addr())

	conn := env.connect(t)
	resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT rebind.test:443 HTTP/1.1\r\nHost: rebind.test:443\r\n\r\n")
	if resp.status != http.StatusOK {
		t.Fatalf("first CONNECT status = %d, want 200", resp.status)
	}
	if calls := env.resolver.callCount("rebind.test"); calls != 1 {
		t.Errorf("the name was resolved %d times for one connection, want exactly 1", calls)
	}
	if dialed := env.network.dials(); len(dialed) != 1 || dialed[0] != publicIP+":443" {
		t.Errorf("dialed %v, want only the validated answer %s:443", dialed, publicIP)
	}

	// The next connection sees the rebound answer and is refused outright.
	second := env.connect(t)
	resp2 := roundTrip(t, second, bufio.NewReader(second), "CONNECT rebind.test:443 HTTP/1.1\r\nHost: rebind.test:443\r\n\r\n")
	if resp2.status != http.StatusForbidden {
		t.Errorf("second CONNECT status = %d, want 403", resp2.status)
	}
	if dialed := env.network.dials(); len(dialed) != 1 {
		t.Errorf("dialed %v after rebinding, want no further dial", dialed)
	}
}

func TestPlainHTTP_ReusedConnectionIsCheckedPerRequest(t *testing.T) {
	var mu sync.Mutex
	var heads []string
	origin := newRawServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		for {
			head, err := readRawHead(reader)
			if err != nil {
				return
			}
			mu.Lock()
			heads = append(heads, head)
			mu.Unlock()
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})

	env := newTestEnv(t, nil)
	env.resolver.set("one.test", []string{publicIP})
	env.resolver.set("two.test", []string{otherPublicIP})
	env.network.route(publicIP+":80", origin.addr())
	env.network.route(otherPublicIP+":80", origin.addr())

	conn := env.connect(t)
	reader := bufio.NewReader(conn)

	if got := roundTrip(t, conn, reader, "GET http://one.test/1 HTTP/1.1\r\nHost: one.test\r\n\r\n"); got.body != "ok" {
		t.Fatalf("response body = %q, want ok", got.body)
	}

	// Same destination: the origin connection is reused, not redialed.
	if got := roundTrip(t, conn, reader, "GET http://one.test/2 HTTP/1.1\r\nHost: one.test\r\n\r\n"); got.body != "ok" {
		t.Fatalf("response body = %q, want ok", got.body)
	}
	if dialed := env.network.dials(); len(dialed) != 1 {
		t.Fatalf("dialed %v for two requests to one host, want one dial", dialed)
	}

	// Another public destination on the same client connection is dialed anew.
	if got := roundTrip(t, conn, reader, "GET http://two.test/3 HTTP/1.1\r\nHost: two.test\r\n\r\n"); got.body != "ok" {
		t.Fatalf("response body = %q, want ok", got.body)
	}
	if dialed := env.network.dials(); len(dialed) != 2 || dialed[1] != otherPublicIP+":80" {
		t.Fatalf("dialed %v, want a second dial to %s:80", dialed, otherPublicIP)
	}

	// A private destination on the same connection is refused, and must not
	// ride the connection that is already open to a public host.
	blocked := roundTrip(t, conn, reader, "GET http://"+privateIP+"/internal HTTP/1.1\r\nHost: "+privateIP+"\r\n\r\n")
	if blocked.status != http.StatusForbidden {
		t.Errorf("status for the private destination = %d, want 403", blocked.status)
	}
	if dialed := env.network.dials(); len(dialed) != 2 {
		t.Errorf("dialed %v, want no dial for the private destination", dialed)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(heads) != 3 {
		t.Fatalf("origin saw %d requests, want 3", len(heads))
	}
	for _, head := range heads {
		if strings.Contains(head, "/internal") || strings.Contains(head, privateIP) {
			t.Errorf("the refused request reached an origin: %q", head)
		}
	}
}

func TestPlainHTTP_ForwardsRequestBodies(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    string
	}{
		{
			name: "content-length",
			request: "POST http://body.test/submit HTTP/1.1\r\nHost: body.test\r\nContent-Length: 11\r\n\r\n" +
				"hello=world",
			want: "POST /submit HTTP/1.1\r\nHost: body.test\r\nContent-Length: 11\r\n\r\n" +
				"hello=world",
		},
		{
			name: "chunked with extension and trailer",
			request: "POST http://body.test/submit HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
			want: "POST /submit HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A second request follows on the same connection: the body must
			// have been delimited correctly for it to be parsed at all.
			const followUp = "GET /after HTTP/1.1\r\nHost: body.test\r\n\r\n"
			received := make(chan string, 1)
			origin := newRawServer(t, func(conn net.Conn) {
				got := make([]byte, len(tt.want))
				if _, err := io.ReadFull(conn, got); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				next := make([]byte, len(followUp))
				if _, err := io.ReadFull(conn, next); err != nil {
					return
				}
				received <- string(got) + string(next)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			})

			env := newTestEnv(t, nil)
			env.resolver.set("body.test", []string{publicIP})
			env.network.route(publicIP+":80", origin.addr())

			conn := env.connect(t)
			reader := bufio.NewReader(conn)
			roundTrip(t, conn, reader, tt.request)
			roundTrip(t, conn, reader, "GET http://body.test/after HTTP/1.1\r\nHost: body.test\r\n\r\n")

			select {
			case got := <-received:
				if got != tt.want+followUp {
					t.Errorf("origin received:\n%q\nwant:\n%q", got, tt.want+followUp)
				}
			case <-time.After(testTimeout):
				t.Fatal("origin never received both requests")
			}
		})
	}
}

func TestPlainHTTP_UpgradeBecomesByteRelay(t *testing.T) {
	origin := newRawServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		if _, err := readRawHead(reader); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		// Echo whatever follows: it is no longer HTTP.
		_, _ = io.Copy(conn, reader)
	})

	env := newTestEnv(t, nil)
	env.resolver.set("ws.test", []string{publicIP})
	env.network.route(publicIP+":80", origin.addr())

	conn := env.connect(t)
	reader := bufio.NewReader(conn)
	resp := roundTrip(t, conn, reader, "GET http://ws.test/socket HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if resp.status != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.status)
	}

	frame := []byte{0x81, 0x85, 0x00, 0xff, 0x0a, 0x0d, 0x10, 0x00, 0x7f}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(frame))
	if _, err := io.ReadFull(reader, echoed); err != nil {
		t.Fatalf("read echoed frame: %v", err)
	}
	if !bytes.Equal(echoed, frame) {
		t.Errorf("echoed %v, want %v", echoed, frame)
	}
}

func TestMalformedRequestsAreRejected(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		wantStatus int
	}{
		{name: "not http", request: "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 \r\n\r\n", wantStatus: 400},
		{name: "origin-form target", request: "GET /path HTTP/1.1\r\nHost: public.test\r\n\r\n", wantStatus: 400},
		{name: "https absolute target", request: "GET https://public.test/ HTTP/1.1\r\nHost: public.test\r\n\r\n", wantStatus: 400},
		{name: "userinfo in target", request: "GET http://public.test@" + privateIP + "/ HTTP/1.1\r\nHost: x\r\n\r\n", wantStatus: 400},
		{name: "connect without port", request: "CONNECT public.test HTTP/1.1\r\nHost: public.test\r\n\r\n", wantStatus: 400},
		{name: "connect port zero", request: "CONNECT public.test:0 HTTP/1.1\r\n\r\n", wantStatus: 400},
		{name: "connect port too large", request: "CONNECT public.test:70000 HTTP/1.1\r\n\r\n", wantStatus: 400},
		{name: "http/2 preface", request: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", wantStatus: 400},
		{name: "length and chunked", request: "POST http://public.test/ HTTP/1.1\r\nHost: public.test\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", wantStatus: 400},
		{name: "conflicting lengths", request: "POST http://public.test/ HTTP/1.1\r\nHost: public.test\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", wantStatus: 400},
		{name: "signed length", request: "POST http://public.test/ HTTP/1.1\r\nHost: public.test\r\nContent-Length: +3\r\n\r\n", wantStatus: 400},
		{name: "folded header", request: "GET http://public.test/ HTTP/1.1\r\nHost: public.test\r\n folded: yes\r\n\r\n", wantStatus: 400},
		{name: "space before colon", request: "GET http://public.test/ HTTP/1.1\r\nHost : public.test\r\n\r\n", wantStatus: 400},
		{name: "oversized head", request: "GET http://public.test/ HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 4096) + "\r\n\r\n", wantStatus: 431},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t, func(o *Options) { o.MaxHeaderBytes = 2048 })
			env.resolver.set("public.test", []string{publicIP})

			conn := env.connect(t)
			resp := roundTrip(t, conn, bufio.NewReader(conn), tt.request)
			if resp.status != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.status, tt.wantStatus)
			}
			if dialed := env.network.dials(); len(dialed) != 0 {
				t.Errorf("the guard dialed %v for a malformed request", dialed)
			}
		})
	}
}

// peerConn is a connection that reports a chosen remote address.
type peerConn struct {
	net.Conn
	remote net.Addr
}

func (c *peerConn) RemoteAddr() net.Addr {
	return c.remote
}

func TestRefusesNonLoopbackPeer(t *testing.T) {
	tests := []struct {
		name   string
		remote net.Addr
		refuse bool
	}{
		{name: "ipv4 loopback", remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}},
		{name: "ipv6 loopback", remote: &net.TCPAddr{IP: net.IPv6loopback, Port: 40000}},
		{name: "lan address", remote: &net.TCPAddr{IP: net.ParseIP("192.168.50.20"), Port: 40000}, refuse: true},
		{name: "docker bridge", remote: &net.TCPAddr{IP: net.ParseIP("172.17.0.1"), Port: 40000}, refuse: true},
		{name: "public address", remote: &net.TCPAddr{IP: net.ParseIP(publicIP), Port: 40000}, refuse: true},
		{name: "unix socket", remote: &net.UnixAddr{Name: "/tmp/x", Net: "unix"}, refuse: true},
		{name: "no ip", remote: &net.TCPAddr{}, refuse: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin := newRawServer(t, func(conn net.Conn) {
				_, _ = io.Copy(io.Discard, conn)
			})
			env := newTestEnv(t, nil)
			env.resolver.set("public.test", []string{publicIP})
			env.network.route(publicIP+":443", origin.addr())

			clientSide, guardSide := net.Pipe()
			defer clientSide.Close()
			served := make(chan struct{})
			go func() {
				defer close(served)
				env.proxy.serveConn(&peerConn{Conn: guardSide, remote: tt.remote})
			}()

			_ = clientSide.SetDeadline(time.Now().Add(testTimeout))
			go func() {
				_, _ = io.WriteString(clientSide, "CONNECT public.test:443 HTTP/1.1\r\n\r\n")
			}()

			if tt.refuse {
				// Closed without a byte: not even an error response is sent.
				expectClosed(t, clientSide)
				<-served
				if dialed := env.network.dials(); len(dialed) != 0 {
					t.Errorf("dialed %v for a refused peer", dialed)
				}
				if stats := env.proxy.Stats(); stats.RejectedPeers != 1 || stats.Accepted != 0 {
					t.Errorf("stats = %+v, want 1 rejected peer and nothing accepted", stats)
				}
				return
			}

			statusLine, err := bufio.NewReader(clientSide).ReadString('\n')
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if !strings.HasPrefix(statusLine, "HTTP/1.1 200 ") {
				t.Errorf("status line = %q, want 200", statusLine)
			}
			_ = clientSide.Close()
			<-served
		})
	}
}

func TestListenerIsLoopbackOnly(t *testing.T) {
	env := newTestEnv(t, nil)
	host, _, err := net.SplitHostPort(env.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Errorf("listener bound to %s, want 127.0.0.1", host)
	}
	if got, want := env.proxy.ProxyServer(), "http://"+env.proxy.Addr(); got != want {
		t.Errorf("ProxyServer() = %q, want %q", got, want)
	}
}

func TestDefaultDialerRefusesLoopbackEvenIfResolved(t *testing.T) {
	// No fake network here: the real dialer, with a resolver and a validator
	// that both wrongly approve, must still refuse at the socket.
	local := newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})
	_, port, err := net.SplitHostPort(local.addr())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		validateIP func(net.IP) error // nil = the real rules
		wantStatus int
		wantConns  int
	}{
		{name: "real rules", wantStatus: http.StatusForbidden},
		{name: "rules disabled", validateIP: func(net.IP) error { return nil }, wantStatus: http.StatusOK, wantConns: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := local.connections()
			resolver := newFakeResolver()
			resolver.set("sneaky.test", []string{"127.0.0.1"})
			proxy, err := New(Options{Resolver: resolver, ValidateIP: tt.validateIP})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()

			conn := dialTCP(t, proxy.Addr())
			resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT sneaky.test:"+port+" HTTP/1.1\r\n\r\n")
			if resp.status != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.status, tt.wantStatus)
			}
			if tt.wantConns > 0 {
				waitFor(t, "the local server to be reached", func() bool {
					return local.connections()-before == tt.wantConns
				})
				return
			}
			if got := local.connections() - before; got != 0 {
				t.Errorf("the loopback server received %d connections, want 0", got)
			}
		})
	}
}

func TestCheckSocketAddress(t *testing.T) {
	approve := func(net.IP) error { return nil }
	deny := func(net.IP) error { return errors.New("denied") }
	tests := []struct {
		name     string
		address  string
		validate func(net.IP) error
		wantErr  bool
	}{
		{name: "approved literal", address: publicIP + ":443", validate: approve},
		{name: "approved v6 literal", address: "[2606:4700::1111]:443", validate: approve},
		{name: "denied literal", address: privateIP + ":80", validate: deny, wantErr: true},
		{name: "hostname", address: "example.com:443", validate: approve, wantErr: true},
		{name: "no port", address: publicIP, validate: approve, wantErr: true},
		{name: "empty", address: "", validate: approve, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSocketAddress(tt.address, tt.validate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkSocketAddress(%q) = %v, wantErr %v", tt.address, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrBlocked) {
				t.Errorf("error %v does not wrap ErrBlocked", err)
			}
		})
	}
}

func TestUnresolvableAndUnreachableDestinations(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "unknown name", target: "nxdomain.test:443"},
		{name: "no route", target: "unrouted.test:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t, nil)
			env.resolver.set("unrouted.test", []string{publicIP, otherPublicIP})

			conn := env.connect(t)
			resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT "+tt.target+" HTTP/1.1\r\n\r\n")
			if resp.status != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", resp.status)
			}
			if stats := env.proxy.Stats(); stats.Failed != 1 || stats.Blocked != 0 {
				t.Errorf("stats = %+v, want 1 failed and 0 blocked", stats)
			}
		})
	}
}

func TestDialFallsBackToNextValidatedAddress(t *testing.T) {
	origin := newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})
	env := newTestEnv(t, nil)
	env.resolver.set("multi.test", []string{publicIP, otherPublicIP})
	env.network.route(otherPublicIP+":443", origin.addr()) // the first answer is dead

	conn := env.connect(t)
	resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT multi.test:443 HTTP/1.1\r\n\r\n")
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.status)
	}
	want := []string{publicIP + ":443", otherPublicIP + ":443"}
	if got := env.network.dials(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("dialed %v, want %v", got, want)
	}
}

func TestConnectionLimit(t *testing.T) {
	origin := newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})
	env := newTestEnv(t, func(o *Options) { o.MaxConns = 2 })
	env.resolver.set("public.test", []string{publicIP})
	env.network.route(publicIP+":443", origin.addr())

	for i := 0; i < 2; i++ {
		conn := env.connect(t)
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT public.test:443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusOK {
			t.Fatalf("tunnel %d status = %d, want 200", i, resp.status)
		}
	}

	extra := env.connect(t)
	expectClosed(t, extra)
	if stats := env.proxy.Stats(); stats.RejectedBusy != 1 || stats.Active != 2 {
		t.Errorf("stats = %+v, want 1 rejected at the limit and 2 active", stats)
	}
}

func TestTimeouts(t *testing.T) {
	t.Run("idle tunnel is closed", func(t *testing.T) {
		origin := newRawServer(t, func(conn net.Conn) {
			_, _ = io.Copy(io.Discard, conn)
		})
		env := newTestEnv(t, func(o *Options) { o.IdleTimeout = 100 * time.Millisecond })
		env.resolver.set("public.test", []string{publicIP})
		env.network.route(publicIP+":443", origin.addr())

		conn := env.connect(t)
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT public.test:443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.status)
		}
		expectClosed(t, conn)
		waitFor(t, "the connection to be released", func() bool { return env.proxy.Stats().Active == 0 })
	})

	t.Run("one quiet direction does not end a busy tunnel", func(t *testing.T) {
		// The server streams for several idle periods while the client sends
		// nothing at all.
		const total = 12
		origin := newRawServer(t, func(conn net.Conn) {
			for i := 0; i < total; i++ {
				if _, err := conn.Write([]byte{byte(i)}); err != nil {
					return
				}
				time.Sleep(40 * time.Millisecond)
			}
		})
		env := newTestEnv(t, func(o *Options) { o.IdleTimeout = 120 * time.Millisecond })
		env.resolver.set("public.test", []string{publicIP})
		env.network.route(publicIP+":443", origin.addr())

		conn := env.connect(t)
		reader := bufio.NewReader(conn)
		resp := roundTrip(t, conn, reader, "CONNECT public.test:443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.status)
		}
		got := make([]byte, total)
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatalf("stream cut short after %v: %v", got, err)
		}
	})

	t.Run("slow request head is dropped", func(t *testing.T) {
		env := newTestEnv(t, func(o *Options) { o.HeaderTimeout = 100 * time.Millisecond })
		conn := env.connect(t)
		if _, err := io.WriteString(conn, "CONNECT public.test:443 HTT"); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, conn)
	})

	t.Run("slow destination is abandoned", func(t *testing.T) {
		env := newTestEnv(t, func(o *Options) {
			o.DialTimeout = 100 * time.Millisecond
			o.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		})
		env.resolver.set("slow.test", []string{publicIP})

		conn := env.connect(t)
		started := time.Now()
		resp := roundTrip(t, conn, bufio.NewReader(conn), "CONNECT slow.test:443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", resp.status)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("gave up after %v, want about the dial timeout", elapsed)
		}
	})
}

func TestClose_StopsEverything(t *testing.T) {
	origin := newRawServer(t, func(conn net.Conn) {
		_, _ = io.Copy(io.Discard, conn)
	})
	before := settledGoroutines()

	resolver := newFakeResolver()
	resolver.set("public.test", []string{publicIP})
	network := newFakeNetwork()
	network.route(publicIP+":443", origin.addr())
	network.route(publicIP+":80", origin.addr())
	proxy, err := New(Options{Resolver: resolver, Dial: network.dial})
	if err != nil {
		t.Fatal(err)
	}

	// Leave connections in every state: an open tunnel, a plain connection
	// with a request in flight, one that has sent nothing, and half a head.
	var clients []net.Conn
	for i := 0; i < 5; i++ {
		tunnel := dialTCP(t, proxy.Addr())
		resp := roundTrip(t, tunnel, bufio.NewReader(tunnel), "CONNECT public.test:443 HTTP/1.1\r\n\r\n")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.status)
		}
		clients = append(clients, tunnel)

		plain := dialTCP(t, proxy.Addr())
		if _, err := io.WriteString(plain, "GET http://public.test/ HTTP/1.1\r\nHost: public.test\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		silent := dialTCP(t, proxy.Addr())
		partial := dialTCP(t, proxy.Addr())
		if _, err := io.WriteString(partial, "GET http://public.test/ HTTP/1.1\r\nHos"); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, plain, silent, partial)
	}
	waitFor(t, "all connections to be accepted", func() bool { return proxy.Stats().Active == 20 })

	if err := proxy.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	if active := proxy.Stats().Active; active != 0 {
		t.Errorf("Active = %d after Close, want 0", active)
	}
	for _, client := range clients {
		expectClosed(t, client)
	}

	// The listener is gone.
	dialer := net.Dialer{Timeout: time.Second}
	if conn, err := dialer.DialContext(context.Background(), "tcp", proxy.Addr()); err == nil {
		_ = conn.Close()
		t.Error("the listener still accepts connections after Close")
	}

	// Close waited for every goroutine: none of the proxy's are left. The
	// origin's handlers finish when their connections close.
	waitFor(t, "goroutines to exit", func() bool { return settledGoroutines() <= before+1 })
}
