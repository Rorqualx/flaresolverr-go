package guardproxy

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestParseRequestLine(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantMethod string
		wantTarget string
		wantProto  string
		wantErr    bool
	}{
		{name: "connect", line: "CONNECT example.com:443 HTTP/1.1\r\n", wantMethod: "CONNECT", wantTarget: "example.com:443", wantProto: "HTTP/1.1"},
		{name: "get", line: "GET http://example.com/ HTTP/1.1\r\n", wantMethod: "GET", wantTarget: "http://example.com/", wantProto: "HTTP/1.1"},
		{name: "http 1.0", line: "GET http://example.com/ HTTP/1.0\r\n", wantMethod: "GET", wantTarget: "http://example.com/", wantProto: "HTTP/1.0"},
		{name: "bare line feed", line: "GET http://example.com/ HTTP/1.1\n", wantMethod: "GET", wantTarget: "http://example.com/", wantProto: "HTTP/1.1"},
		{name: "empty", line: "\r\n", wantErr: true},
		{name: "two parts", line: "GET http://example.com/\r\n", wantErr: true},
		{name: "four parts", line: "GET http://example.com/ extra HTTP/1.1\r\n", wantErr: true},
		{name: "double space", line: "GET  http://example.com/ HTTP/1.1\r\n", wantErr: true},
		{name: "lowercase method", line: "get http://example.com/ HTTP/1.1\r\n", wantErr: true},
		{name: "method with symbol", line: "GE-T http://example.com/ HTTP/1.1\r\n", wantErr: true},
		{name: "long method", line: strings.Repeat("A", 33) + " http://example.com/ HTTP/1.1\r\n", wantErr: true},
		{name: "http 2", line: "GET http://example.com/ HTTP/2.0\r\n", wantErr: true},
		{name: "http 0.9", line: "GET http://example.com/ HTTP/0.9\r\n", wantErr: true},
		{name: "tab in target", line: "GET http://exa\tmple.com/ HTTP/1.1\r\n", wantErr: true},
		{name: "nul in target", line: "GET http://exa\x00mple.com/ HTTP/1.1\r\n", wantErr: true},
		{name: "non-ascii target", line: "GET http://exämple.com/ HTTP/1.1\r\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, target, proto, err := parseRequestLine([]byte(tt.line))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseRequestLine(%q) error = %v, wantErr %v", tt.line, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if method != tt.wantMethod || target != tt.wantTarget || proto != tt.wantProto {
				t.Errorf("parseRequestLine(%q) = %q %q %q, want %q %q %q",
					tt.line, method, target, proto, tt.wantMethod, tt.wantTarget, tt.wantProto)
			}
		})
	}
}

func TestParseConnectTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "name and port", target: "example.com:443", wantHost: "example.com", wantPort: 443},
		{name: "uppercase name", target: "EXAMPLE.com:8443", wantHost: "example.com", wantPort: 8443},
		{name: "ipv4 literal", target: "93.184.216.34:443", wantHost: "93.184.216.34", wantPort: 443},
		{name: "ipv6 literal", target: "[2606:4700::1111]:443", wantHost: "2606:4700::1111", wantPort: 443},
		{name: "trailing dot", target: "example.com.:443", wantHost: "example.com.", wantPort: 443},
		{name: "max port", target: "example.com:65535", wantHost: "example.com", wantPort: 65535},
		{name: "no port", target: "example.com", wantErr: true},
		{name: "empty port", target: "example.com:", wantErr: true},
		{name: "port zero", target: "example.com:0", wantErr: true},
		{name: "port too large", target: "example.com:65536", wantErr: true},
		{name: "negative port", target: "example.com:-1", wantErr: true},
		{name: "signed port", target: "example.com:+443", wantErr: true},
		{name: "non-numeric port", target: "example.com:https", wantErr: true},
		{name: "empty host", target: ":443", wantErr: true},
		{name: "empty", target: "", wantErr: true},
		{name: "unbracketed ipv6", target: "2606:4700::1111:443", wantErr: true},
		{name: "ipv6 without port", target: "[2606:4700::1111]", wantErr: true},
		{name: "unterminated bracket", target: "[2606:4700::1111:443", wantErr: true},
		{name: "junk after bracket", target: "[::1]x:443", wantErr: true},
		{name: "brackets around name", target: "[example.com]:443", wantErr: true},
		{name: "ipv6 zone", target: "[fe80::1%eth0]:443", wantErr: true},
		{name: "userinfo", target: "user@example.com:443", wantErr: true},
		{name: "userinfo hiding host", target: "example.com:443@10.0.0.1:80", wantErr: true},
		{name: "path", target: "example.com:443/path", wantErr: true},
		{name: "backslash", target: "example.com\\@10.0.0.1:443", wantErr: true},
		{name: "percent", target: "exa%6dple.com:443", wantErr: true},
		{name: "absolute url", target: "http://example.com:443", wantErr: true},
		{name: "space", target: "example.com :443", wantErr: true},
		{name: "overlong host", target: strings.Repeat("a", 254) + ":443", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, err := parseConnectTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseConnectTarget(%q) = %+v, %v; wantErr %v", tt.target, dest, err, tt.wantErr)
			}
			if err != nil {
				if !errors.Is(err, errBadTarget) {
					t.Errorf("error %v does not wrap errBadTarget", err)
				}
				return
			}
			if dest.host != tt.wantHost || dest.port != tt.wantPort {
				t.Errorf("parseConnectTarget(%q) = %s port %d, want %s port %d",
					tt.target, dest.host, dest.port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestParseAbsoluteTarget(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantHost   string
		wantPort   int
		wantOrigin string
		wantErr    bool
	}{
		{name: "root", target: "http://example.com/", wantHost: "example.com", wantPort: 80, wantOrigin: "/"},
		{name: "no path", target: "http://example.com", wantHost: "example.com", wantPort: 80, wantOrigin: "/"},
		{name: "path and query", target: "http://example.com/a/b?c=d&e=%2F", wantHost: "example.com", wantPort: 80, wantOrigin: "/a/b?c=d&e=%2F"},
		{name: "query without path", target: "http://example.com?c=d", wantHost: "example.com", wantPort: 80, wantOrigin: "/?c=d"},
		{name: "port", target: "http://example.com:8080/x", wantHost: "example.com", wantPort: 8080, wantOrigin: "/x"},
		{name: "uppercase scheme and host", target: "HTTP://EXAMPLE.COM/Path", wantHost: "example.com", wantPort: 80, wantOrigin: "/Path"},
		{name: "ipv6", target: "http://[2606:4700::1111]:8080/x", wantHost: "2606:4700::1111", wantPort: 8080, wantOrigin: "/x"},
		{name: "ipv6 default port", target: "http://[2606:4700::1111]/x", wantHost: "2606:4700::1111", wantPort: 80, wantOrigin: "/x"},
		{name: "fragment dropped", target: "http://example.com/x#frag", wantHost: "example.com", wantPort: 80, wantOrigin: "/x"},
		{name: "fragment without path", target: "http://example.com#frag", wantHost: "example.com", wantPort: 80, wantOrigin: "/"},
		{name: "at sign in path is fine", target: "http://example.com/@10.0.0.1", wantHost: "example.com", wantPort: 80, wantOrigin: "/@10.0.0.1"},
		{name: "url in query is fine", target: "http://example.com/?u=http://10.0.0.1/", wantHost: "example.com", wantPort: 80, wantOrigin: "/?u=http://10.0.0.1/"},
		{name: "https", target: "https://example.com/", wantErr: true},
		{name: "ws", target: "ws://example.com/", wantErr: true},
		{name: "origin form", target: "/path", wantErr: true},
		{name: "asterisk", target: "*", wantErr: true},
		{name: "authority form", target: "example.com:80", wantErr: true},
		{name: "empty authority", target: "http:///path", wantErr: true},
		{name: "userinfo", target: "http://user:pass@example.com/", wantErr: true},
		{name: "userinfo hiding host", target: "http://example.com@10.0.0.1/", wantErr: true},
		{name: "backslash authority", target: "http://example.com\\@10.0.0.1/", wantErr: true},
		{name: "bad port", target: "http://example.com:99999/", wantErr: true},
		{name: "empty port", target: "http://example.com:/", wantErr: true},
		{name: "short", target: "http:/", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, origin, err := parseAbsoluteTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAbsoluteTarget(%q) = %+v, %q, %v; wantErr %v", tt.target, dest, origin, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if dest.host != tt.wantHost || dest.port != tt.wantPort || origin != tt.wantOrigin {
				t.Errorf("parseAbsoluteTarget(%q) = %s port %d %q, want %s port %d %q",
					tt.target, dest.host, dest.port, origin, tt.wantHost, tt.wantPort, tt.wantOrigin)
			}
		})
	}
}

func TestDestinationAddress(t *testing.T) {
	tests := []struct {
		dest destination
		want string
	}{
		{dest: destination{host: "example.com", port: 443}, want: "example.com:443"},
		{dest: destination{host: "93.184.216.34", port: 80}, want: "93.184.216.34:80"},
		{dest: destination{host: "2606:4700::1111", port: 443}, want: "[2606:4700::1111]:443"},
	}
	for _, tt := range tests {
		if got := tt.dest.address(); got != tt.want {
			t.Errorf("address() = %q, want %q", got, tt.want)
		}
	}
}

func TestParseHead_Limits(t *testing.T) {
	head := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-A: " + strings.Repeat("a", 100) + "\r\n\r\n"

	if _, err := parseHead(bufio.NewReader(strings.NewReader(head)), len(head)); err != nil {
		t.Errorf("a head of exactly the limit was refused: %v", err)
	}
	if _, err := parseHead(bufio.NewReader(strings.NewReader(head)), len(head)-1); !errors.Is(err, errHeadTooLarge) {
		t.Errorf("a head one byte over the limit: error = %v, want errHeadTooLarge", err)
	}

	// A line longer than the reader's buffer is still bounded by the budget.
	long := "GET http://example.com/ HTTP/1.1\r\nX-Long: " + strings.Repeat("b", 100000)
	if _, err := parseHead(bufio.NewReaderSize(strings.NewReader(long), 16), 8192); !errors.Is(err, errHeadTooLarge) {
		t.Errorf("an endless header line: error = %v, want errHeadTooLarge", err)
	}
}

// FuzzParseHead checks that no input makes the parser panic, read past its
// budget, or accept a destination that its own rules forbid.
func FuzzParseHead(f *testing.F) {
	seeds := []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
		"POST http://example.com/ HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
		"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"GET http://user@10.0.0.1/ HTTP/1.1\r\n\r\n",
		"CONNECT [::ffff:10.0.0.1]:443 HTTP/1.1\r\n\r\n",
		"CONNECT 01230600002:80 HTTP/1.1\r\n\r\n",
		"GET http://example.com\\@10.0.0.1/ HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\n\r\n",
		"\r\n\r\n",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	const budget = 4096
	f.Fuzz(func(t *testing.T, input string) {
		head, err := parseHead(bufio.NewReader(strings.NewReader(input)), budget)
		if err != nil {
			return
		}

		size := len(head.method) + len(head.target) + len(head.proto)
		for _, line := range head.lines {
			size += len(line)
		}
		if size > budget {
			t.Fatalf("accepted a %d-byte head with a %d-byte budget", size, budget)
		}
		if head.chunked && head.contentLength >= 0 {
			t.Fatal("accepted a head with both body framings")
		}

		var dest destination
		if head.method == methodConnect {
			dest, err = parseConnectTarget(head.target)
		} else {
			dest, _, err = parseAbsoluteTarget(head.target)
		}
		if err != nil {
			return
		}
		if dest.host == "" || dest.port < 1 || dest.port > 65535 {
			t.Fatalf("accepted destination %+v from target %q", dest, head.target)
		}
		if strings.ContainsAny(dest.host, "@/\\?#% \t\r\n[]") || dest.host != strings.ToLower(dest.host) {
			t.Fatalf("accepted host %q from target %q", dest.host, head.target)
		}
		// What is rendered onwards never carries the proxy credentials.
		out := string(buildHead(head, "/", false, nil))
		if strings.Contains(strings.ToLower(out), "\nproxy-authorization:") {
			t.Fatalf("Proxy-Authorization survived into %q", out)
		}
	})
}
