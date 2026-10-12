package guardproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	methodConnect      = "CONNECT"
	connectEstablished = "HTTP/1.1 200 Connection established\r\n\r\n"

	maxMethodLength = 32
	maxHostLength   = 253
	httpScheme      = "http://"
	defaultHTTPPort = 80

	// maxChunkLineBytes bounds one chunk-size line or trailer line of a
	// chunked request body.
	maxChunkLineBytes = 4 << 10
)

// Errors for a request the guard cannot parse. None of them reaches a
// destination.
var (
	errHeadTooLarge  = errors.New("request head too large")
	errMalformedHead = errors.New("malformed request")
	errBadTarget     = errors.New("malformed request target")
)

// destination is where a request wants to go, exactly as the client named it.
type destination struct {
	host string // lowercase name or address literal, no brackets
	port int
}

// address returns the destination as host:port.
func (d destination) address() string {
	if strings.Contains(d.host, ":") {
		return "[" + d.host + "]:" + strconv.Itoa(d.port)
	}
	return d.host + ":" + strconv.Itoa(d.port)
}

// requestHead is one parsed request head. Header lines are kept as the bytes
// the client sent, in the order it sent them.
type requestHead struct {
	method string
	target string
	proto  string

	lines [][]byte // raw header lines including their line endings

	contentLength int64 // -1 when the request has no Content-Length
	chunked       bool
	upgrade       bool
}

// readHead reads one request head from the client. wait bounds the arrival of
// its first byte; the rest must follow within the header timeout.
func (p *Proxy) readHead(client *clientConn, wait time.Duration) (*requestHead, error) {
	if err := client.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return nil, err
	}
	if _, err := client.reader.Peek(1); err != nil {
		return nil, err
	}
	if err := client.SetReadDeadline(time.Now().Add(p.opts.HeaderTimeout)); err != nil {
		return nil, err
	}
	return parseHead(client.reader, p.opts.MaxHeaderBytes)
}

// parseHead reads and parses a request head of at most maxBytes.
func parseHead(reader *bufio.Reader, maxBytes int) (*requestHead, error) {
	budget := maxBytes

	line, err := readLine(reader, &budget)
	if err != nil {
		return nil, err
	}
	method, target, proto, err := parseRequestLine(line)
	if err != nil {
		return nil, err
	}

	head := &requestHead{method: method, target: target, proto: proto, contentLength: -1}
	for {
		line, err := readLine(reader, &budget)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break
		}
		if err := head.addLine(line); err != nil {
			return nil, err
		}
	}
	if head.chunked && head.contentLength >= 0 {
		// Two ways to frame one body is how requests get smuggled.
		return nil, fmt.Errorf("%w: both Content-Length and Transfer-Encoding", errMalformedHead)
	}
	return head, nil
}

// readLine reads through the next line feed, charging the bytes to budget.
func readLine(reader *bufio.Reader, budget *int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		*budget -= len(chunk)
		if *budget < 0 {
			return nil, errHeadTooLarge
		}
		line = append(line, chunk...)
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// parseRequestLine splits "METHOD target HTTP/1.x".
func parseRequestLine(line []byte) (method, target, proto string, err error) {
	text := strings.TrimRight(string(line), "\r\n")
	parts := strings.Split(text, " ")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("%w: request line", errMalformedHead)
	}
	method, target, proto = parts[0], parts[1], parts[2]

	if method == "" || len(method) > maxMethodLength {
		return "", "", "", fmt.Errorf("%w: method", errMalformedHead)
	}
	for i := 0; i < len(method); i++ {
		if method[i] < 'A' || method[i] > 'Z' {
			return "", "", "", fmt.Errorf("%w: method", errMalformedHead)
		}
	}
	if proto != "HTTP/1.1" && proto != "HTTP/1.0" {
		return "", "", "", fmt.Errorf("%w: protocol version", errMalformedHead)
	}
	if target == "" || !printableASCII(target) {
		return "", "", "", errBadTarget
	}
	return method, target, proto, nil
}

// printableASCII reports whether s is made only of visible ASCII characters.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// addLine records one raw header line and notes what it says about framing.
func (h *requestHead) addLine(line []byte) error {
	if line[0] == ' ' || line[0] == '\t' {
		return fmt.Errorf("%w: folded header", errMalformedHead)
	}
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return fmt.Errorf("%w: header line", errMalformedHead)
	}
	name := line[:colon]
	if bytes.ContainsAny(name, " \t") {
		return fmt.Errorf("%w: space in header name", errMalformedHead)
	}
	value := strings.TrimSpace(string(line[colon+1:]))

	switch {
	case bytes.EqualFold(name, []byte("Content-Length")):
		length, err := strconv.ParseInt(value, 10, 64)
		if err != nil || length < 0 || !allDigits(value) {
			return fmt.Errorf("%w: Content-Length", errMalformedHead)
		}
		if h.contentLength >= 0 && h.contentLength != length {
			return fmt.Errorf("%w: conflicting Content-Length", errMalformedHead)
		}
		h.contentLength = length
	case bytes.EqualFold(name, []byte("Transfer-Encoding")):
		if !strings.EqualFold(value, "chunked") {
			return fmt.Errorf("%w: unsupported Transfer-Encoding", errMalformedHead)
		}
		h.chunked = true
	case bytes.EqualFold(name, []byte("Upgrade")):
		h.upgrade = true
	}

	h.lines = append(h.lines, line)
	return nil
}

// allDigits reports whether s is a non-empty run of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseConnectTarget parses the authority-form target of a CONNECT request.
// The port is mandatory.
func parseConnectTarget(target string) (destination, error) {
	return parseAuthority(target, 0)
}

// parseAbsoluteTarget parses the absolute-form target of a plain HTTP request
// into its destination and the origin-form target to send to that
// destination. Only http:// is accepted: https never reaches a proxy in this
// form.
func parseAbsoluteTarget(target string) (dest destination, originForm string, err error) {
	if len(target) < len(httpScheme) || !strings.EqualFold(target[:len(httpScheme)], httpScheme) {
		return destination{}, "", fmt.Errorf("%w: not an absolute http URL", errBadTarget)
	}
	rest := target[len(httpScheme):]

	authority := rest
	originForm = "/"
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		authority = rest[:end]
		switch rest[end] {
		case '/':
			originForm = rest[end:]
		case '?':
			originForm = "/" + rest[end:]
		}
	}
	// A fragment is never sent to a server.
	if hash := strings.IndexByte(originForm, '#'); hash >= 0 {
		originForm = originForm[:hash]
	}

	dest, err = parseAuthority(authority, defaultHTTPPort)
	if err != nil {
		return destination{}, "", err
	}
	return dest, originForm, nil
}

// parseAuthority splits host[:port]. defaultPort is used when the port is
// absent; zero makes the port mandatory. Userinfo is refused: a browser never
// sends it to a proxy, and it is the classic way to disguise the real host.
func parseAuthority(authority string, defaultPort int) (destination, error) {
	if authority == "" || !printableASCII(authority) {
		return destination{}, fmt.Errorf("%w: empty or non-ASCII authority", errBadTarget)
	}
	if strings.ContainsAny(authority, "@/\\?#%") {
		return destination{}, fmt.Errorf("%w: unexpected character in authority", errBadTarget)
	}

	host, portText := authority, ""
	switch {
	case strings.HasPrefix(authority, "["):
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return destination{}, fmt.Errorf("%w: unterminated IPv6 literal", errBadTarget)
		}
		host = authority[1:end]
		remainder := authority[end+1:]
		if remainder != "" {
			if remainder[0] != ':' {
				return destination{}, fmt.Errorf("%w: junk after IPv6 literal", errBadTarget)
			}
			portText = remainder[1:]
			if portText == "" {
				return destination{}, fmt.Errorf("%w: empty port", errBadTarget)
			}
		}
		if !strings.Contains(host, ":") {
			return destination{}, fmt.Errorf("%w: brackets around a non-IPv6 host", errBadTarget)
		}
	case strings.Count(authority, ":") == 1:
		colon := strings.IndexByte(authority, ':')
		host, portText = authority[:colon], authority[colon+1:]
		if portText == "" {
			return destination{}, fmt.Errorf("%w: empty port", errBadTarget)
		}
	case strings.Contains(authority, ":"):
		return destination{}, fmt.Errorf("%w: unbracketed IPv6 literal", errBadTarget)
	}

	if host == "" || len(host) > maxHostLength || strings.ContainsAny(host, "[]") {
		return destination{}, fmt.Errorf("%w: host", errBadTarget)
	}

	port := defaultPort
	if portText != "" {
		parsed, err := strconv.Atoi(portText)
		if err != nil || !allDigits(portText) {
			return destination{}, fmt.Errorf("%w: port", errBadTarget)
		}
		port = parsed
	}
	if port < 1 || port > 65535 {
		return destination{}, fmt.Errorf("%w: port", errBadTarget)
	}
	return destination{host: strings.ToLower(host), port: port}, nil
}

// headerName returns the name of a raw header line.
func headerName(line []byte) []byte {
	colon := bytes.IndexByte(line, ':')
	if colon < 0 {
		return nil
	}
	return line[:colon]
}

// buildHead renders the head to send onwards. requestTarget replaces the
// target in the request line; every header line is passed through byte for
// byte and in order, with two exceptions that concern only the hop between
// the browser and a proxy:
//
//   - "Proxy-Connection" is what Chrome sends in place of "Connection" when it
//     talks to a proxy. It is renamed back, in place, so the destination sees
//     the header a direct connection would have carried.
//   - "Proxy-Authorization" is addressed to this proxy and is dropped.
//
// When the next hop is itself a proxy (viaProxy), Proxy-Connection is meant
// for it and is left alone, and extra, if non-empty, is appended as further
// header lines (used to authenticate to that proxy).
func buildHead(head *requestHead, requestTarget string, viaProxy bool, extra []byte) []byte {
	var out bytes.Buffer
	out.WriteString(head.method)
	out.WriteByte(' ')
	out.WriteString(requestTarget)
	out.WriteByte(' ')
	out.WriteString(head.proto)
	out.WriteString("\r\n")

	for _, line := range head.lines {
		name := headerName(line)
		switch {
		case bytes.EqualFold(name, []byte("Proxy-Authorization")):
			continue
		case !viaProxy && bytes.EqualFold(name, []byte("Proxy-Connection")):
			out.WriteString("Connection")
			out.Write(line[len(name):])
		default:
			out.Write(line)
		}
	}
	out.Write(extra)
	out.WriteString("\r\n")
	return out.Bytes()
}
