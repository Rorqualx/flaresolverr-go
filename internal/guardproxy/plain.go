package guardproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// originLink is the connection plain HTTP requests are currently being
// forwarded on, and the goroutine relaying its responses to the client.
type originLink struct {
	conn         net.Conn
	dest         destination
	absoluteForm bool // conn leads to another proxy: keep targets absolute

	// retired is set before the guard closes conn itself, so the response
	// relay does not take the client down with it.
	retired atomic.Bool
	done    chan struct{}
}

// servePlain forwards plain HTTP requests from one client connection.
//
// A browser reuses a proxy connection for requests to different hosts, so
// every request head is parsed and its destination checked; the connection is
// never treated as a tunnel to wherever the first request went. Responses are
// relayed as bytes without being parsed.
func (p *Proxy) servePlain(client *clientConn, head *requestHead) {
	act := newActivity()
	var link *originLink
	defer func() { p.retire(link) }()

	for {
		dest, originForm, err := parseAbsoluteTarget(head.target)
		if err != nil {
			p.refuseBadRequest(client.Conn, err)
			return
		}

		if link == nil || link.dest != dest || link.finished() {
			// A browser does not pipeline, so a request for another
			// destination means the previous response is complete.
			p.retire(link)
			link, err = p.link(client, dest, act)
			if err != nil {
				p.refuse(client.Conn, dest, err)
				link = nil
				return
			}
		}

		target := originForm
		var proxyHeader []byte
		if link.absoluteForm {
			target = head.target
			proxyHeader = p.origin.proxyHeader()
		}
		payload := buildHead(head, target, link.absoluteForm, proxyHeader)
		if err := writeAll(link.conn, payload, p.opts.IdleTimeout); err != nil {
			return
		}
		p.stats.requests.Add(1)
		act.touch()

		if head.upgrade {
			// What follows is not HTTP (a WebSocket, usually): relay it as is.
			p.relay(link.conn, client.reader, client.Conn, act)
			return
		}
		if err := p.forwardBody(link.conn, client, head, act); err != nil {
			return
		}

		head, err = p.readHead(client, p.opts.IdleTimeout)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isTimeout(err) && !errors.Is(err, net.ErrClosed) {
				p.refuseBadRequest(client.Conn, err)
			}
			return
		}
		if head.method == methodConnect {
			p.refuseBadRequest(client.Conn, fmt.Errorf("%w: CONNECT on a connection already used for requests", errMalformedHead))
			return
		}
	}
}

// link opens the connection for dest and starts relaying what comes back on
// it to the client.
func (p *Proxy) link(client *clientConn, dest destination, act *activity) (*originLink, error) {
	conn, absoluteForm, err := p.open(dest, false)
	if err != nil {
		return nil, err
	}

	link := &originLink{conn: conn, dest: dest, absoluteForm: absoluteForm, done: make(chan struct{})}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer close(link.done)

		var response byteReader = conn
		if absoluteForm {
			// The first answer on a connection to an upstream proxy may be
			// its refusal of our credentials. That must not reach Chrome as a
			// proxy challenge: Chrome would ask for credentials it was never
			// meant to have.
			reader := bufio.NewReader(conn)
			if p.upstreamDeniedAuth(reader, conn) {
				p.origin.noteAuthFailure()
				writeRefusal(client.Conn, 502, upstreamAuthReason)
				// Ignore error: serveConn closes it again
				_ = client.Close()
				return
			}
			response = reader
		}

		p.relay(client.Conn, response, conn, act)
		if !link.retired.Load() {
			// The destination ended the response by closing; the client
			// learns that the same way.
			// Ignore error: serveConn closes it again
			_ = client.Close()
		}
	}()
	return link, nil
}

// upstreamDeniedAuth reports whether the response waiting on conn starts with
// a 407 status line. Nothing is consumed from reader.
func (p *Proxy) upstreamDeniedAuth(reader *bufio.Reader, conn net.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(p.opts.IdleTimeout)); err != nil {
		return false
	}
	const statusLinePrefix = len("HTTP/1.1 407")
	prefix, err := reader.Peek(statusLinePrefix)
	if err != nil {
		return false // the relay reports whatever is wrong with the connection
	}
	return bytes.HasPrefix(prefix, []byte("HTTP/1.")) && bytes.HasSuffix(prefix, []byte(" 407"))
}

// finished reports whether the response relay for the link has ended.
func (l *originLink) finished() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// retire closes a link and waits for its relay goroutine. A nil link is a
// no-op.
func (p *Proxy) retire(link *originLink) {
	if link == nil {
		return
	}
	link.retired.Store(true)
	p.drop(link.conn)
	<-link.done
}

// forwardBody relays the request body the head announced, if any.
func (p *Proxy) forwardBody(origin net.Conn, client *clientConn, head *requestHead, act *activity) error {
	switch {
	case head.chunked:
		return p.forwardChunked(origin, client, act)
	case head.contentLength > 0:
		return p.forwardN(origin, client, head.contentLength, act)
	default:
		return nil
	}
}

// forwardN relays exactly n body bytes from the client to origin.
func (p *Proxy) forwardN(origin net.Conn, client *clientConn, n int64, act *activity) error {
	buf := make([]byte, relayBufferSize)
	for n > 0 {
		want := int64(len(buf))
		if n < want {
			want = n
		}
		if err := client.SetReadDeadline(time.Now().Add(p.opts.IdleTimeout)); err != nil {
			return err
		}
		read, err := client.reader.Read(buf[:want])
		if read > 0 {
			act.touch()
			if writeErr := writeAll(origin, buf[:read], p.opts.IdleTimeout); writeErr != nil {
				return writeErr
			}
			n -= int64(read)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// forwardChunked relays a chunked request body, byte for byte, through its
// terminating chunk and trailer section.
func (p *Proxy) forwardChunked(origin net.Conn, client *clientConn, act *activity) error {
	for {
		line, err := p.readBodyLine(client)
		if err != nil {
			return err
		}
		if err := writeAll(origin, line, p.opts.IdleTimeout); err != nil {
			return err
		}

		sizeText := bytes.TrimRight(line, "\r\n")
		if semi := bytes.IndexByte(sizeText, ';'); semi >= 0 {
			sizeText = sizeText[:semi] // chunk extension
		}
		size, err := strconv.ParseInt(string(bytes.TrimSpace(sizeText)), 16, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("%w: chunk size", errMalformedHead)
		}

		if size == 0 {
			// Trailer section: lines up to and including the empty one.
			for {
				trailer, err := p.readBodyLine(client)
				if err != nil {
					return err
				}
				if err := writeAll(origin, trailer, p.opts.IdleTimeout); err != nil {
					return err
				}
				if len(bytes.TrimRight(trailer, "\r\n")) == 0 {
					return nil
				}
			}
		}

		// The chunk data and the line ending that follows it.
		if err := p.forwardN(origin, client, size, act); err != nil {
			return err
		}
		ending, err := p.readBodyLine(client)
		if err != nil {
			return err
		}
		if err := writeAll(origin, ending, p.opts.IdleTimeout); err != nil {
			return err
		}
	}
}

// readBodyLine reads one bounded line of chunked-body framing.
func (p *Proxy) readBodyLine(client *clientConn) ([]byte, error) {
	if err := client.SetReadDeadline(time.Now().Add(p.opts.IdleTimeout)); err != nil {
		return nil, err
	}
	budget := maxChunkLineBytes
	return readLine(client.reader, &budget)
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// refuse answers a request whose destination the guard will not or cannot
// reach. The client gets a status and a reason; nothing is sent anywhere else.
func (p *Proxy) refuse(conn net.Conn, dest destination, err error) {
	status, reason := refusalFor(err)
	log.Debug().
		Str("host", dest.host).
		Int("port", dest.port).
		Int("status", status).
		Str("reason", reason).
		Msg("Egress guard refused a destination")
	writeRefusal(conn, status, reason)
}

// refuseBadRequest answers a request the guard could not parse.
func (p *Proxy) refuseBadRequest(conn net.Conn, err error) {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed), isTimeout(err):
		return // nothing was asked
	case errors.Is(err, errHeadTooLarge):
		writeRefusal(conn, 431, "Request Header Fields Too Large")
	default:
		writeRefusal(conn, 400, "Bad Request")
	}
}

// upstreamAuthReason is what the client is told when the upstream proxy does
// not accept the credentials the guard was given for it.
const upstreamAuthReason = "The upstream proxy rejected the configured credentials"

// refusalFor maps an error from opening a destination to the status and the
// reason the client is given. The reason never includes address details
// beyond what the client itself asked for.
func refusalFor(err error) (status int, reason string) {
	switch {
	case errors.Is(err, ErrBlocked):
		return 403, "Blocked by the egress guard: the destination is not a public address"
	case errors.Is(err, ErrUpstreamAuth):
		return 502, upstreamAuthReason
	case errors.Is(err, ErrUpstream):
		return 502, "The upstream proxy refused or failed the connection"
	case errors.Is(err, ErrResolve):
		return 502, "The destination name did not resolve"
	default:
		return 502, "The destination is unreachable"
	}
}

// writeRefusal sends a minimal, self-contained error response and leaves the
// connection for the caller to close.
func writeRefusal(conn net.Conn, status int, reason string) {
	body := reason + "\n"
	response := "HTTP/1.1 " + strconv.Itoa(status) + " " + statusText(status) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	// Ignore error: the connection is being closed either way
	_ = writeAll(conn, []byte(response), refusalTimeout)
}

// statusText returns the reason phrase for the statuses the guard sends.
func statusText(status int) string {
	switch status {
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 431:
		return "Request Header Fields Too Large"
	default:
		return "Bad Gateway"
	}
}
