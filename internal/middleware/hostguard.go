package middleware

import (
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// HostGuardConfig configures the Host and Origin checks.
type HostGuardConfig struct {
	// AllowedHosts lists extra hostnames accepted in the Host header. An entry
	// starting with a dot matches that domain and its subdomains; "*" disables
	// the Host check entirely.
	AllowedHosts []string

	// AllowedOrigins lists the origins (scheme://host[:port]) allowed to call
	// the API from a browser. Any other Origin header is rejected.
	AllowedOrigins []string
}

// HostGuard returns middleware that protects an API meant for local or
// internal use from being driven through a visitor's web browser.
//
// Two attacks apply to a server like this one, which by default has no API key
// and listens on an address only local software can reach:
//
//   - DNS rebinding. A page on attacker.example re-points its own name at
//     127.0.0.1 (or a LAN address), after which the browser treats this server
//     as same-origin with the page and lets it read responses. The browser
//     still sends "Host: attacker.example", so the Host check stops it.
//   - Cross-site requests. A page posts to http://127.0.0.1:8191 directly. The
//     Host is then legitimate, but the browser attaches the page's Origin, so
//     the Origin check stops it.
//
// Hosts accepted without configuration are those an attacker cannot make a
// public DNS name resolve to: IP literals, "localhost", this machine's own
// hostname, and single-label names (no dot), which is what a Docker Compose
// service name such as "flaresolverr" is. Any other name must be listed in
// AllowedHosts.
func HostGuard(cfg HostGuardConfig) func(http.Handler) http.Handler {
	allowAnyHost := false
	exactHosts := make(map[string]struct{}, len(cfg.AllowedHosts)+1)
	var suffixHosts []string
	for _, entry := range cfg.AllowedHosts {
		entry = strings.ToLower(strings.TrimSpace(entry))
		switch {
		case entry == "":
		case entry == "*":
			allowAnyHost = true
		case strings.HasPrefix(entry, "."):
			if suffix := strings.TrimSuffix(entry, "."); len(suffix) > 1 {
				suffixHosts = append(suffixHosts, suffix)
			}
		default:
			exactHosts[strings.TrimSuffix(hostOnly(entry), ".")] = struct{}{}
		}
	}
	if name, err := os.Hostname(); err == nil && name != "" {
		exactHosts[strings.ToLower(strings.TrimSuffix(name, "."))] = struct{}{}
	}

	allowedOrigins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		allowedOrigins[strings.TrimSpace(origin)] = struct{}{}
	}

	if allowAnyHost {
		log.Warn().Msg("ALLOWED_HOSTS=* - Host header check disabled; DNS rebinding protection is off")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()

			if !allowAnyHost && !hostAllowed(r.Host, exactHosts, suffixHosts) {
				host := hostOnly(r.Host)
				log.Warn().
					Str("host", r.Host).
					Str("path", r.URL.Path).
					Str("fix", "ALLOWED_HOSTS="+host).
					Msg("Rejected request: Host header is not an allowed name for this server. If this is how you reach FlareSolverr, set the env var shown in 'fix'")
				writeErrorResponse(w, http.StatusForbidden,
					"Host not allowed. If this hostname is how you reach FlareSolverr, set ALLOWED_HOSTS="+host, startTime)
				return
			}

			// Browsers attach Origin to every cross-site request that can have
			// side effects, and to every CORS preflight. Programs calling the
			// API do not send it.
			if origin := r.Header.Get("Origin"); origin != "" {
				if _, ok := allowedOrigins[origin]; !ok {
					log.Warn().
						Str("origin", origin).
						Str("path", r.URL.Path).
						Str("fix", "CORS_ALLOWED_ORIGINS="+origin).
						Msg("Rejected request: it came from a web page whose origin is not allowed")
					writeErrorResponse(w, http.StatusForbidden,
						"Origin not allowed. To call the API from this web origin, add it to CORS_ALLOWED_ORIGINS", startTime)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// hostAllowed reports whether a Host header value names this server in a way
// an outside party could not have arranged.
func hostAllowed(hostHeader string, exact map[string]struct{}, suffixes []string) bool {
	host := strings.ToLower(strings.TrimSuffix(hostOnly(hostHeader), "."))
	if host == "" {
		return false
	}

	// IP literal: rebinding needs a name
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	// A numeric-looking host that is not a valid address (for example the
	// octal or integer forms a browser would still treat as an IP) is not a
	// name anyone can register either, but it is also never what a real
	// client sends; fall through to the name rules, which reject dotted ones.

	if host == "localhost" {
		return true
	}
	if _, ok := exact[host]; ok {
		return true
	}
	// Single-label names resolve only through local means (hosts file, Docker's
	// embedded DNS, a search domain), never through public DNS.
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return true
	}
	for _, suffix := range suffixes {
		if host == suffix[1:] || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// hostOnly strips the port from a Host header value, handling bracketed IPv6
// literals ("[::1]:8191") and returning the address without brackets.
func hostOnly(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if strings.HasPrefix(hostport, "[") {
		if end := strings.Index(hostport, "]"); end > 0 {
			return hostport[1:end]
		}
		return hostport
	}
	// Exactly one colon separates host and port; more than one is a bare
	// IPv6 literal with no port.
	if strings.Count(hostport, ":") == 1 {
		host, _, _ := strings.Cut(hostport, ":")
		return host
	}
	return hostport
}
