package security

import "fmt"

// ValidateOperatorProxyURL checks the proxy the operator configured for the
// whole server (PROXY_URL). An empty URL is valid (no default proxy).
//
// Unlike a proxy supplied in an API request, this one is trusted
// configuration: a private address, localhost or a Docker-network hostname is
// a normal place for an operator's own proxy to live, so those are accepted
// without ALLOW_LOCAL_PROXIES. The scheme, host and port are still checked,
// and cloud metadata endpoints are still refused, since no proxy lives there
// and pointing at one is always a mistake.
//
// Call it once at startup. Checking the operator's proxy against the
// caller-facing SSRF rules on every request made all requests fail whenever
// PROXY_URL pointed at a private address.
func ValidateOperatorProxyURL(proxyURL string) error {
	if err := ValidateProxyURL(proxyURL, true); err != nil {
		return fmt.Errorf("invalid PROXY_URL: %w", err)
	}
	return nil
}
