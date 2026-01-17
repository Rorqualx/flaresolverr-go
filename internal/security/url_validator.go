// Package security provides security utilities for input validation.
package security

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// URL validation errors.
var (
	ErrInvalidURL       = errors.New("invalid URL")
	ErrBlockedScheme    = errors.New("URL scheme not allowed")
	ErrBlockedHost      = errors.New("host not allowed")
	ErrPrivateIPBlocked = errors.New("private/internal IP addresses are not allowed")
	ErrLocalhostBlocked = errors.New("localhost URLs are not allowed")
	ErrMetadataBlocked  = errors.New("cloud metadata URLs are not allowed")
)

// AllowedSchemes defines the permitted URL schemes.
var AllowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// BlockedHosts contains hostnames that should never be accessed.
var BlockedHosts = map[string]bool{
	"localhost":                true,
	"metadata.google.internal": true, // GCP metadata
	"metadata":                 true, // Generic cloud metadata
	"instance-data":            true, // AWS instance metadata hostname
}

// cloudMetadataIPs contains IP addresses used by cloud provider metadata services.
// These must be blocked to prevent SSRF attacks from accessing cloud credentials.
var cloudMetadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"), // AWS, GCP, Azure, DigitalOcean, OpenStack
	net.ParseIP("169.254.170.2"),   // AWS ECS task metadata
	net.ParseIP("100.100.100.200"), // Alibaba Cloud
	net.ParseIP("192.0.0.192"),     // Oracle Cloud Instance Metadata (IMDS)
	net.ParseIP("fd00:ec2::254"),   // AWS IPv6 metadata
	net.ParseIP("fc00:ec2::254"),   // AWS IPv6 metadata (alternate)
}

// ValidateURL checks if a URL is safe to navigate to.
// It blocks:
// - Non-HTTP(S) schemes (file://, javascript:, data:, etc.)
// - Private/internal IP addresses (RFC 1918, RFC 4193, link-local)
// - Localhost and loopback addresses (entire 127.0.0.0/8 range)
// - Cloud metadata service IPs (169.254.169.254, etc.)
// - IP address encoding bypasses (decimal, octal, hex)
// - IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return ErrInvalidURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ErrInvalidURL
	}

	// Check scheme
	if !AllowedSchemes[strings.ToLower(parsed.Scheme)] {
		return ErrBlockedScheme
	}

	// Check for blocked hostnames
	hostname := strings.ToLower(parsed.Hostname())
	if BlockedHosts[hostname] {
		return ErrLocalhostBlocked
	}

	// Check for localhost hostname variations
	if isLocalhostHostname(hostname) {
		return ErrLocalhostBlocked
	}

	// Try to parse as IP address (handles standard formats)
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		// Normalize IPv4-mapped IPv6 addresses to IPv4
		ip = normalizeIPv4Mapped(ip)
		if err := validateIP(ip); err != nil {
			return err
		}
	} else {
		// For hostnames, resolve and check all IPs
		ips, err := net.LookupIP(hostname)
		if err == nil {
			for _, resolvedIP := range ips {
				// Normalize IPv4-mapped addresses
				resolvedIP = normalizeIPv4Mapped(resolvedIP)
				if err := validateIP(resolvedIP); err != nil {
					return err
				}
			}
		}
		// If DNS resolution fails, we allow it - the browser will handle the error
	}

	return nil
}

// parseIPWithNormalization parses an IP address string, handling various encoding formats
// that could be used to bypass SSRF protections:
// - Standard dotted decimal (192.168.1.1)
// - Decimal encoding (3232235777 for 192.168.1.1)
// - Octal encoding (0300.0250.01.01 for 192.168.1.1)
// - Hex encoding (0xC0.0xA8.0x01.0x01 for 192.168.1.1)
// - Mixed encodings
func parseIPWithNormalization(hostname string) net.IP {
	// First try standard parsing (handles most cases including IPv6)
	if ip := net.ParseIP(hostname); ip != nil {
		return ip
	}

	// Try parsing as a single decimal number (e.g., 2130706433 for 127.0.0.1)
	if num, err := strconv.ParseUint(hostname, 10, 32); err == nil {
		return net.IPv4(byte(num>>24), byte(num>>16), byte(num>>8), byte(num))
	}

	// Try parsing with octal/hex components (e.g., 0177.0.0.1 or 0x7f.0.0.1)
	parts := strings.Split(hostname, ".")
	if len(parts) == 4 {
		var octets [4]byte
		for i, part := range parts {
			val, err := parseIntWithBase(part)
			if err != nil || val > 255 {
				return nil
			}
			octets[i] = byte(val)
		}
		return net.IPv4(octets[0], octets[1], octets[2], octets[3])
	}

	// Handle shortened IP forms (e.g., 127.1 -> 127.0.0.1)
	if len(parts) == 2 {
		first, err1 := parseIntWithBase(parts[0])
		second, err2 := parseIntWithBase(parts[1])
		if err1 == nil && err2 == nil && first <= 255 && second <= 0xFFFFFF {
			return net.IPv4(byte(first), byte(second>>16), byte(second>>8), byte(second))
		}
	}

	return nil
}

// parseIntWithBase parses an integer that may be in decimal, octal (0-prefixed),
// or hexadecimal (0x-prefixed) format.
func parseIntWithBase(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty string")
	}

	// Hex format (0x or 0X prefix)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}

	// Octal format (0 prefix, but not just "0")
	if strings.HasPrefix(s, "0") && len(s) > 1 && s[1] != 'x' && s[1] != 'X' {
		return strconv.ParseUint(s[1:], 8, 64)
	}

	// Decimal format
	return strconv.ParseUint(s, 10, 64)
}

// normalizeIPv4Mapped converts IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to IPv4.
// This prevents bypasses using IPv6 notation to hide IPv4 addresses.
func normalizeIPv4Mapped(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

// isLocalhostHostname checks if a hostname is a localhost variant.
func isLocalhostHostname(hostname string) bool {
	localHostnames := []string{
		"localhost",
		"localhost.localdomain",
		"local",
		"ip6-localhost",
		"ip6-loopback",
	}

	for _, local := range localHostnames {
		if hostname == local {
			return true
		}
	}

	// Check for localhost subdomains (e.g., foo.localhost)
	if strings.HasSuffix(hostname, ".localhost") {
		return true
	}

	// Check for localhost with other TLDs (e.g., localhost.local)
	if strings.HasPrefix(hostname, "localhost.") {
		return true
	}

	return false
}

// isLoopbackIP checks if an IP is in the loopback range.
// For IPv4, this is the entire 127.0.0.0/8 range (not just 127.0.0.1).
// For IPv6, this is ::1.
func isLoopbackIP(ip net.IP) bool {
	// Check IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// Entire 127.0.0.0/8 range is loopback
		return ip4[0] == 127
	}

	// Check IPv6 loopback (::1)
	return ip.Equal(net.IPv6loopback)
}

// validateIP checks if an IP address is safe to access.
func validateIP(ip net.IP) error {
	// Block loopback (entire 127.0.0.0/8 range for IPv4)
	if isLoopbackIP(ip) {
		return ErrLocalhostBlocked
	}

	// Block private addresses (RFC 1918 for IPv4, RFC 4193 for IPv6)
	if ip.IsPrivate() {
		return ErrPrivateIPBlocked
	}

	// Block link-local addresses (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ErrPrivateIPBlocked
	}

	// Block cloud metadata service IPs
	if isCloudMetadataIP(ip) {
		return ErrMetadataBlocked
	}

	// Block unspecified addresses (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return ErrPrivateIPBlocked
	}

	return nil
}

// isCloudMetadataIP checks if an IP is a cloud provider metadata service.
func isCloudMetadataIP(ip net.IP) bool {
	for _, metadataIP := range cloudMetadataIPs {
		if ip.Equal(metadataIP) {
			return true
		}
	}
	return false
}

// ValidateAndResolveURL validates a URL and returns the resolved IP for DNS pinning.
// This helps prevent DNS rebinding attacks by allowing the caller to verify
// the IP hasn't changed between validation and use.
func ValidateAndResolveURL(rawURL string) (string, net.IP, error) {
	if rawURL == "" {
		return "", nil, ErrInvalidURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", nil, ErrInvalidURL
	}

	// Check scheme
	if !AllowedSchemes[strings.ToLower(parsed.Scheme)] {
		return "", nil, ErrBlockedScheme
	}

	hostname := strings.ToLower(parsed.Hostname())
	if BlockedHosts[hostname] {
		return "", nil, ErrLocalhostBlocked
	}

	if isLocalhostHostname(hostname) {
		return "", nil, ErrLocalhostBlocked
	}

	// Try to parse as IP address
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		ip = normalizeIPv4Mapped(ip)
		if err := validateIP(ip); err != nil {
			return "", nil, err
		}
		return rawURL, ip, nil
	}

	// For hostnames, resolve and validate all IPs
	// If DNS resolution fails, allow it - browser will handle the error
	ips, _ := net.LookupIP(hostname)
	if len(ips) == 0 {
		return rawURL, nil, nil
	}

	for _, resolvedIP := range ips {
		resolvedIP = normalizeIPv4Mapped(resolvedIP)
		if err := validateIP(resolvedIP); err != nil {
			return "", nil, err
		}
	}

	// Return first resolved IP for DNS pinning
	return rawURL, normalizeIPv4Mapped(ips[0]), nil
}

// Proxy URL validation errors.
var (
	ErrInvalidProxyURL    = errors.New("invalid proxy URL")
	ErrBlockedProxyScheme = errors.New("proxy URL scheme not allowed (must be http, https, socks4, or socks5)")
)

// AllowedProxySchemes defines the permitted schemes for proxy URLs.
var AllowedProxySchemes = map[string]bool{
	"http":   true,
	"https":  true,
	"socks4": true,
	"socks5": true,
}

// ValidateProxyURL validates a proxy URL for safe use.
// Unlike ValidateURL, this allows socks4/socks5 schemes and optionally
// allows private IPs (since local proxies are a common use case).
//
// Parameters:
//   - proxyURL: The proxy URL to validate
//   - allowPrivateIPs: If true, allows private/localhost IPs (for local proxies)
//
// Returns an error if the proxy URL is invalid or uses a blocked scheme.
func ValidateProxyURL(proxyURL string, allowPrivateIPs bool) error {
	if proxyURL == "" {
		return nil // Empty proxy is valid (means no proxy)
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return ErrInvalidProxyURL
	}

	// Validate scheme
	scheme := strings.ToLower(parsed.Scheme)
	if !AllowedProxySchemes[scheme] {
		return ErrBlockedProxyScheme
	}

	// Validate host is present
	if parsed.Host == "" {
		return ErrInvalidProxyURL
	}

	// If we allow private IPs, we're done
	if allowPrivateIPs {
		return nil
	}

	// Otherwise, check for private/localhost IPs
	hostname := strings.ToLower(parsed.Hostname())

	// Check for blocked hostnames
	if BlockedHosts[hostname] {
		return ErrLocalhostBlocked
	}

	// Check for localhost hostname variations
	if isLocalhostHostname(hostname) {
		return ErrLocalhostBlocked
	}

	// Try to parse as IP address
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		ip = normalizeIPv4Mapped(ip)
		if err := validateIP(ip); err != nil {
			return err
		}
	}
	// For hostnames, we don't resolve since the browser will do that through the proxy

	return nil
}

// SanitizeCookieDomain validates and sanitizes a cookie domain.
// Returns the target host if the domain is invalid or potentially malicious.
func SanitizeCookieDomain(domain string, targetHost string) string {
	if domain == "" {
		return targetHost
	}

	// Remove leading dot if present (cookies use implicit dot matching)
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.ToLower(domain)

	// Domain must be a suffix of target host or equal to it
	targetHost = strings.ToLower(targetHost)

	if domain == targetHost {
		return domain
	}

	// Check if domain is a valid suffix
	if strings.HasSuffix(targetHost, "."+domain) {
		// Prevent setting cookies on TLDs or overly broad domains
		// Domain must have at least 2 segments (e.g., "example.com" not "com")
		if strings.Count(domain, ".") < 1 {
			return targetHost
		}
		return domain
	}

	// Domain doesn't match target - use target host instead
	return targetHost
}
