// Package security provides security utilities for input validation.
package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Default DNS lookup timeout to prevent blocking on slow/unresponsive resolvers.
const dnsLookupTimeout = 5 * time.Second

// lookupIPWithTimeout performs DNS resolution with a context timeout.
// This prevents blocking indefinitely on slow or unresponsive DNS servers.
func lookupIPWithTimeout(ctx context.Context, hostname string) ([]net.IP, error) {
	// Create timeout context if none provided
	if ctx == nil {
		ctx = context.Background()
	}

	// Add timeout if context doesn't have a deadline
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dnsLookupTimeout)
		defer cancel()
	}

	resolver := &net.Resolver{}
	return resolver.LookupIP(ctx, "ip", hostname)
}

// URL validation errors.
var (
	ErrInvalidURL       = errors.New("invalid URL")
	ErrBlockedScheme    = errors.New("URL scheme not allowed")
	ErrBlockedHost      = errors.New("host not allowed")
	ErrPrivateIPBlocked = errors.New("private/internal IP addresses are not allowed")
	ErrLocalhostBlocked = errors.New("localhost URLs are not allowed")
	ErrMetadataBlocked  = errors.New("cloud metadata URLs are not allowed")
	ErrEmptyURL         = errors.New("empty or special URL")
	ErrEmptyHostname    = errors.New("empty hostname")
	ErrDNSLookupFailed  = errors.New("DNS lookup failed or returned no IPs")
	ErrHomographAttack  = errors.New("potential IDN homograph attack detected")
	ErrInvalidIDN       = errors.New("invalid internationalized domain name")
)

// idnaProfile is used for strict IDN validation to detect homograph attacks.
var idnaProfile = idna.New(
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
	idna.StrictDomainName(true),
)

// AllowedSchemes defines the permitted URL schemes.
var AllowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// BlockedHosts contains hostnames that should never be accessed.
// Fix HIGH: Added comprehensive list of cloud metadata hostnames.
var BlockedHosts = map[string]bool{
	// Localhost variants
	"localhost": true,

	// AWS metadata
	"instance-data":             true, // AWS instance metadata hostname
	"instance-data.ec2.internal": true, // AWS EC2 internal hostname

	// GCP metadata
	"metadata.google.internal": true, // GCP metadata
	"metadata":                 true, // Generic cloud metadata

	// Azure metadata
	"metadata.azure.com":          true, // Azure metadata (IMDS)
	"management.azure.com":        true, // Azure management API
	"login.microsoftonline.com":   true, // Azure AD (could leak tokens)
	"graph.microsoft.com":         true, // Microsoft Graph API

	// Alibaba Cloud metadata
	"metadata.aliyun.com": true,

	// Oracle Cloud metadata
	"metadata.oraclecloud.com": true,

	// IBM Cloud metadata
	"metadata.softlayer.local": true,

	// DigitalOcean metadata
	"metadata.digitalocean.com": true,

	// Hetzner Cloud metadata
	"metadata.hetzner.cloud": true,

	// Vultr metadata
	"metadata.vultr.com": true,

	// Linode metadata
	"metadata.linode.com": true,

	// Tencent Cloud metadata
	"metadata.tencentyun.com": true,

	// Generic patterns
	"kubernetes.default.svc": true, // Kubernetes API
	"kubernetes.default":     true,
	"kubernetes":             true,
}

// cloudMetadataIPs contains IP addresses used by cloud provider metadata services.
// These must be blocked to prevent SSRF attacks from accessing cloud credentials.
var cloudMetadataIPs = []net.IP{
	// AWS metadata endpoints
	net.ParseIP("169.254.169.254"), // AWS, GCP, Azure, DigitalOcean, OpenStack
	net.ParseIP("169.254.170.2"),   // AWS ECS task metadata v2
	net.ParseIP("169.254.170.23"),  // AWS ECS task metadata v4
	net.ParseIP("fd00:ec2::254"),   // AWS IPv6 metadata
	net.ParseIP("fc00:ec2::254"),   // AWS IPv6 metadata (alternate)

	// Azure metadata endpoints
	net.ParseIP("169.254.169.253"), // Azure Wire Server

	// GCP metadata endpoints
	net.ParseIP("169.254.169.252"), // GCP Kubernetes metadata

	// Alibaba Cloud
	net.ParseIP("100.100.100.200"),

	// Oracle Cloud
	net.ParseIP("192.0.0.192"), // Oracle Cloud Instance Metadata (IMDS)

	// Generic link-local that might be metadata
	net.ParseIP("169.254.0.1"), // Often used for container metadata
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
	return ValidateURLWithContext(context.Background(), rawURL)
}

// ValidateURLWithContext checks if a URL is safe to navigate to, with context support.
// The context is used for DNS resolution timeout control.
func ValidateURLWithContext(ctx context.Context, rawURL string) error {
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

	// Fix #18: Validate internationalized domain names (IDN)
	// This detects potential homograph attacks using lookalike Unicode characters
	if err := validateIDN(hostname); err != nil {
		return err
	}

	// Try to parse as IP address (handles standard formats)
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		// Normalize IPv4-mapped IPv6 addresses to IPv4
		ip = normalizeIPv4Mapped(ip)
		if err := validateIP(ip); err != nil {
			return fmt.Errorf("invalid parsed IP %s: %w", ip.String(), err)
		}
	} else {
		// For hostnames, resolve and check all IPs with timeout
		// SECURITY: Fail closed on DNS failure to prevent SSRF bypass
		ips, err := lookupIPWithTimeout(ctx, hostname)
		if err != nil || len(ips) == 0 {
			return ErrDNSLookupFailed
		}
		for _, resolvedIP := range ips {
			// Normalize IPv4-mapped addresses
			resolvedIP = normalizeIPv4Mapped(resolvedIP)
			if err := validateIP(resolvedIP); err != nil {
				return fmt.Errorf("invalid resolved IP for %s: %w", hostname, err)
			}
		}
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

	// Fix 2.8: Handle 3-part IP form (e.g., 127.0.1 -> 127.0.0.1)
	// Format: A.B.C where C is interpreted as a 16-bit value for last two octets
	if len(parts) == 3 {
		first, err1 := parseIntWithBase(parts[0])
		second, err2 := parseIntWithBase(parts[1])
		third, err3 := parseIntWithBase(parts[2])
		if err1 == nil && err2 == nil && err3 == nil &&
			first <= 255 && second <= 255 && third <= 0xFFFF {
			// Fix #35: Reject ambiguous 3-part IPs where truncation could occur
			// If third value is >255 but lower byte is non-zero, the encoding is ambiguous
			// and could be used to bypass SSRF protections. Reject to be safe.
			if third > 255 && (third&0xFF) != 0 {
				return nil // Reject ambiguous encoding
			}
			return net.IPv4(byte(first), byte(second), byte(third>>8), byte(third))
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
	// Example: "0177" -> strip leading 0 -> parse "177" as base 8 = 127
	// Note: strconv.ParseUint expects digits without 0 prefix for explicit base,
	// so we strip the leading 0 and parse the rest as octal (base 8).
	// This handles IP obfuscation like 0177.0.0.1 -> 127.0.0.1
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

// validateIDN validates internationalized domain names to detect homograph attacks.
// This uses the IDNA 2008 standard to convert Unicode domains to ASCII (punycode)
// and detects potentially confusing character combinations.
func validateIDN(hostname string) error {
	// Skip validation if hostname is already pure ASCII
	isASCII := true
	for i := 0; i < len(hostname); i++ {
		if hostname[i] > 127 {
			isASCII = false
			break
		}
	}
	if isASCII {
		return nil
	}

	// Convert to punycode/ASCII using strict IDNA profile
	asciiHost, err := idnaProfile.ToASCII(hostname)
	if err != nil {
		log.Warn().
			Str("hostname", hostname).
			Err(err).
			Msg("Invalid IDN hostname")
		return ErrInvalidIDN
	}

	// Check for potential homograph attack:
	// If the ASCII version starts with "xn--" (punycode), it means the original
	// contained non-ASCII characters. Log for monitoring but allow.
	// For strict security, you could block all punycode domains.
	if strings.Contains(asciiHost, "xn--") {
		log.Debug().
			Str("original", hostname).
			Str("punycode", asciiHost).
			Msg("IDN domain detected (punycode conversion)")
	}

	return nil
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
			// Fix #48: Log security event for blocked metadata access attempts
			log.Warn().
				Str("blocked_ip", ip.String()).
				Msg("Blocked cloud metadata access attempt (potential SSRF)")
			return true
		}
	}
	return false
}

// cloudMetadataHosts contains hostnames used by cloud provider metadata services.
// These must be blocked to prevent SSRF attacks from accessing cloud credentials.
// Fix HIGH: This is a subset of BlockedHosts focused specifically on metadata endpoints.
var cloudMetadataHosts = map[string]bool{
	// AWS metadata
	"instance-data":              true,
	"instance-data.ec2.internal": true,

	// GCP metadata
	"metadata.google.internal": true,
	"metadata":                 true,

	// Azure metadata
	"metadata.azure.com": true,

	// Alibaba Cloud metadata
	"metadata.aliyun.com": true,

	// Oracle Cloud metadata
	"metadata.oraclecloud.com": true,

	// IBM Cloud metadata
	"metadata.softlayer.local": true,

	// DigitalOcean metadata
	"metadata.digitalocean.com": true,

	// Hetzner Cloud metadata
	"metadata.hetzner.cloud": true,

	// Vultr metadata
	"metadata.vultr.com": true,

	// Linode metadata
	"metadata.linode.com": true,

	// Tencent Cloud metadata
	"metadata.tencentyun.com": true,
}

// isCloudMetadataHost checks if a hostname is a cloud metadata service.
func isCloudMetadataHost(hostname string) bool {
	return cloudMetadataHosts[hostname]
}

// ValidateAndResolveURL validates a URL and returns the resolved IP for DNS pinning.
// This helps prevent DNS rebinding attacks by allowing the caller to verify
// the IP hasn't changed between validation and use.
//
// Fix #19: IMPORTANT - DNS rebinding protection requires calling ValidateURLWithPinnedIP
// on EVERY navigation, not just the first one. The returned expectedIP must be
// passed to subsequent validations to detect if DNS resolution has changed.
// Attackers can set up domains that initially resolve to safe IPs, then change
// resolution to internal IPs after initial validation.
func ValidateAndResolveURL(rawURL string) (string, net.IP, error) {
	return ValidateAndResolveURLWithContext(context.Background(), rawURL)
}

// ValidateAndResolveURLWithContext validates a URL with context support for DNS timeout.
func ValidateAndResolveURLWithContext(ctx context.Context, rawURL string) (string, net.IP, error) {
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

	// For hostnames, resolve and validate all IPs with timeout
	// SECURITY: Fail closed on DNS lookup failure to prevent SSRF bypass.
	// An attacker could set up a domain that intentionally fails DNS to bypass validation,
	// then have the browser resolve it differently.
	ips, err := lookupIPWithTimeout(ctx, hostname)
	if err != nil || len(ips) == 0 {
		return "", nil, ErrDNSLookupFailed
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

	// Validate port is in valid range (1-65535)
	if portStr := parsed.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return ErrInvalidProxyURL
		}
	}

	hostname := strings.ToLower(parsed.Hostname())

	// SECURITY: Always block cloud metadata endpoints, even if allowPrivateIPs is true.
	// This prevents accessing cloud metadata services (169.254.169.254, metadata.google.internal)
	// which could expose cloud credentials or instance information.
	// Note: We check specific metadata hosts, not localhost (which is valid for local proxies).
	if isCloudMetadataHost(hostname) {
		return ErrMetadataBlocked
	}

	// Fix 1.7: Also block cloud metadata IPs directly, even when allowPrivateIPs is true
	// This prevents bypassing hostname checks by using IP address directly
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		ip = normalizeIPv4Mapped(ip)
		if isCloudMetadataIP(ip) {
			return ErrMetadataBlocked
		}
	}

	// If we allow private IPs (common for local proxies), skip remaining validation
	// This allows localhost and private IPs for legitimate local proxy use cases
	if allowPrivateIPs {
		return nil
	}

	// Check for blocked hostnames (including localhost)
	if BlockedHosts[hostname] {
		return ErrLocalhostBlocked
	}

	// Check for localhost hostname variations
	if isLocalhostHostname(hostname) {
		return ErrLocalhostBlocked
	}

	// Try to parse as IP address (reuse ip variable from earlier check)
	if ip == nil {
		ip = parseIPWithNormalization(hostname)
	}
	if ip != nil {
		ip = normalizeIPv4Mapped(ip)
		if err := validateIP(ip); err != nil {
			return err
		}
	} else {
		// Fix: For hostnames, resolve and check for metadata IPs to prevent SSRF bypass
		// Attacker could set up a hostname pointing to metadata service IPs
		ips, err := lookupIPWithTimeout(context.Background(), hostname)
		if err == nil && len(ips) > 0 {
			for _, resolvedIP := range ips {
				resolvedIP = normalizeIPv4Mapped(resolvedIP)
				if isCloudMetadataIP(resolvedIP) {
					return ErrMetadataBlocked
				}
				if err := validateIP(resolvedIP); err != nil {
					return err
				}
			}
		}
		// Note: DNS lookup failure is NOT an error for proxy URLs since
		// the browser connects through the proxy, not directly
	}

	return nil
}

// SanitizeCookieDomain validates and sanitizes a cookie domain.
// Returns the target host if the domain is invalid or potentially malicious.
// Uses the Public Suffix List to prevent supercookie attacks on domains like co.uk.
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
		// Check if domain is a public suffix (like co.uk, com.au, etc.)
		// This prevents supercookie attacks where an attacker sets cookies
		// on a public suffix to affect all sites under that suffix.
		suffix, icann := publicsuffix.PublicSuffix(domain)
		if icann && suffix == domain {
			// Domain is exactly a public suffix, reject it
			return targetHost
		}

		// Also check if it's registered under a public suffix with nothing else
		// e.g., "example.co.uk" is OK, but "co.uk" is not
		eTLD, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			// If we can't determine eTLD+1, the domain might be a public suffix itself
			return targetHost
		}
		// Domain must be at least eTLD+1 (e.g., example.com, not just com)
		// Accept if domain equals eTLD+1 or is a subdomain of it
		if domain != eTLD && !strings.HasSuffix(domain, "."+eTLD) {
			// Domain is broader than eTLD+1, reject it
			return targetHost
		}

		return domain
	}

	// Domain doesn't match target - use target host instead
	return targetHost
}

// DNS pinning errors.
var (
	ErrDNSRebinding = errors.New("DNS rebinding detected: resolved IP does not match expected IP")
)

// ValidateURLWithPinnedIP validates that a URL resolves to the expected IP address.
// This prevents DNS rebinding attacks where the DNS resolution changes between
// the initial validation and the actual request.
//
// Parameters:
//   - rawURL: The URL to validate
//   - expectedIP: The IP address that was resolved during initial validation (can be nil to skip pinning)
//
// Returns an error if:
//   - The URL is invalid or blocked (same checks as ValidateURL)
//   - The URL's hostname resolves to a different IP than expected (DNS rebinding)
//   - The resolved IP is blocked (private, metadata, etc.)
func ValidateURLWithPinnedIP(rawURL string, expectedIP net.IP) error {
	return ValidateURLWithPinnedIPContext(context.Background(), rawURL, expectedIP)
}

// ValidateURLWithPinnedIPContext validates with context support for DNS timeout.
func ValidateURLWithPinnedIPContext(ctx context.Context, rawURL string, expectedIP net.IP) error {
	// First, run standard validation
	if err := ValidateURLWithContext(ctx, rawURL); err != nil {
		return err
	}

	// If no expected IP provided, skip pinning check
	if expectedIP == nil {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ErrInvalidURL
	}

	hostname := strings.ToLower(parsed.Hostname())

	// If hostname is already an IP, compare directly
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		ip = normalizeIPv4Mapped(ip)
		if !ip.Equal(expectedIP) {
			return ErrDNSRebinding
		}
		return nil
	}

	// Resolve hostname with timeout and check if any resolved IP matches expected
	ips, err := lookupIPWithTimeout(ctx, hostname)
	if err != nil {
		// DNS resolution failed - this could be a rebinding attack
		// where attacker made DNS unavailable after initial resolution
		return ErrDNSRebinding
	}

	// Check if any resolved IP matches the expected IP
	for _, resolvedIP := range ips {
		resolvedIP = normalizeIPv4Mapped(resolvedIP)
		if resolvedIP.Equal(expectedIP) {
			return nil
		}
	}

	// No matching IP found - possible DNS rebinding
	return ErrDNSRebinding
}

// ExtractAndValidateHostIP extracts the hostname from a URL and returns its resolved IP.
// This is useful for capturing the IP at navigation time for later comparison.
// Returns nil IP if the URL uses an IP address directly or if resolution fails.
func ExtractAndValidateHostIP(rawURL string) (net.IP, error) {
	return ExtractAndValidateHostIPWithContext(context.Background(), rawURL)
}

// ExtractAndValidateHostIPWithContext extracts and validates with context support.
// Returns ErrEmptyURL for empty/special URLs, ErrEmptyHostname for empty hostnames,
// and ErrDNSLookupFailed if DNS resolution fails (these are expected conditions, not errors).
func ExtractAndValidateHostIPWithContext(ctx context.Context, rawURL string) (net.IP, error) {
	if rawURL == "" || rawURL == "about:blank" {
		return nil, ErrEmptyURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrInvalidURL
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return nil, ErrEmptyHostname
	}

	// Check if hostname is already an IP
	ip := parseIPWithNormalization(hostname)
	if ip != nil {
		ip = normalizeIPv4Mapped(ip)
		if err := validateIP(ip); err != nil {
			return nil, err
		}
		return ip, nil
	}

	// Resolve hostname with timeout
	ips, err := lookupIPWithTimeout(ctx, hostname)
	if err != nil || len(ips) == 0 {
		return nil, ErrDNSLookupFailed // Allow but don't pin - caller should check for this specific error
	}

	// Validate and return first IP
	firstIP := normalizeIPv4Mapped(ips[0])
	if err := validateIP(firstIP); err != nil {
		return nil, err
	}

	return firstIP, nil
}
