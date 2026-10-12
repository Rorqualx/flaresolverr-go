package security

import (
	"fmt"
	"net"
	"strings"
)

// ValidateIP reports whether ip is a public address that a request may be
// sent to. It is the same check ValidateURL applies to every address a
// hostname resolves to: loopback, private, link-local, cloud metadata,
// unspecified and all other special-purpose ranges are refused, and an
// IPv4 address embedded in an IPv6 one (mapped, NAT64, 6to4) is checked as
// if it had been given directly.
//
// It exists so that code which dials on a caller's behalf (the egress guard)
// applies exactly the rules the URL validator applies, instead of a copy that
// can drift.
func ValidateIP(ip net.IP) error {
	if ip == nil {
		return ErrBlockedHost
	}
	return validateIP(normalizeIPv4Mapped(ip))
}

// ClassifyEgressHost decides, without any DNS lookup, what a destination
// hostname is.
//
//   - A name the validator always refuses (localhost and its variants, cloud
//     metadata names, an invalid IDN) returns an error.
//   - An IP literal, in any encoding a browser accepts (dotted, decimal, octal,
//     hex, shortened, IPv4-mapped IPv6), returns the address it denotes after
//     it has passed ValidateIP, or the error ValidateIP gave.
//   - Anything else is a name that needs resolving: it returns a nil address
//     and a nil error.
//
// hostname must not include a port or IPv6 brackets.
func ClassifyEgressHost(hostname string) (literal net.IP, err error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return nil, ErrEmptyHostname
	}

	// A trailing dot only marks the name as fully qualified; "localhost."
	// is localhost.
	name := strings.TrimSuffix(hostname, ".")
	if name == "" {
		return nil, ErrEmptyHostname
	}

	if BlockedHosts[name] || isLocalhostHostname(name) {
		return nil, ErrLocalhostBlocked
	}
	if isCloudMetadataHost(name) {
		return nil, ErrMetadataBlocked
	}
	if err := validateIDN(name); err != nil {
		return nil, err
	}

	ip := parseIPWithNormalization(name)
	if ip == nil {
		return nil, nil // a name: the caller resolves it
	}
	ip = normalizeIPv4Mapped(ip)
	if err := validateIP(ip); err != nil {
		return nil, fmt.Errorf("address %s: %w", ip.String(), err)
	}
	return ip, nil
}
