// Package security provides security utilities for input validation.
package security

import (
	"errors"
	"fmt"
	"strings"
)

// Header validation constants.
const (
	MaxHeaderCount       = 50
	MaxHeaderNameLength  = 256
	MaxHeaderValueLength = 8192  // 8KB per header
	MaxTotalHeadersSize  = 65536 // 64KB total for all headers combined
)

// Header validation errors.
var (
	ErrTooManyHeaders      = errors.New("too many headers (maximum 50)")
	ErrHeaderNameTooLong   = errors.New("header name exceeds maximum length of 256 bytes")
	ErrHeaderValueTooLong  = errors.New("header value exceeds maximum length of 8KB")
	ErrTotalHeadersTooLong = errors.New("total headers size exceeds maximum of 64KB")
	ErrHeaderNameEmpty     = errors.New("header name cannot be empty")
	ErrBlockedHeader       = errors.New("header is not allowed for security reasons")
	ErrInvalidHeaderName   = errors.New("header name contains invalid characters")
	ErrInvalidHeaderChar   = errors.New("header value contains invalid characters")
)

// blockedHeaders contains header names that are forbidden for security reasons.
// These headers could be used to bypass security controls or cause issues.
var blockedHeaders = map[string]bool{
	// Connection control headers (could interfere with browser behavior)
	"host":              true,
	"connection":        true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"content-length":    true,
	"te":                true,
	"trailer":           true,
	"upgrade":           true,

	// Authentication bypass headers
	"cookie":              true,
	"authorization":       true,
	"proxy-authorization": true,
	"www-authenticate":    true,
	"proxy-authenticate":  true,

	// Origin/referrer spoofing (browser will set these correctly)
	"origin":  true,
	"referer": true,
}

// blockedHeaderPrefixes contains prefixes of headers that are forbidden.
// Headers starting with these prefixes are typically set by the browser or CDN
// and should not be overridden.
var blockedHeaderPrefixes = []string{
	"sec-",         // Fetch Metadata headers (sec-fetch-*, sec-ch-*)
	"cf-",          // Cloudflare headers
	"x-forwarded-", // Proxy headers
	"proxy-",       // Proxy headers
	"x-real-",      // Reverse proxy headers
	"x-amz-",       // AWS headers
	"x-goog-",      // Google Cloud headers
}

// ValidateHeaders validates a map of custom headers for security.
// Returns an error if any header violates security constraints.
// Fix: Added aggregate size limit to prevent memory exhaustion attacks.
func ValidateHeaders(headers map[string]string) error {
	if headers == nil {
		return nil
	}

	// Check total count
	if len(headers) > MaxHeaderCount {
		return ErrTooManyHeaders
	}

	// Track total size for aggregate limit
	var totalSize int

	for name, value := range headers {
		if err := validateHeaderName(name); err != nil {
			return fmt.Errorf("invalid header name %q: %w", name, err)
		}

		if err := validateHeaderValue(value); err != nil {
			return fmt.Errorf("invalid value for header %q: %w", name, err)
		}

		// Accumulate total size (name + value + overhead for ": " and newline)
		totalSize += len(name) + len(value) + 4
		if totalSize > MaxTotalHeadersSize {
			return ErrTotalHeadersTooLong
		}
	}

	return nil
}

// validateHeaderName checks if a header name is valid and allowed.
func validateHeaderName(name string) error {
	if name == "" {
		return ErrHeaderNameEmpty
	}

	if len(name) > MaxHeaderNameLength {
		return ErrHeaderNameTooLong
	}

	// Check for invalid characters (header names should be ASCII, no control chars or spaces)
	for _, c := range name {
		if c < 33 || c > 126 || c == ':' {
			return ErrInvalidHeaderName
		}
	}

	// Normalize to lowercase for comparison
	nameLower := strings.ToLower(name)

	// Check against blocked headers
	if blockedHeaders[nameLower] {
		return ErrBlockedHeader
	}

	// Check against blocked prefixes
	for _, prefix := range blockedHeaderPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			return ErrBlockedHeader
		}
	}

	return nil
}

// validateHeaderValue checks if a header value is valid.
// Fix #36: Rejects control characters INCLUDING tabs and non-ASCII characters
// to prevent header injection attacks. While RFC 7230 technically allows tabs
// in header values, rejecting them provides stricter security against potential
// parsing inconsistencies between different HTTP implementations.
func validateHeaderValue(value string) error {
	if len(value) > MaxHeaderValueLength {
		return ErrHeaderValueTooLong
	}

	// Check for control characters and non-ASCII characters
	// Fix #36: Only allow printable ASCII (32-126), reject tabs for stricter security
	// Note: Character 127 (DEL) is a control character and must be rejected
	for _, c := range value {
		// Fix #36: Tabs are rejected (stricter than RFC 7230 but safer)
		if c < 32 || c >= 127 {
			return ErrInvalidHeaderChar
		}
	}

	return nil
}
