package security

import (
	"net/url"
	"strings"
)

// RedactURL removes sensitive information from a URL for safe logging.
// It redacts:
// - User credentials (user:pass@host)
// - Query parameters that look like secrets
func RedactURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		// If we can't parse it, redact aggressively
		return "[invalid-url]"
	}

	// Redact user credentials
	if parsed.User != nil {
		parsed.User = url.User("[REDACTED]")
	}

	// Redact sensitive query parameters
	if parsed.RawQuery != "" {
		parsed.RawQuery = redactQueryParams(parsed.Query()).Encode()
	}

	return parsed.String()
}

// sensitiveParamPatterns are query parameter names that likely contain secrets
var sensitiveParamPatterns = []string{
	"password",
	"passwd",
	"pwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"api-key",
	"auth",
	"authorization",
	"bearer",
	"credential",
	"key",
	"access_token",
	"refresh_token",
	"session",
	"sessionid",
	"sid",
	"private",
}

func redactQueryParams(params url.Values) url.Values {
	redacted := make(url.Values)

	for key, values := range params {
		keyLower := strings.ToLower(key)
		shouldRedact := false

		for _, pattern := range sensitiveParamPatterns {
			if strings.Contains(keyLower, pattern) {
				shouldRedact = true
				break
			}
		}

		if shouldRedact {
			redacted[key] = []string{"[REDACTED]"}
		} else {
			redacted[key] = values
		}
	}

	return redacted
}

// RedactProxyURL redacts credentials from a proxy URL.
func RedactProxyURL(proxyURL string) string {
	if proxyURL == "" {
		return ""
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return "[invalid-proxy-url]"
	}

	// Redact credentials
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			parsed.User = url.UserPassword(parsed.User.Username(), "[REDACTED]")
		}
	}

	return parsed.String()
}
