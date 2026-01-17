// Package ratelimit provides rate limit detection for responses from target sites.
package ratelimit

import (
	"regexp"
	"strings"
)

// maxBodyLenForRegex limits the body size for regex matching to prevent ReDoS attacks.
// 100KB is sufficient for detecting rate limit messages while preventing abuse.
const maxBodyLenForRegex = 100 * 1024

// ErrorCategory represents the broad category of a detected error.
type ErrorCategory string

// Error categories.
const (
	CategoryRateLimit    ErrorCategory = "rate_limit"
	CategoryAccessDenied ErrorCategory = "access_denied"
	CategoryCaptcha      ErrorCategory = "captcha"
	CategoryGeoBlocked   ErrorCategory = "geo_blocked"
)

// ErrorPattern defines a detection pattern and its metadata.
type ErrorPattern struct {
	Pattern     *regexp.Regexp
	ErrorCode   string
	Category    ErrorCategory
	BaseDelayMs int
	Description string
}

// Info contains detected rate limit information.
type Info struct {
	Detected       bool
	ErrorCode      string
	Category       ErrorCategory
	SuggestedDelay int
	Description    string
}

// patterns contains all detection patterns, ordered by specificity.
// Patterns use [^<]{0,N} instead of .{0,N} to prevent backtracking on HTML content
// and reduce ReDoS vulnerability while still matching across element boundaries.
var patterns = []ErrorPattern{
	// Cloudflare-specific errors (most specific first)
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1015`),
		ErrorCode:   "CF_1015",
		Category:    CategoryRateLimit,
		BaseDelayMs: 60000,
		Description: "Cloudflare rate limit exceeded",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1020`),
		ErrorCode:   "CF_1020",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 30000,
		Description: "Cloudflare access denied - suspicious request",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1006`),
		ErrorCode:   "CF_1006",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 30000,
		Description: "Cloudflare access denied",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1007`),
		ErrorCode:   "CF_1007",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 30000,
		Description: "Cloudflare access denied",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1008`),
		ErrorCode:   "CF_1008",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 30000,
		Description: "Cloudflare access denied",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1009`),
		ErrorCode:   "CF_1009",
		Category:    CategoryGeoBlocked,
		BaseDelayMs: 0, // No retry will help
		Description: "Cloudflare geo-restriction",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1010`),
		ErrorCode:   "CF_1010",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 30000,
		Description: "Cloudflare browser signature rejected",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)error[^<]{0,10}code[^<]{0,5}:?\s{0,5}1012`),
		ErrorCode:   "CF_1012",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 30000,
		Description: "Cloudflare access denied",
	},

	// Generic patterns (less specific, checked after Cloudflare codes)
	{
		Pattern:     regexp.MustCompile(`(?i)access\s{1,5}denied`),
		ErrorCode:   "ACCESS_DENIED",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 5000,
		Description: "Generic access denied",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)rate\s{0,3}limit`),
		ErrorCode:   "RATE_LIMITED",
		Category:    CategoryRateLimit,
		BaseDelayMs: 10000,
		Description: "Generic rate limit",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)too\s{1,5}many\s{1,5}requests`),
		ErrorCode:   "TOO_MANY_REQUESTS",
		Category:    CategoryRateLimit,
		BaseDelayMs: 10000,
		Description: "Too many requests",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)you\s{1,5}(have\s{1,5}been\s{1,5})?blocked`),
		ErrorCode:   "BLOCKED",
		Category:    CategoryAccessDenied,
		BaseDelayMs: 15000,
		Description: "Request blocked",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)(captcha|hcaptcha|recaptcha|challenge)`),
		ErrorCode:   "CAPTCHA_REQUIRED",
		Category:    CategoryCaptcha,
		BaseDelayMs: 0, // Manual intervention needed
		Description: "CAPTCHA or challenge required",
	},
}

// Detect analyzes HTTP status code and response body for rate limiting indicators.
// It returns information about any detected rate limiting, including a suggested delay.
// Body is truncated to maxBodyLenForRegex to prevent ReDoS attacks with large inputs.
func Detect(statusCode int, body string) Info {
	info := Info{}

	// Truncate body to prevent ReDoS attacks with large inputs
	if len(body) > maxBodyLenForRegex {
		body = body[:maxBodyLenForRegex]
	}

	// Check HTTP status first
	switch statusCode {
	case 429:
		info = Info{
			Detected:       true,
			ErrorCode:      "HTTP_429",
			Category:       CategoryRateLimit,
			SuggestedDelay: 60000,
			Description:    "HTTP 429 Too Many Requests",
		}
	case 503:
		info = Info{
			Detected:       true,
			ErrorCode:      "HTTP_503",
			Category:       CategoryRateLimit,
			SuggestedDelay: 30000,
			Description:    "HTTP 503 Service Unavailable",
		}
	}

	// Check body patterns (may override HTTP status detection with more specific info)
	for _, pattern := range patterns {
		if pattern.Pattern.MatchString(body) {
			info = Info{
				Detected:       true,
				ErrorCode:      pattern.ErrorCode,
				Category:       pattern.Category,
				SuggestedDelay: pattern.BaseDelayMs,
				Description:    pattern.Description,
			}
			break // Use first match (patterns ordered by specificity)
		}
	}

	// Check for Cloudflare in 403 responses without specific error code
	if statusCode == 403 && !info.Detected {
		if strings.Contains(strings.ToLower(body), "cloudflare") {
			info = Info{
				Detected:       true,
				ErrorCode:      "CF_403",
				Category:       CategoryAccessDenied,
				SuggestedDelay: 30000,
				Description:    "Cloudflare 403 Forbidden",
			}
		}
	}

	return info
}

// AdjustDelay modifies the suggested delay based on external factors.
// This can be used by domain stats to increase delays based on history.
func AdjustDelay(baseDelay, minDelay, maxDelay int) int {
	if baseDelay < minDelay {
		return minDelay
	}
	if baseDelay > maxDelay {
		return maxDelay
	}
	return baseDelay
}
