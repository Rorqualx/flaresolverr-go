package ratelimit

import (
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		body           string
		wantDetected   bool
		wantCode       string
		wantCategory   ErrorCategory
		wantDelayRange [2]int // min, max acceptable delay
	}{
		{
			name:           "cloudflare 1015 rate limit",
			statusCode:     429,
			body:           "<html><body>Error code: 1015 - You are being rate limited</body></html>",
			wantDetected:   true,
			wantCode:       "CF_1015",
			wantCategory:   CategoryRateLimit,
			wantDelayRange: [2]int{60000, 60000},
		},
		{
			name:           "cloudflare 1020 access denied",
			statusCode:     403,
			body:           "<html><body>Error code: 1020 - Access denied</body></html>",
			wantDetected:   true,
			wantCode:       "CF_1020",
			wantCategory:   CategoryAccessDenied,
			wantDelayRange: [2]int{30000, 30000},
		},
		{
			name:           "cloudflare 1009 geo blocked",
			statusCode:     403,
			body:           "<html><body>Error code: 1009 - Access denied due to your region</body></html>",
			wantDetected:   true,
			wantCode:       "CF_1009",
			wantCategory:   CategoryGeoBlocked,
			wantDelayRange: [2]int{0, 0},
		},
		{
			name:           "generic access denied",
			statusCode:     403,
			body:           "<html><body>Access denied. Please try again later.</body></html>",
			wantDetected:   true,
			wantCode:       "ACCESS_DENIED",
			wantCategory:   CategoryAccessDenied,
			wantDelayRange: [2]int{5000, 5000},
		},
		{
			name:           "generic rate limit text",
			statusCode:     400,
			body:           "<html><body>Rate limit exceeded. Please slow down.</body></html>",
			wantDetected:   true,
			wantCode:       "RATE_LIMITED",
			wantCategory:   CategoryRateLimit,
			wantDelayRange: [2]int{10000, 10000},
		},
		{
			name:           "too many requests",
			statusCode:     403,
			body:           "<html><body>Too many requests from your IP</body></html>",
			wantDetected:   true,
			wantCode:       "TOO_MANY_REQUESTS",
			wantCategory:   CategoryRateLimit,
			wantDelayRange: [2]int{10000, 10000},
		},
		{
			name:           "http 429 without body pattern",
			statusCode:     429,
			body:           "<html><body>Please wait</body></html>",
			wantDetected:   true,
			wantCode:       "HTTP_429",
			wantCategory:   CategoryRateLimit,
			wantDelayRange: [2]int{60000, 60000},
		},
		{
			name:           "http 503 service unavailable",
			statusCode:     503,
			body:           "<html><body>Service temporarily unavailable</body></html>",
			wantDetected:   true,
			wantCode:       "HTTP_503",
			wantCategory:   CategoryRateLimit,
			wantDelayRange: [2]int{30000, 30000},
		},
		{
			name:           "cloudflare 403 generic",
			statusCode:     403,
			body:           "<html><body>Sorry, you have been blocked. Cloudflare Ray ID: abc123</body></html>",
			wantDetected:   true,
			wantCode:       "BLOCKED",
			wantCategory:   CategoryAccessDenied,
			wantDelayRange: [2]int{15000, 15000},
		},
		{
			name:           "captcha required",
			statusCode:     403,
			body:           "<html><body>Please complete the CAPTCHA to continue</body></html>",
			wantDetected:   true,
			wantCode:       "CAPTCHA_REQUIRED",
			wantCategory:   CategoryCaptcha,
			wantDelayRange: [2]int{0, 0},
		},
		{
			name:           "normal 200 response",
			statusCode:     200,
			body:           "<html><body>Hello World</body></html>",
			wantDetected:   false,
			wantCode:       "",
			wantCategory:   "",
			wantDelayRange: [2]int{0, 0},
		},
		{
			name:           "normal 404 response",
			statusCode:     404,
			body:           "<html><body>Page not found</body></html>",
			wantDetected:   false,
			wantCode:       "",
			wantCategory:   "",
			wantDelayRange: [2]int{0, 0},
		},
		{
			name:           "case insensitive access denied",
			statusCode:     403,
			body:           "<html><body>ACCESS DENIED - You cannot access this page</body></html>",
			wantDetected:   true,
			wantCode:       "ACCESS_DENIED",
			wantCategory:   CategoryAccessDenied,
			wantDelayRange: [2]int{5000, 5000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := Detect(tt.statusCode, tt.body)

			if info.Detected != tt.wantDetected {
				t.Errorf("Detected = %v, want %v", info.Detected, tt.wantDetected)
			}

			if info.ErrorCode != tt.wantCode {
				t.Errorf("ErrorCode = %v, want %v", info.ErrorCode, tt.wantCode)
			}

			if info.Category != tt.wantCategory {
				t.Errorf("Category = %v, want %v", info.Category, tt.wantCategory)
			}

			if info.SuggestedDelay < tt.wantDelayRange[0] || info.SuggestedDelay > tt.wantDelayRange[1] {
				t.Errorf("SuggestedDelay = %v, want between %v and %v",
					info.SuggestedDelay, tt.wantDelayRange[0], tt.wantDelayRange[1])
			}
		})
	}
}

func TestAdjustDelay(t *testing.T) {
	tests := []struct {
		name      string
		baseDelay int
		minDelay  int
		maxDelay  int
		want      int
	}{
		{
			name:      "within bounds",
			baseDelay: 5000,
			minDelay:  1000,
			maxDelay:  30000,
			want:      5000,
		},
		{
			name:      "below minimum",
			baseDelay: 500,
			minDelay:  1000,
			maxDelay:  30000,
			want:      1000,
		},
		{
			name:      "above maximum",
			baseDelay: 60000,
			minDelay:  1000,
			maxDelay:  30000,
			want:      30000,
		},
		{
			name:      "at minimum",
			baseDelay: 1000,
			minDelay:  1000,
			maxDelay:  30000,
			want:      1000,
		},
		{
			name:      "at maximum",
			baseDelay: 30000,
			minDelay:  1000,
			maxDelay:  30000,
			want:      30000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AdjustDelay(tt.baseDelay, tt.minDelay, tt.maxDelay)
			if got != tt.want {
				t.Errorf("AdjustDelay(%d, %d, %d) = %d, want %d",
					tt.baseDelay, tt.minDelay, tt.maxDelay, got, tt.want)
			}
		})
	}
}

// TestDetect_GenericPatternsNeedErrorStatus verifies the generic phrases are
// only treated as rate limiting on an HTTP error response. On an ordinary page
// they match script identifiers and prose, which used to mark successful
// requests as rate limited and inflate the domain's suggested delay.
func TestDetect_GenericPatternsNeedErrorStatus(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantDetected bool
		wantCode     string
	}{
		{
			name:       "200 page with rateLimit identifier in script",
			statusCode: 200,
			body:       "<html><script>const rateLimit = 5; api.setRateLimiter(rateLimit);</script><body>Welcome</body></html>",
		},
		{
			name:       "200 help article about access denied",
			statusCode: 200,
			body:       "<html><body><h1>Why do I see Access Denied on my router?</h1></body></html>",
		},
		{
			name:       "200 page mentioning too many requests",
			statusCode: 200,
			body:       "<html><body>HTTP 429 means too many requests were sent.</body></html>",
		},
		{
			name:       "301 page mentioning blocked",
			statusCode: 301,
			body:       "<html><body>You have been blocked by this user.</body></html>",
		},
		{
			name:         "200 page with a Cloudflare error code is still detected",
			statusCode:   200,
			body:         "<html><body>Error code: 1015 - You are being rate limited</body></html>",
			wantDetected: true,
			wantCode:     "CF_1015",
		},
		{
			name:         "403 with rate limit text",
			statusCode:   403,
			body:         "<html><body>Rate limit exceeded</body></html>",
			wantDetected: true,
			wantCode:     "RATE_LIMITED",
		},
		{
			name:         "429 with generic text keeps the more specific body code",
			statusCode:   429,
			body:         "<html><body>Too many requests</body></html>",
			wantDetected: true,
			wantCode:     "TOO_MANY_REQUESTS",
		},
		{
			name:         "400 with access denied",
			statusCode:   400,
			body:         "<html><body>Access denied</body></html>",
			wantDetected: true,
			wantCode:     "ACCESS_DENIED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.statusCode, tt.body)
			if got.Detected != tt.wantDetected {
				t.Fatalf("Detected = %v, want %v (code %q)", got.Detected, tt.wantDetected, got.ErrorCode)
			}
			if got.ErrorCode != tt.wantCode {
				t.Errorf("ErrorCode = %q, want %q", got.ErrorCode, tt.wantCode)
			}
		})
	}
}
