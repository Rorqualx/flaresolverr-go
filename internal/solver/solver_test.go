package solver

import (
	"testing"
)

func TestDetectChallenge(t *testing.T) {
	s := &Solver{}

	tests := []struct {
		name     string
		html     string
		expected ChallengeType
	}{
		{
			name:     "no challenge - normal page",
			html:     "<html><head><title>Test</title></head><body>Normal content</body></html>",
			expected: ChallengeNone,
		},
		{
			name:     "no challenge - empty page",
			html:     "<html><body></body></html>",
			expected: ChallengeNone,
		},
		{
			name:     "js challenge - just a moment",
			html:     "<html><body>Just a moment... Checking your browser before accessing</body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "js challenge - checking your browser",
			html:     "<html><body>Checking your browser before accessing example.com</body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "js challenge - please wait",
			html:     "<html><body>Please wait while we verify your browser...</body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "js challenge - cf_chl_opt",
			html:     "<html><head><script>var __cf_chl_opt = {};</script></head><body></body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "js challenge - cf-challenge class",
			html:     "<html><body><div class=\"cf-challenge\">Challenge</div></body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "js challenge - ddos-guard",
			html:     "<html><body>Protected by DDoS-Guard</body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "turnstile challenge - cf-turnstile",
			html:     "<html><body><div class=\"cf-turnstile\"></div></body></html>",
			expected: ChallengeTurnstile,
		},
		{
			name:     "turnstile challenge - challenges url",
			html:     "<html><body><iframe src=\"https://challenges.cloudflare.com/turnstile/v0/\"></iframe></body></html>",
			expected: ChallengeTurnstile,
		},
		{
			name:     "turnstile challenge - turnstile-wrapper",
			html:     "<html><body><div class=\"turnstile-wrapper\"></div></body></html>",
			expected: ChallengeTurnstile,
		},
		{
			name:     "access denied - with cloudflare",
			html:     "<html><body>Access denied Cloudflare Ray ID: abc123</body></html>",
			expected: ChallengeAccessDenied,
		},
		{
			name:     "access denied - error 1015",
			html:     "<html><body>Error 1015 Cloudflare - You are being rate limited</body></html>",
			expected: ChallengeAccessDenied,
		},
		{
			name:     "access denied - error 1020",
			html:     "<html><body>Error 1020 Cloudflare Access Denied</body></html>",
			expected: ChallengeAccessDenied,
		},
		{
			name:     "access denied - blocked",
			html:     "<html><body>You have been blocked by Cloudflare</body></html>",
			expected: ChallengeAccessDenied,
		},
		{
			name:     "access denied without cloudflare - not detected",
			html:     "<html><body>Access denied</body></html>",
			expected: ChallengeNone,
		},
		{
			name:     "case insensitive - JUST A MOMENT",
			html:     "<html><body>JUST A MOMENT...</body></html>",
			expected: ChallengeJavaScript,
		},
		{
			name:     "mixed content - turnstile takes precedence over js",
			html:     "<html><body>Just a moment <div class=\"cf-turnstile\"></div></body></html>",
			expected: ChallengeTurnstile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.detectChallenge(tt.html)
			if got != tt.expected {
				t.Errorf("detectChallenge() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestChallengeTypeString(t *testing.T) {
	// Test that challenge types have expected values
	if ChallengeNone != 0 {
		t.Errorf("ChallengeNone should be 0, got %d", ChallengeNone)
	}
	if ChallengeJavaScript != 1 {
		t.Errorf("ChallengeJavaScript should be 1, got %d", ChallengeJavaScript)
	}
	if ChallengeTurnstile != 2 {
		t.Errorf("ChallengeTurnstile should be 2, got %d", ChallengeTurnstile)
	}
	if ChallengeAccessDenied != 3 {
		t.Errorf("ChallengeAccessDenied should be 3, got %d", ChallengeAccessDenied)
	}
}

func TestNewSolver(t *testing.T) {
	userAgent := "TestAgent/1.0"
	s := New(nil, userAgent)

	if s == nil {
		t.Fatal("New() returned nil")
	}

	if s.userAgent != userAgent {
		t.Errorf("userAgent = %q, want %q", s.userAgent, userAgent)
	}
}

func TestSolveOptionsDefaults(t *testing.T) {
	opts := &SolveOptions{
		URL: "https://example.com",
	}

	if opts.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", opts.URL, "https://example.com")
	}

	if opts.IsPost != false {
		t.Error("IsPost should default to false")
	}

	if opts.Proxy != nil {
		t.Error("Proxy should default to nil")
	}

	if len(opts.Cookies) != 0 {
		t.Error("Cookies should default to empty")
	}
}
