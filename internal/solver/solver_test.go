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

// TestBuildFormFieldsJS_MultilinePostData tests that multiline and special characters
// in POST data are properly escaped via JSON encoding, preventing JavaScript injection.
// This is the Go equivalent fix for Python FlareSolverr PR #1320.
// The Python version breaks when postData contains newlines because string interpolation
// fails. The Go version uses json.Marshal() which properly escapes all special characters.
func TestBuildFormFieldsJS_MultilinePostData(t *testing.T) {
	s := &Solver{}

	tests := []struct {
		name        string
		postData    string
		shouldMatch []string // Strings that should appear in output (JSON-escaped)
		shouldNot   []string // Strings that should NOT appear literally (unescaped)
	}{
		{
			name:     "simple key-value",
			postData: "key=value",
			shouldMatch: []string{
				`"key"`,   // JSON-encoded key
				`"value"`, // JSON-encoded value
			},
		},
		{
			name:     "multiline value - newline in data (PR #1320 bug)",
			postData: "field1=line1%0Aline2", // %0A is URL-encoded newline
			shouldMatch: []string{
				`"field1"`,       // Key should be JSON-encoded
				`"line1\nline2"`, // Value with newline should be JSON-escaped as \n
			},
			shouldNot: []string{
				"line1\nline2", // Raw newline should NOT appear (would break JS)
			},
		},
		{
			name:     "value with quotes",
			postData: "field=%22quoted%22", // %22 is URL-encoded double quote
			shouldMatch: []string{
				`"field"`,
				`"\"quoted\""`, // Quotes should be escaped
			},
		},
		{
			name:     "value with backslash",
			postData: "path=C%3A%5CUsers%5Ctest", // C:\Users\test URL-encoded
			shouldMatch: []string{
				`"path"`,
				`"C:\\Users\\test"`, // Backslashes should be escaped
			},
		},
		{
			name:     "value with script tag (XSS attempt)",
			postData: "xss=%3Cscript%3Ealert(1)%3C%2Fscript%3E", // <script>alert(1)</script>
			shouldMatch: []string{
				`"xss"`,
				`\u003cscript\u003e`, // json.Marshal escapes < > as unicode (even safer)
			},
			shouldNot: []string{
				`<script>`, // Raw script tag should NOT appear
			},
		},
		{
			name:     "complex multiline with special chars",
			postData: "data=line1%0Aline2%0D%0Aline3%09tabbed", // newlines, CRLF, tab
			shouldMatch: []string{
				`"data"`,
				`\n`, // Newline escaped
				`\t`, // Tab escaped
			},
		},
		{
			name:     "multiple fields with special chars",
			postData: "field1=value%0Awith%0Anewlines&field2=has%22quotes%22",
			shouldMatch: []string{
				`"field1"`,
				`"field2"`,
				`\n`, // Newlines escaped
				`\"`, // Quotes escaped
			},
		},
		{
			name:     "empty value",
			postData: "empty=",
			shouldMatch: []string{
				`"empty"`,
				`""`, // Empty string JSON
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.buildFormFieldsJS(tt.postData)
			if err != nil {
				t.Fatalf("buildFormFieldsJS() returned unexpected error: %v", err)
			}

			// Check that expected patterns appear
			for _, pattern := range tt.shouldMatch {
				if !containsString(result, pattern) {
					t.Errorf("buildFormFieldsJS() output should contain %q\nGot: %s", pattern, result)
				}
			}

			// Check that raw (unescaped) patterns do NOT appear
			for _, pattern := range tt.shouldNot {
				if containsString(result, pattern) {
					t.Errorf("buildFormFieldsJS() output should NOT contain raw %q\nGot: %s", pattern, result)
				}
			}

			// Verify the output is valid JavaScript (basic structure check)
			if tt.postData != "" && result != "" {
				if !containsString(result, "document.createElement('input')") {
					t.Error("buildFormFieldsJS() should create input elements")
				}
				if !containsString(result, "form.appendChild") {
					t.Error("buildFormFieldsJS() should append to form")
				}
			}
		})
	}
}

// containsString is a helper to check if a string contains a substring
func containsString(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
