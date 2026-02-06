package security

import (
	"strings"
	"testing"
)

// FuzzValidateSessionID tests session ID validation with fuzzed inputs.
// Run with: go test -fuzz=FuzzValidateSessionID -fuzztime=60s ./internal/security/
func FuzzValidateSessionID(f *testing.F) {
	// Seed corpus with known test cases
	seeds := []string{
		// Valid session IDs (min 8 chars)
		"test-session-123",
		"abc12345",
		"my_session",
		"Session-1",
		"abcdefgh",              // Min length (8 chars)
		strings.Repeat("a", 64), // Max length

		// Invalid - too long
		strings.Repeat("a", 65),
		strings.Repeat("a", 100),

		// Invalid - special characters
		"session<script>",
		"../../../etc/passwd",
		"..\\..\\windows",
		"session\x00null",
		"session\t\n",
		"__proto__",
		"constructor",
		"javascript:alert(1)",

		// Empty
		"",

		// Unicode
		"session-日本語",
		"session-émoji-🎉",

		// Null bytes and control characters
		"test\x00session",
		"test\ntest",
		"test\rtest",

		// SQL injection attempts
		"' OR '1'='1",
		"1; DROP TABLE sessions--",

		// XSS attempts
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, sessionID string) {
		// Should never panic
		result := ValidateSessionID(sessionID)

		// Empty session ID should always fail
		if len(sessionID) == 0 && result == "" {
			t.Error("empty session ID should return error message")
		}

		// Valid session ID should have empty error
		if result == "" {
			// If valid, check invariants
			if len(sessionID) > MaxSessionIDLength {
				t.Errorf("session ID longer than max length was accepted: len=%d", len(sessionID))
			}
			if len(sessionID) < MinSessionIDLength {
				t.Errorf("session ID shorter than min length was accepted: len=%d", len(sessionID))
			}

			// Should not contain dangerous patterns
			idLower := strings.ToLower(sessionID)
			dangerousPatterns := []string{"../", "..\\", "<script", "javascript:", "__proto__", "constructor"}
			for _, pattern := range dangerousPatterns {
				if strings.Contains(idLower, pattern) {
					t.Errorf("session ID with dangerous pattern was accepted: %q contains %q", sessionID, pattern)
				}
			}
		}

		// If result indicates "too long", verify length
		if strings.Contains(result, "too long") && len(sessionID) <= MaxSessionIDLength {
			t.Errorf("session ID wrongly rejected as too long: len=%d, max=%d", len(sessionID), MaxSessionIDLength)
		}

		// Path traversal should always be blocked
		if (strings.Contains(sessionID, "../") || strings.Contains(sessionID, "..\\")) && result == "" {
			t.Errorf("path traversal attempt was accepted: %q", sessionID)
		}
	})
}

// FuzzGenerateSessionID ensures generated session IDs pass validation.
func FuzzGenerateSessionID(f *testing.F) {
	// This isn't a traditional fuzz test but ensures consistency
	f.Add(0) // Dummy seed

	f.Fuzz(func(t *testing.T, _ int) {
		// Generate a session ID
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("GenerateSessionID failed: %v", err)
		}

		// Generated ID should always pass validation
		if validationErr := ValidateSessionID(id); validationErr != "" {
			t.Errorf("Generated session ID failed validation: id=%q, error=%q", id, validationErr)
		}

		// ID should have expected length (48 hex chars = 24 bytes)
		if len(id) != 48 {
			t.Errorf("Generated session ID has unexpected length: %d (expected 48)", len(id))
		}
	})
}
