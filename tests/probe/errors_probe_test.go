package probe

import (
	"errors"
	"testing"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// TestChallengeError_Interface tests that ChallengeError implements the error interface correctly.
func TestChallengeError_Interface(t *testing.T) {
	tests := []struct {
		name            string
		challengeError  *types.ChallengeError
		expectedMessage string
	}{
		{
			name: "access_denied_error",
			challengeError: &types.ChallengeError{
				Type:    "access_denied",
				URL:     "https://example.com",
				Message: "Access denied by target site",
				Err:     types.ErrAccessDenied,
			},
			expectedMessage: "Access denied by target site",
		},
		{
			name: "timeout_error",
			challengeError: &types.ChallengeError{
				Type:    "timeout",
				URL:     "https://example.com/slow",
				Message: "Challenge resolution timed out",
				Err:     types.ErrChallengeTimeout,
			},
			expectedMessage: "Challenge resolution timed out",
		},
		{
			name: "unsolvable_error",
			challengeError: &types.ChallengeError{
				Type:    "unsolvable",
				URL:     "https://example.com/captcha",
				Message: "Challenge could not be solved: CAPTCHA required",
				Err:     types.ErrChallengeUnsolvable,
			},
			expectedMessage: "Challenge could not be solved: CAPTCHA required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Error() method
			if got := tt.challengeError.Error(); got != tt.expectedMessage {
				t.Errorf("Error() = %q, want %q", got, tt.expectedMessage)
			}

			// Verify it implements error interface
			var err error = tt.challengeError
			if err.Error() != tt.expectedMessage {
				t.Errorf("error interface Error() = %q, want %q", err.Error(), tt.expectedMessage)
			}
		})
	}
}

// TestChallengeError_Unwrap tests that ChallengeError.Unwrap() returns the underlying error.
func TestChallengeError_Unwrap(t *testing.T) {
	tests := []struct {
		name        string
		err         *types.ChallengeError
		expectedErr error
	}{
		{
			name: "unwrap_access_denied",
			err: &types.ChallengeError{
				Type:    "access_denied",
				URL:     "https://example.com",
				Message: "Access denied",
				Err:     types.ErrAccessDenied,
			},
			expectedErr: types.ErrAccessDenied,
		},
		{
			name: "unwrap_timeout",
			err: &types.ChallengeError{
				Type:    "timeout",
				URL:     "https://example.com",
				Message: "Timeout",
				Err:     types.ErrChallengeTimeout,
			},
			expectedErr: types.ErrChallengeTimeout,
		},
		{
			name: "unwrap_nil",
			err: &types.ChallengeError{
				Type:    "unknown",
				URL:     "https://example.com",
				Message: "Unknown error",
				Err:     nil,
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := tt.err.Unwrap()
			if unwrapped != tt.expectedErr {
				t.Errorf("Unwrap() = %v, want %v", unwrapped, tt.expectedErr)
			}
		})
	}
}

// TestChallengeError_ErrorsIs tests that errors.Is() works correctly with wrapped sentinel errors.
func TestChallengeError_ErrorsIs(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   error
		expected bool
	}{
		{
			name:     "is_access_denied",
			err:      types.NewAccessDeniedError("https://example.com"),
			target:   types.ErrAccessDenied,
			expected: true,
		},
		{
			name:     "is_challenge_timeout",
			err:      types.NewChallengeTimeoutError("https://example.com"),
			target:   types.ErrChallengeTimeout,
			expected: true,
		},
		{
			name:     "is_unsolvable",
			err:      types.NewUnsolvableChallengeError("https://example.com", "CAPTCHA required"),
			target:   types.ErrChallengeUnsolvable,
			expected: true,
		},
		{
			name:     "not_is_wrong_sentinel",
			err:      types.NewAccessDeniedError("https://example.com"),
			target:   types.ErrChallengeTimeout,
			expected: false,
		},
		{
			name:     "not_is_session_error",
			err:      types.NewAccessDeniedError("https://example.com"),
			target:   types.ErrSessionNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.expected {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.target, got, tt.expected)
			}
		})
	}
}

// TestChallengeError_ErrorsAs tests that errors.As() can extract ChallengeError details.
func TestChallengeError_ErrorsAs(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedType string
		expectedURL  string
	}{
		{
			name:         "as_access_denied",
			err:          types.NewAccessDeniedError("https://blocked.com"),
			expectedType: "access_denied",
			expectedURL:  "https://blocked.com",
		},
		{
			name:         "as_timeout",
			err:          types.NewChallengeTimeoutError("https://slow.com"),
			expectedType: "timeout",
			expectedURL:  "https://slow.com",
		},
		{
			name:         "as_unsolvable",
			err:          types.NewUnsolvableChallengeError("https://captcha.com", "manual intervention required"),
			expectedType: "unsolvable",
			expectedURL:  "https://captcha.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var challengeErr *types.ChallengeError
			if !errors.As(tt.err, &challengeErr) {
				t.Fatalf("errors.As() failed to extract ChallengeError")
			}

			if challengeErr.Type != tt.expectedType {
				t.Errorf("Type = %q, want %q", challengeErr.Type, tt.expectedType)
			}
			if challengeErr.URL != tt.expectedURL {
				t.Errorf("URL = %q, want %q", challengeErr.URL, tt.expectedURL)
			}
			if challengeErr.Message == "" {
				t.Error("Message should not be empty")
			}
		})
	}
}

// TestPoolError_Interface tests that PoolError implements the error interface correctly.
func TestPoolError_Interface(t *testing.T) {
	tests := []struct {
		name            string
		poolError       *types.PoolError
		expectedMessage string
	}{
		{
			name: "acquire_error",
			poolError: &types.PoolError{
				Operation: "acquire",
				Message:   "Failed to acquire browser from pool: timeout",
				Err:       types.ErrBrowserPoolTimeout,
			},
			expectedMessage: "Failed to acquire browser from pool: timeout",
		},
		{
			name: "exhausted_error",
			poolError: &types.PoolError{
				Operation: "acquire",
				Message:   "Failed to acquire browser from pool: pool exhausted",
				Err:       types.ErrBrowserPoolExhausted,
			},
			expectedMessage: "Failed to acquire browser from pool: pool exhausted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Error() method
			if got := tt.poolError.Error(); got != tt.expectedMessage {
				t.Errorf("Error() = %q, want %q", got, tt.expectedMessage)
			}

			// Verify it implements error interface
			var err error = tt.poolError
			if err.Error() != tt.expectedMessage {
				t.Errorf("error interface Error() = %q, want %q", err.Error(), tt.expectedMessage)
			}
		})
	}
}

// TestPoolError_Unwrap tests that PoolError.Unwrap() returns the underlying error.
func TestPoolError_Unwrap(t *testing.T) {
	tests := []struct {
		name        string
		err         *types.PoolError
		expectedErr error
	}{
		{
			name: "unwrap_timeout",
			err: &types.PoolError{
				Operation: "acquire",
				Message:   "timeout",
				Err:       types.ErrBrowserPoolTimeout,
			},
			expectedErr: types.ErrBrowserPoolTimeout,
		},
		{
			name: "unwrap_exhausted",
			err: &types.PoolError{
				Operation: "acquire",
				Message:   "exhausted",
				Err:       types.ErrBrowserPoolExhausted,
			},
			expectedErr: types.ErrBrowserPoolExhausted,
		},
		{
			name: "unwrap_nil",
			err: &types.PoolError{
				Operation: "release",
				Message:   "some error",
				Err:       nil,
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := tt.err.Unwrap()
			if unwrapped != tt.expectedErr {
				t.Errorf("Unwrap() = %v, want %v", unwrapped, tt.expectedErr)
			}
		})
	}
}

// TestPoolError_ErrorsIs tests that errors.Is() works correctly with wrapped pool errors.
func TestPoolError_ErrorsIs(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   error
		expected bool
	}{
		{
			name:     "is_pool_timeout",
			err:      types.NewPoolAcquireError("timeout waiting", types.ErrBrowserPoolTimeout),
			target:   types.ErrBrowserPoolTimeout,
			expected: true,
		},
		{
			name:     "is_pool_exhausted",
			err:      types.NewPoolAcquireError("no browsers available", types.ErrBrowserPoolExhausted),
			target:   types.ErrBrowserPoolExhausted,
			expected: true,
		},
		{
			name:     "not_is_wrong_error",
			err:      types.NewPoolAcquireError("timeout", types.ErrBrowserPoolTimeout),
			target:   types.ErrBrowserPoolExhausted,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.expected {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.target, got, tt.expected)
			}
		})
	}
}

// TestErrorFactoryFunctions tests that error factory functions create correct structures.
func TestErrorFactoryFunctions(t *testing.T) {
	t.Run("NewAccessDeniedError", func(t *testing.T) {
		err := types.NewAccessDeniedError("https://blocked.example.com")

		if err.Type != "access_denied" {
			t.Errorf("Type = %q, want %q", err.Type, "access_denied")
		}
		if err.URL != "https://blocked.example.com" {
			t.Errorf("URL = %q, want %q", err.URL, "https://blocked.example.com")
		}
		if err.Err != types.ErrAccessDenied {
			t.Errorf("Err = %v, want %v", err.Err, types.ErrAccessDenied)
		}
		if err.Message == "" {
			t.Error("Message should not be empty")
		}
	})

	t.Run("NewChallengeTimeoutError", func(t *testing.T) {
		err := types.NewChallengeTimeoutError("https://slow.example.com")

		if err.Type != "timeout" {
			t.Errorf("Type = %q, want %q", err.Type, "timeout")
		}
		if err.URL != "https://slow.example.com" {
			t.Errorf("URL = %q, want %q", err.URL, "https://slow.example.com")
		}
		if err.Err != types.ErrChallengeTimeout {
			t.Errorf("Err = %v, want %v", err.Err, types.ErrChallengeTimeout)
		}
	})

	t.Run("NewUnsolvableChallengeError", func(t *testing.T) {
		err := types.NewUnsolvableChallengeError("https://captcha.example.com", "CAPTCHA required")

		if err.Type != "unsolvable" {
			t.Errorf("Type = %q, want %q", err.Type, "unsolvable")
		}
		if err.URL != "https://captcha.example.com" {
			t.Errorf("URL = %q, want %q", err.URL, "https://captcha.example.com")
		}
		if err.Err != types.ErrChallengeUnsolvable {
			t.Errorf("Err = %v, want %v", err.Err, types.ErrChallengeUnsolvable)
		}
		if err.Message == "" {
			t.Error("Message should not be empty")
		}
		// Message should contain the reason
		if !contains(err.Message, "CAPTCHA required") {
			t.Errorf("Message should contain reason, got %q", err.Message)
		}
	})

	t.Run("NewPoolAcquireError", func(t *testing.T) {
		err := types.NewPoolAcquireError("all browsers busy", types.ErrBrowserPoolExhausted)

		if err.Operation != "acquire" {
			t.Errorf("Operation = %q, want %q", err.Operation, "acquire")
		}
		if err.Err != types.ErrBrowserPoolExhausted {
			t.Errorf("Err = %v, want %v", err.Err, types.ErrBrowserPoolExhausted)
		}
		if err.Message == "" {
			t.Error("Message should not be empty")
		}
	})
}

// TestSentinelErrors tests that sentinel errors are defined correctly.
func TestSentinelErrors(t *testing.T) {
	// Browser pool errors
	sentinelErrors := []struct {
		name string
		err  error
	}{
		{"ErrBrowserPoolExhausted", types.ErrBrowserPoolExhausted},
		{"ErrBrowserPoolClosed", types.ErrBrowserPoolClosed},
		{"ErrBrowserPoolTimeout", types.ErrBrowserPoolTimeout},
		{"ErrBrowserUnhealthy", types.ErrBrowserUnhealthy},
		{"ErrBrowserCrashed", types.ErrBrowserCrashed},
		{"ErrSessionNotFound", types.ErrSessionNotFound},
		{"ErrSessionAlreadyExists", types.ErrSessionAlreadyExists},
		{"ErrSessionExpired", types.ErrSessionExpired},
		{"ErrTooManySessions", types.ErrTooManySessions},
		{"ErrSessionPageNil", types.ErrSessionPageNil},
		{"ErrAccessDenied", types.ErrAccessDenied},
		{"ErrChallengeTimeout", types.ErrChallengeTimeout},
		{"ErrChallengeUnsolvable", types.ErrChallengeUnsolvable},
		{"ErrTurnstileFailed", types.ErrTurnstileFailed},
		{"ErrInvalidRequest", types.ErrInvalidRequest},
		{"ErrInvalidURL", types.ErrInvalidURL},
		{"ErrInvalidCommand", types.ErrInvalidCommand},
		{"ErrURLRequired", types.ErrURLRequired},
		{"ErrPostDataRequired", types.ErrPostDataRequired},
		{"ErrContextCanceled", types.ErrContextCanceled},
	}

	for _, tc := range sentinelErrors {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Errorf("%s should not be nil", tc.name)
			}
			if tc.err.Error() == "" {
				t.Errorf("%s.Error() should not be empty", tc.name)
			}
		})
	}
}

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
