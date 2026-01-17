// Package types provides shared types, interfaces, and errors for the application.
package types

import "errors"

// Sentinel errors for consistent error handling across the application.
// These errors can be checked with errors.Is() for type-safe error handling.
var (
	// Browser pool errors
	ErrBrowserPoolExhausted = errors.New("browser pool exhausted: no browsers available")
	ErrBrowserPoolClosed    = errors.New("browser pool is closed")
	ErrBrowserPoolTimeout   = errors.New("timeout waiting for browser from pool")
	ErrBrowserUnhealthy     = errors.New("browser is unhealthy")
	ErrBrowserCrashed       = errors.New("browser process crashed")

	// Session errors
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionAlreadyExists = errors.New("session already exists")
	ErrSessionExpired       = errors.New("session has expired")
	ErrTooManySessions      = errors.New("maximum number of sessions reached")
	ErrSessionPageNil       = errors.New("session page is nil or has been closed")

	// Challenge errors
	ErrAccessDenied        = errors.New("access denied by target site")
	ErrChallengeTimeout    = errors.New("challenge resolution timed out")
	ErrChallengeUnsolvable = errors.New("challenge could not be solved")
	ErrTurnstileFailed     = errors.New("turnstile verification failed")

	// Request errors
	ErrInvalidRequest   = errors.New("invalid request")
	ErrInvalidURL       = errors.New("invalid URL")
	ErrInvalidCommand   = errors.New("invalid command")
	ErrURLRequired      = errors.New("url is required")
	ErrPostDataRequired = errors.New("postData is required for POST requests")

	// Context errors
	ErrContextCanceled = errors.New("operation canceled")
)

// ChallengeError provides detailed information about challenge failures.
// It implements the error interface and supports error unwrapping.
type ChallengeError struct {
	Type    string // Error type: "access_denied", "timeout", "unsolvable"
	URL     string // The URL where the error occurred
	Message string // Human-readable error message
	Err     error  // Underlying error (for unwrapping)
}

// Error implements the error interface.
func (e *ChallengeError) Error() string {
	return e.Message
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *ChallengeError) Unwrap() error {
	return e.Err
}

// NewAccessDeniedError creates an error for access denied situations.
func NewAccessDeniedError(url string) *ChallengeError {
	return &ChallengeError{
		Type:    "access_denied",
		URL:     url,
		Message: "Access denied. The target site has blocked this request. Your IP may be banned or the site requires specific conditions.",
		Err:     ErrAccessDenied,
	}
}

// NewChallengeTimeoutError creates an error for challenge timeout.
func NewChallengeTimeoutError(url string) *ChallengeError {
	return &ChallengeError{
		Type:    "timeout",
		URL:     url,
		Message: "Challenge resolution timed out. The challenge could not be solved within the allowed time.",
		Err:     ErrChallengeTimeout,
	}
}

// NewUnsolvableChallengeError creates an error for unsolvable challenges.
func NewUnsolvableChallengeError(url string, reason string) *ChallengeError {
	return &ChallengeError{
		Type:    "unsolvable",
		URL:     url,
		Message: "Challenge could not be solved: " + reason,
		Err:     ErrChallengeUnsolvable,
	}
}

// PoolError provides detailed information about browser pool failures.
type PoolError struct {
	Operation string // The operation that failed
	Message   string // Human-readable error message
	Err       error  // Underlying error
}

// Error implements the error interface.
func (e *PoolError) Error() string {
	return e.Message
}

// Unwrap returns the underlying error.
func (e *PoolError) Unwrap() error {
	return e.Err
}

// NewPoolAcquireError creates an error for pool acquire failures.
func NewPoolAcquireError(reason string, err error) *PoolError {
	return &PoolError{
		Operation: "acquire",
		Message:   "Failed to acquire browser from pool: " + reason,
		Err:       err,
	}
}
