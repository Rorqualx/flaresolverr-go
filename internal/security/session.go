package security

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

// Session ID constraints
const (
	// MinSessionIDLength requires at least 16 characters for adequate entropy
	// 16 hex characters = 64 bits of entropy, providing strong collision resistance
	MinSessionIDLength = 16
	MaxSessionIDLength = 64
)

// validSessionIDPattern allows alphanumeric, hyphens, and underscores
var validSessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// blockedSessionPatterns contains patterns that are blocked in session IDs for security.
// Cached at package level to avoid allocation on every ValidateSessionID call.
var blockedSessionPatterns = []string{
	"../",
	"..\\",
	"<script",
	"javascript:",
	"__proto__",
	"constructor",
}

// GenerateSessionID creates a cryptographically secure random session ID.
// Uses 24 bytes (192 bits) for strong uniqueness.
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateSessionID checks if a session ID is valid and safe.
// Returns an error message if invalid, empty string if valid.
func ValidateSessionID(id string) string {
	if id == "" {
		return "session ID is required"
	}

	if len(id) < MinSessionIDLength {
		return "session ID too short (min 16 characters)"
	}

	if len(id) > MaxSessionIDLength {
		return "session ID too long (max 64 characters)"
	}

	if !validSessionIDPattern.MatchString(id) {
		return "session ID contains invalid characters (use alphanumeric, hyphens, underscores only)"
	}

	// Block potentially dangerous patterns using cached patterns
	idLower := strings.ToLower(id)
	for _, pattern := range blockedSessionPatterns {
		if strings.Contains(idLower, pattern) {
			return "session ID contains blocked pattern"
		}
	}

	return ""
}
