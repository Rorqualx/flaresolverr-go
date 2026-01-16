package security

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

// Session ID constraints
const (
	MinSessionIDLength = 1
	MaxSessionIDLength = 64
)

// validSessionIDPattern allows alphanumeric, hyphens, and underscores
var validSessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// GenerateSessionID creates a cryptographically secure random session ID.
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateSessionID checks if a session ID is valid and safe.
// Returns an error message if invalid, empty string if valid.
func ValidateSessionID(id string) string {
	if len(id) < MinSessionIDLength {
		return "session ID is required"
	}

	if len(id) > MaxSessionIDLength {
		return "session ID too long (max 64 characters)"
	}

	if !validSessionIDPattern.MatchString(id) {
		return "session ID contains invalid characters (use alphanumeric, hyphens, underscores only)"
	}

	// Block potentially dangerous patterns
	idLower := strings.ToLower(id)
	blockedPatterns := []string{
		"../",
		"..\\",
		"<script",
		"javascript:",
		"__proto__",
		"constructor",
	}

	for _, pattern := range blockedPatterns {
		if strings.Contains(idLower, pattern) {
			return "session ID contains blocked pattern"
		}
	}

	return ""
}
