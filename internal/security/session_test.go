package security

import (
	"testing"
)

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error: %v", err)
	}

	if len(id1) != 48 { // 24 bytes = 48 hex chars
		t.Errorf("Expected 48 char session ID, got %d", len(id1))
	}

	// Generate another and ensure they're different
	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error: %v", err)
	}

	if id1 == id2 {
		t.Error("Generated session IDs should be unique")
	}
}

func TestValidateSessionID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		// Valid cases - now require at least 16 characters
		{"valid 16 chars", "my-session-12345", false},
		{"valid with numbers", "session123456789", false},
		{"valid with underscore", "my_session_12345", false},
		{"valid UUID-like", "550e8400-e29b-41d4-a716-446655440000", false},

		// Invalid cases
		{"empty", "", true},
		{"too short 10 chars", "my-session", true}, // Now too short (was valid before)
		{"too short 15 chars", "session1234567", true},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true}, // 65 chars
		{"contains space", "my session 12345", true},
		{"contains slash", "my/session/12345", true},
		{"contains dot", "my.session.12345", true},
		{"path traversal", "../etc/passwd", true},
		{"script injection", "<script>alert(1)</script>", true},
		{"proto pollution", "__proto__session1", true},
		{"constructor attack", "constructor12345", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSessionID(tt.id)
			if (err != "") != tt.wantErr {
				t.Errorf("ValidateSessionID(%q) = %q, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}
