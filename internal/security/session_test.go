package security

import (
	"testing"
)

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error: %v", err)
	}

	if len(id1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("Expected 32 char session ID, got %d", len(id1))
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
		{"valid simple", "my-session", false},
		{"valid with numbers", "session123", false},
		{"valid with underscore", "my_session_1", false},
		{"valid UUID-like", "550e8400-e29b-41d4-a716-446655440000", false},

		{"empty", "", true},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true}, // 65 chars
		{"contains space", "my session", true},
		{"contains slash", "my/session", true},
		{"contains dot", "my.session", true},
		{"path traversal", "../etc/passwd", true},
		{"script injection", "<script>alert(1)</script>", true},
		{"proto pollution", "__proto__", true},
		{"constructor attack", "constructor", true},
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
