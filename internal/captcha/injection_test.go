package captcha

import (
	"context"
	"testing"
)

func TestInjectTurnstileToken_EmptyToken(t *testing.T) {
	err := InjectTurnstileToken(context.Background(), nil, "")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestInjectTurnstileToken_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := InjectTurnstileToken(ctx, nil, "test-token")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// Note: Full injection tests require a browser page mock
// which would need a test browser setup. These are covered
// by integration tests.
