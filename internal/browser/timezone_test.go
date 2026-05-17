package browser

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

func TestApplyTimezoneOverrideEmpty(t *testing.T) {
	// Empty timezone must be a no-op: it must not touch the *rod.Page argument,
	// so passing nil is safe and proves the early return is in place.
	if err := ApplyTimezoneOverride((*rod.Page)(nil), ""); err != nil {
		t.Errorf("expected nil error for empty timezone, got %v", err)
	}
}

func TestApplyTimezoneOverride(t *testing.T) {
	skipCI(t)

	pool, err := NewPool(testConfig())
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	brow, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	defer pool.Release(brow)

	page, err := brow.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	if err := ApplyTimezoneOverride(page, "Europe/Paris"); err != nil {
		t.Errorf("ApplyTimezoneOverride returned error: %v", err)
	}

	result, err := page.Eval("() => Intl.DateTimeFormat().resolvedOptions().timeZone")
	if err != nil {
		t.Fatalf("page eval failed: %v", err)
	}
	if got := result.Value.Str(); got != "Europe/Paris" {
		t.Errorf("expected timezone Europe/Paris, got %q", got)
	}
}
