package selectors

import (
	"testing"
)

func TestGetSelectors(t *testing.T) {
	sel := Get()

	if sel == nil {
		t.Fatal("Get() returned nil")
	}

	// Verify access denied patterns
	if len(sel.AccessDenied) == 0 {
		t.Error("Expected access denied patterns")
	}

	// Verify turnstile patterns
	if len(sel.Turnstile) == 0 {
		t.Error("Expected turnstile patterns")
	}

	// Verify JavaScript patterns
	if len(sel.JavaScript) == 0 {
		t.Error("Expected JavaScript patterns")
	}

	// Verify turnstile selectors
	if len(sel.TurnstileSelectors) == 0 {
		t.Error("Expected turnstile selectors")
	}

	// Verify turnstile frame pattern
	if sel.TurnstileFramePattern == "" {
		t.Error("Expected turnstile frame pattern")
	}
}

func TestGetSelectorsSingleton(t *testing.T) {
	sel1 := Get()
	sel2 := Get()

	if sel1 != sel2 {
		t.Error("Expected Get() to return the same instance")
	}
}

func TestDefaultSelectors(t *testing.T) {
	sel := defaultSelectors()

	// Verify all patterns are populated
	expectedAccessDenied := []string{
		"access denied",
		"error 1015",
		"error 1012",
		"error 1020",
		"you have been blocked",
		"ray id:",
	}
	if len(sel.AccessDenied) != len(expectedAccessDenied) {
		t.Errorf("Expected %d access denied patterns, got %d", len(expectedAccessDenied), len(sel.AccessDenied))
	}

	expectedTurnstile := []string{
		"cf-turnstile",
		"challenges.cloudflare.com/turnstile",
		"turnstile-wrapper",
	}
	if len(sel.Turnstile) != len(expectedTurnstile) {
		t.Errorf("Expected %d turnstile patterns, got %d", len(expectedTurnstile), len(sel.Turnstile))
	}

	expectedJS := []string{
		"just a moment",
		"checking your browser",
		"please wait",
		"ddos-guard",
		"__cf_chl_opt",
		"_cf_chl_opt",
		"cf-challenge",
		"cf_chl_prog",
	}
	if len(sel.JavaScript) != len(expectedJS) {
		t.Errorf("Expected %d JavaScript patterns, got %d", len(expectedJS), len(sel.JavaScript))
	}

	if sel.TurnstileFramePattern != "challenges.cloudflare.com" {
		t.Errorf("Unexpected turnstile frame pattern: %s", sel.TurnstileFramePattern)
	}
}

func TestSelectorsContainExpectedPatterns(t *testing.T) {
	sel := Get()

	// Check for specific expected patterns
	expectedPatterns := map[string][]string{
		"access_denied": {"access denied", "error 1020"},
		"turnstile":     {"cf-turnstile"},
		"javascript":    {"just a moment", "checking your browser"},
	}

	for category, patterns := range expectedPatterns {
		var list []string
		switch category {
		case "access_denied":
			list = sel.AccessDenied
		case "turnstile":
			list = sel.Turnstile
		case "javascript":
			list = sel.JavaScript
		}

		for _, expected := range patterns {
			found := false
			for _, p := range list {
				if p == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected pattern %q not found in %s", expected, category)
			}
		}
	}
}
