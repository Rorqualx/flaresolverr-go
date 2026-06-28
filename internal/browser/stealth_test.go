package browser

import (
	"strings"
	"testing"
)

// TestGate2CorrectionsScriptContent guards the two evidence-backed gate-2 fixes
// (docs/INVESTIGATION-fingerprint-gate2.md): a Linux-consistent WebGL renderer
// and a coherent screen/window geometry override. A regression here silently
// reintroduces the macOS-renderer / impossible-screen bot tells.
func TestGate2CorrectionsScriptContent(t *testing.T) {
	mustContain := []string{
		"WebGLRenderingContext",
		"WebGL2RenderingContext",
		"ANGLE (Intel",        // Linux ANGLE renderer
		"Google Inc. (Intel)", // Linux ANGLE vendor
		"availWidth",
		"availHeight",
		"outerWidth",
		"outerHeight",
		"window.innerWidth",
		"__gate2Applied", // idempotency guard
	}
	for _, s := range mustContain {
		if !strings.Contains(gate2CorrectionsScript, s) {
			t.Errorf("gate2CorrectionsScript missing expected fragment %q", s)
		}
	}

	// The macOS WebGL renderer string is the exact tell we override away from.
	if strings.Contains(gate2CorrectionsScript, "Intel Iris OpenGL Engine") {
		t.Error("gate2CorrectionsScript must NOT contain the macOS WebGL renderer string")
	}
}

// TestGate2CorrectionsScriptBalanced is a cheap syntax sanity check: the injected
// JS must have balanced braces, parens and brackets or it fails at document_start.
func TestGate2CorrectionsScriptBalanced(t *testing.T) {
	pairs := map[rune]rune{'}': '{', ')': '(', ']': '['}
	counts := map[rune]int{}
	for _, c := range gate2CorrectionsScript {
		switch c {
		case '{', '(', '[':
			counts[c]++
		case '}', ')', ']':
			counts[pairs[c]]--
		}
	}
	for open, n := range counts {
		if n != 0 {
			t.Errorf("unbalanced %q in gate2CorrectionsScript: net %d", open, n)
		}
	}
}
