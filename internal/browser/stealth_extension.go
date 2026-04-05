// Package browser provides browser management functionality.
package browser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// StealthExtension creates a Chrome extension that injects stealth patches
// into pages without requiring a CDP connection. This is used by the two-phase
// CDP bypass to apply anti-detection measures during Phase 1 (clean Chrome launch).
//
// The extension uses Manifest V3 content_scripts with "world": "MAIN" to run
// stealth JavaScript in the page's context at document_start — equivalent to
// Page.addScriptToEvaluateOnNewDocument but without CDP.
type StealthExtension struct {
	dir string
}

// NewStealthExtension creates a new stealth extension in a temporary directory.
// The extension contains the same stealth patches from stealthScript (stealth.go)
// packaged as a Chrome content script.
func NewStealthExtension() (*StealthExtension, error) {
	dir, err := os.MkdirTemp("", "flaresolverr-stealth-ext-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for stealth extension: %w", err)
	}

	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to set directory permissions: %w", err)
	}

	ext := &StealthExtension{dir: dir}

	if err := ext.createManifest(); err != nil {
		ext.Cleanup()
		return nil, err
	}
	if err := ext.createStealthScript(); err != nil {
		ext.Cleanup()
		return nil, err
	}
	if err := ext.createBehaviorScript(); err != nil {
		ext.Cleanup()
		return nil, err
	}

	return ext, nil
}

// Dir returns the extension directory path.
func (e *StealthExtension) Dir() string {
	return e.dir
}

// Cleanup removes the extension directory.
func (e *StealthExtension) Cleanup() {
	if e.dir != "" {
		os.RemoveAll(e.dir)
	}
}

// createManifest writes the Manifest V3 manifest.json.
func (e *StealthExtension) createManifest() error {
	manifest := map[string]interface{}{
		"manifest_version": 3,
		"name":             "Stealth",
		"version":          "1.0",
		"content_scripts": []map[string]interface{}{
			{
				"matches":    []string{"<all_urls>"},
				"js":         []string{"stealth.js"},
				"run_at":     "document_start",
				"all_frames": true,
				"world":      "MAIN",
			},
			{
				"matches":    []string{"<all_urls>"},
				"js":         []string{"behavior.js"},
				"run_at":     "document_idle",
				"all_frames": false,
				"world":      "MAIN",
			},
		},
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	path := filepath.Join(e.dir, "manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write manifest.json: %w", err)
	}

	return nil
}

// createStealthScript writes the stealth JavaScript as a content script.
// Uses the same stealthScript constant from stealth.go.
func (e *StealthExtension) createStealthScript() error {
	path := filepath.Join(e.dir, "stealth.js")
	if err := os.WriteFile(path, []byte(stealthScript), 0600); err != nil {
		return fmt.Errorf("failed to write stealth.js: %w", err)
	}
	return nil
}

// behaviorScript simulates human-like behavior on pages.
// This runs at document_idle (after page load) and generates:
// - Natural mouse movements with Bezier curves and jitter
// - Occasional micro-scrolls
// - Proper focus/visibility state
// - requestAnimationFrame timing noise
//
// Events dispatched via JS have isTrusted:false, but the presence of
// mouse coordinates and movement patterns in the event stream is still
// valuable — CF checks both whether events exist AND their properties.
const behaviorScript = `
(() => {
    'use strict';
    if (window.__behaviorApplied) return;
    window.__behaviorApplied = true;

    // Only run on top-level frame
    if (window !== window.top) return;

    // ========================================
    // 1. Ensure proper focus/visibility state
    // ========================================
    // Headless browsers may start without focus. Ensure document.hasFocus()
    // returns true and visibilityState is "visible".
    try {
        if (!document.hasFocus()) {
            window.focus();
        }
        Object.defineProperty(document, 'visibilityState', {
            get: () => 'visible',
            configurable: true
        });
        Object.defineProperty(document, 'hidden', {
            get: () => false,
            configurable: true
        });
    } catch (e) {}

    // ========================================
    // 2. Simulate idle mouse movements
    // ========================================
    // A real user waiting for a page to load has subtle mouse drift.
    // We generate natural-looking movements using Bezier interpolation
    // with random timing (200-2000ms between movements).
    let mouseX = 400 + Math.random() * 600;  // Start somewhere mid-page
    let mouseY = 300 + Math.random() * 300;

    function bezierPoint(t, p0, p1, p2, p3) {
        const mt = 1 - t;
        return mt*mt*mt*p0 + 3*mt*mt*t*p1 + 3*mt*t*t*p2 + t*t*t*p3;
    }

    function simulateMouseMove() {
        // Random target with small drift (idle movement, not navigation)
        const targetX = mouseX + (Math.random() - 0.5) * 120;
        const targetY = mouseY + (Math.random() - 0.5) * 80;

        // Bezier control points for natural curve
        const cx1 = mouseX + (Math.random() - 0.5) * 40;
        const cy1 = mouseY + (Math.random() - 0.5) * 40;
        const cx2 = targetX + (Math.random() - 0.5) * 40;
        const cy2 = targetY + (Math.random() - 0.5) * 40;

        const steps = 5 + Math.floor(Math.random() * 8);
        let step = 0;

        function moveStep() {
            if (step >= steps) {
                mouseX = targetX;
                mouseY = targetY;
                // Schedule next movement (200-3000ms idle gap)
                setTimeout(simulateMouseMove, 200 + Math.random() * 2800);
                return;
            }

            const t = step / steps;
            const x = bezierPoint(t, mouseX, cx1, cx2, targetX);
            const y = bezierPoint(t, mouseY, cy1, cy2, targetY);

            // Add micro-jitter (sub-pixel noise like a real mouse)
            const jitterX = (Math.random() - 0.5) * 2;
            const jitterY = (Math.random() - 0.5) * 2;

            try {
                const evt = new MouseEvent('mousemove', {
                    clientX: x + jitterX,
                    clientY: y + jitterY,
                    screenX: x + jitterX + (window.screenX || 100),
                    screenY: y + jitterY + (window.screenY || 80) + 85,
                    bubbles: true,
                    cancelable: true
                });
                document.dispatchEvent(evt);
            } catch (e) {}

            step++;
            // Human-like timing between move steps (8-25ms, mimicking real mouse polling)
            setTimeout(moveStep, 8 + Math.random() * 17);
        }

        moveStep();
    }

    // Start mouse simulation after a realistic delay (user has just loaded the page)
    setTimeout(simulateMouseMove, 800 + Math.random() * 1500);

    // ========================================
    // 3. Simulate occasional micro-scrolls
    // ========================================
    // A user waiting for a page might slightly scroll or their trackpad
    // might register micro-movements.
    function simulateMicroScroll() {
        try {
            const delta = (Math.random() - 0.5) * 30; // Small scroll amount
            const evt = new WheelEvent('wheel', {
                deltaY: delta,
                deltaX: 0,
                deltaMode: 0, // DOM_DELTA_PIXEL
                bubbles: true,
                cancelable: true
            });
            document.dispatchEvent(evt);
        } catch (e) {}

        // Next micro-scroll in 3-8 seconds
        setTimeout(simulateMicroScroll, 3000 + Math.random() * 5000);
    }

    setTimeout(simulateMicroScroll, 2000 + Math.random() * 3000);

    // ========================================
    // 4. requestAnimationFrame timing noise
    // ========================================
    // CF checks rAF timing consistency. We inject slight timing variation
    // by occasionally adding artificial delays to the event loop.
    // This makes the rAF frame deltas look more like a real browser with
    // background activity (GC pauses, layout recalc, etc.)
    function addTimingNoise() {
        // Occasionally block the main thread for 1-5ms to simulate
        // realistic GC pauses and layout recalculations
        if (Math.random() < 0.1) { // 10% chance per call
            const start = performance.now();
            const blockTime = 1 + Math.random() * 4;
            while (performance.now() - start < blockTime) {
                // Busy-wait to create a natural "long frame"
            }
        }
        setTimeout(addTimingNoise, 100 + Math.random() * 200);
    }

    setTimeout(addTimingNoise, 500 + Math.random() * 1000);

    // ========================================
    // 5. Simulate tab focus/blur cycle
    // ========================================
    // A real user might briefly tab away and come back.
    // Fire a blur then focus event after a realistic delay.
    setTimeout(() => {
        try {
            window.dispatchEvent(new Event('blur'));
            document.dispatchEvent(new Event('visibilitychange'));
        } catch (e) {}

        // "Return" to the tab after 1-3 seconds
        setTimeout(() => {
            try {
                window.dispatchEvent(new Event('focus'));
                document.dispatchEvent(new Event('visibilitychange'));
            } catch (e) {}
        }, 1000 + Math.random() * 2000);
    }, 5000 + Math.random() * 5000);

})();
`

// createBehaviorScript writes the human behavior simulation script.
func (e *StealthExtension) createBehaviorScript() error {
	path := filepath.Join(e.dir, "behavior.js")
	if err := os.WriteFile(path, []byte(behaviorScript), 0600); err != nil {
		return fmt.Errorf("failed to write behavior.js: %w", err)
	}
	return nil
}
