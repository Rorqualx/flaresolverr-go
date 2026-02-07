// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"fmt"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// ExtractTurnstileSitekey extracts the Turnstile sitekey from a page.
// It tries multiple methods to find the sitekey attribute.
func ExtractTurnstileSitekey(page *rod.Page) (string, error) {
	// Method 1: Try JavaScript evaluation for comprehensive extraction
	sitekey, err := extractSitekeyJS(page)
	if err == nil && sitekey != "" {
		log.Debug().Str("method", "js").Msg("Extracted sitekey via JavaScript")
		return sitekey, nil
	}

	// Method 2: Try DOM element queries
	sitekey, err = extractSitekeyDOM(page)
	if err == nil && sitekey != "" {
		log.Debug().Str("method", "dom").Msg("Extracted sitekey via DOM query")
		return sitekey, nil
	}

	// Method 3: Try iframe src attribute
	sitekey, err = extractSitekeyIframe(page)
	if err == nil && sitekey != "" {
		log.Debug().Str("method", "iframe").Msg("Extracted sitekey from iframe")
		return sitekey, nil
	}

	return "", types.ErrCaptchaSitekeyNotFound
}

// extractSitekeyJS uses JavaScript to find the sitekey from various sources.
func extractSitekeyJS(page *rod.Page) (string, error) {
	js := `
	(function() {
		// Method 1: Look for data-sitekey attribute on Turnstile elements
		var selectors = [
			'.cf-turnstile[data-sitekey]',
			'[data-sitekey]',
			'div[data-sitekey]',
			'#turnstile-wrapper [data-sitekey]',
			'.turnstile-widget[data-sitekey]'
		];

		for (var i = 0; i < selectors.length; i++) {
			var el = document.querySelector(selectors[i]);
			if (el) {
				var sitekey = el.getAttribute('data-sitekey');
				if (sitekey && sitekey.length > 10) {
					return sitekey;
				}
			}
		}

		// Method 2: Look for sitekey in Turnstile script initialization
		var scripts = document.querySelectorAll('script');
		for (var i = 0; i < scripts.length; i++) {
			var text = scripts[i].textContent || '';
			// Match patterns like: turnstile.render(..., {sitekey: '...'})
			var match = text.match(/sitekey['":\s]+['"]([0-9a-zA-Z_-]+)['"]/);
			if (match && match[1] && match[1].length > 10) {
				return match[1];
			}
		}

		// Method 3: Look for Cloudflare challenge data
		var cfData = document.querySelector('[data-cf-settings]');
		if (cfData) {
			var settings = cfData.getAttribute('data-cf-settings');
			if (settings) {
				try {
					var parsed = JSON.parse(settings);
					if (parsed.sitekey) return parsed.sitekey;
				} catch(e) {}
			}
		}

		// Method 4: Check for turnstile in window object
		if (window.turnstile && window.__TURNSTILE_SITE_KEY__) {
			return window.__TURNSTILE_SITE_KEY__;
		}

		return '';
	})()
	`

	result, err := proto.RuntimeEvaluate{
		Expression:    js,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		return "", fmt.Errorf("js evaluation failed: %w", err)
	}

	if result == nil || result.Result == nil {
		return "", fmt.Errorf("empty result from js evaluation")
	}

	if result.ExceptionDetails != nil {
		return "", fmt.Errorf("js exception: %s", result.ExceptionDetails.Text)
	}

	sitekey := result.Result.Value.Str()
	if sitekey == "" {
		return "", fmt.Errorf("no sitekey found via js")
	}

	return sitekey, nil
}

// extractSitekeyDOM queries DOM elements directly to find sitekey.
func extractSitekeyDOM(page *rod.Page) (string, error) {
	selectors := []string{
		".cf-turnstile",
		"[data-sitekey]",
		"#turnstile-wrapper",
		".turnstile-widget",
	}

	for _, selector := range selectors {
		has, _, _ := page.Has(selector)
		if !has {
			continue
		}

		el, err := page.Element(selector)
		if err != nil {
			continue
		}

		sitekey, err := el.Attribute("data-sitekey")
		if err == nil && sitekey != nil && *sitekey != "" {
			if err := el.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release element")
			}
			return *sitekey, nil
		}

		if err := el.Release(); err != nil {
			log.Debug().Err(err).Msg("Failed to release element")
		}
	}

	return "", fmt.Errorf("no sitekey found in DOM elements")
}

// extractSitekeyIframe extracts sitekey from Turnstile iframe src URL.
func extractSitekeyIframe(page *rod.Page) (string, error) {
	iframes, err := page.Elements("iframe")
	if err != nil {
		return "", fmt.Errorf("failed to get iframes: %w", err)
	}

	defer func() {
		for _, iframe := range iframes {
			if err := iframe.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release iframe")
			}
		}
	}()

	for _, iframe := range iframes {
		src, err := iframe.Attribute("src")
		if err != nil || src == nil {
			continue
		}

		// Turnstile iframes have sitekey in the URL
		// Format: https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov2/av0/sitekey/...
		if containsTurnstilePattern(*src) {
			// Try to extract sitekey from iframe URL
			sitekey := extractSitekeyFromURL(*src)
			if sitekey != "" {
				return sitekey, nil
			}
		}
	}

	return "", fmt.Errorf("no sitekey found in iframes")
}

// containsTurnstilePattern checks if URL contains Turnstile iframe pattern.
func containsTurnstilePattern(url string) bool {
	patterns := []string{
		"challenges.cloudflare.com",
		"turnstile",
		"cf-turnstile",
	}

	for _, pattern := range patterns {
		if containsSubstring(url, pattern) {
			return true
		}
	}
	return false
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

// findSubstring finds the index of substr in s, or -1 if not found.
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// extractSitekeyFromURL tries to extract sitekey from a Turnstile iframe URL.
func extractSitekeyFromURL(url string) string {
	// Common patterns in Turnstile iframe URLs:
	// - /sitekey/0x... in path
	// - sitekey=0x... in query string

	// Pattern 1: /sitekey/ followed by the key
	sitekeyPrefix := "/sitekey/"
	idx := findSubstring(url, sitekeyPrefix)
	if idx >= 0 {
		start := idx + len(sitekeyPrefix)
		end := start
		for end < len(url) && url[end] != '/' && url[end] != '?' && url[end] != '&' {
			end++
		}
		if end > start {
			return url[start:end]
		}
	}

	// Pattern 2: sitekey= in query string
	queryPrefix := "sitekey="
	idx = findSubstring(url, queryPrefix)
	if idx >= 0 {
		start := idx + len(queryPrefix)
		end := start
		for end < len(url) && url[end] != '&' && url[end] != '#' {
			end++
		}
		if end > start {
			return url[start:end]
		}
	}

	return ""
}

// ExtractTurnstileAction extracts the optional action parameter from the page.
func ExtractTurnstileAction(page *rod.Page) string {
	js := `
	(function() {
		var el = document.querySelector('[data-action]');
		if (el) {
			return el.getAttribute('data-action');
		}
		var cf = document.querySelector('.cf-turnstile[data-action]');
		if (cf) {
			return cf.getAttribute('data-action');
		}
		return '';
	})()
	`

	result, err := proto.RuntimeEvaluate{
		Expression:    js,
		ReturnByValue: true,
	}.Call(page)

	if err != nil || result == nil || result.Result == nil {
		return ""
	}

	return result.Result.Value.Str()
}

// ExtractTurnstileCData extracts the optional cData parameter from the page.
func ExtractTurnstileCData(page *rod.Page) string {
	js := `
	(function() {
		var el = document.querySelector('[data-cdata]');
		if (el) {
			return el.getAttribute('data-cdata');
		}
		var cf = document.querySelector('.cf-turnstile[data-cdata]');
		if (cf) {
			return cf.getAttribute('data-cdata');
		}
		return '';
	})()
	`

	result, err := proto.RuntimeEvaluate{
		Expression:    js,
		ReturnByValue: true,
	}.Call(page)

	if err != nil || result == nil || result.Result == nil {
		return ""
	}

	return result.Result.Value.Str()
}
