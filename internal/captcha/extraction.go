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

	// Method 3: Try iframe src attribute (light DOM only)
	sitekey, err = extractSitekeyIframe(page)
	if err == nil && sitekey != "" {
		log.Debug().Str("method", "iframe").Msg("Extracted sitekey from iframe")
		return sitekey, nil
	}

	// Method 4: Pierce shadow roots and nested frames. Cloudflare *managed*
	// challenges render the Turnstile iframe inside a shadow root, so it is
	// invisible to light-DOM querySelector/Elements. Walk the flattened DOM tree
	// to find the challenges.cloudflare.com iframe URL and parse the sitekey.
	sitekey, err = extractSitekeyViaPierce(page)
	if err == nil && sitekey != "" {
		log.Debug().Str("method", "pierce").Msg("Extracted sitekey via shadow-DOM pierce")
		return sitekey, nil
	}

	return "", types.ErrCaptchaSitekeyNotFound
}

// extractSitekeyViaPierce walks the entire DOM tree (including closed shadow
// roots and nested iframe documents) looking for the Cloudflare Turnstile
// challenge iframe, and parses the sitekey out of its URL. This is the reliable
// path for managed challenges where the widget lives inside a shadow root.
func extractSitekeyViaPierce(page *rod.Page) (string, error) {
	depth := -1
	result, err := proto.DOMGetDocument{
		Depth:  &depth,
		Pierce: true,
	}.Call(page)
	if err != nil {
		return "", fmt.Errorf("failed to get pierced DOM tree: %w", err)
	}
	if result == nil || result.Root == nil {
		return "", fmt.Errorf("pierced DOM tree is empty")
	}

	const maxNodes = 50000
	visited := 0
	found := ""

	var walk func(node *proto.DOMNode)
	walk = func(node *proto.DOMNode) {
		if node == nil || found != "" {
			return
		}
		visited++
		if visited > maxNodes {
			return
		}

		// Attributes is a flat [name, value, name, value, ...] slice. Any value
		// that is a turnstile challenge URL carries the sitekey.
		for i := 0; i+1 < len(node.Attributes); i += 2 {
			val := node.Attributes[i+1]
			if containsTurnstilePattern(val) {
				if key := extractSitekeyFromURL(val); key != "" {
					found = key
					return
				}
			}
		}

		for _, shadow := range node.ShadowRoots {
			walk(shadow)
			if found != "" {
				return
			}
		}
		if node.ContentDocument != nil {
			walk(node.ContentDocument)
			if found != "" {
				return
			}
		}
		if node.TemplateContent != nil {
			walk(node.TemplateContent)
			if found != "" {
				return
			}
		}
		for _, child := range node.Children {
			walk(child)
			if found != "" {
				return
			}
		}
	}

	walk(result.Root)

	if found == "" {
		return "", fmt.Errorf("no turnstile sitekey found via pierce (nodes_visited=%d)", visited)
	}
	return found, nil
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

	// Pattern 3: Cloudflare *managed challenge* iframes embed the sitekey as a bare
	// path segment rather than after /sitekey/ or sitekey=, e.g.
	//   .../turnstile/f/ov2/av0/rch/<token>/0x4AAAAAAADnPIDROrmt1Wwj/light/...
	// Turnstile sitekeys are always "0x" followed by base62 characters, so match
	// the longest such run. Only trusted because the caller already verified the
	// URL belongs to challenges.cloudflare.com (containsTurnstilePattern).
	if key := findTurnstileSitekeyToken(url); key != "" {
		return key
	}

	return ""
}

// findTurnstileSitekeyToken scans s for a Cloudflare Turnstile sitekey token of
// the form "0x" + base62, length-bounded to avoid matching unrelated hex blobs.
func findTurnstileSitekeyToken(s string) string {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '0' || (s[i+1] != 'x' && s[i+1] != 'X') {
			continue
		}
		end := i + 2
		for end < len(s) && isSitekeyChar(s[end]) {
			end++
		}
		// Real sitekeys are ~24 chars ("0x" + 22). Require a sane minimum to
		// reject things like "0x0" or short hex fragments.
		if end-i >= 18 {
			return s[i:end]
		}
	}
	return ""
}

// isSitekeyChar reports whether c is valid inside a Turnstile sitekey body.
func isSitekeyChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
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

// ExtractHCaptchaSitekey extracts the hCaptcha sitekey from a page.
// It looks for the data-sitekey attribute on hCaptcha elements and iframes.
func ExtractHCaptchaSitekey(page *rod.Page) (string, error) {
	js := `
	(function() {
		// hCaptcha elements with data-sitekey
		var selectors = [
			'.h-captcha[data-sitekey]',
			'[data-hcaptcha-widget-id][data-sitekey]',
			'div.h-captcha[data-sitekey]'
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

		// Check for hCaptcha in script initialization
		var scripts = document.querySelectorAll('script');
		for (var i = 0; i < scripts.length; i++) {
			var text = scripts[i].textContent || '';
			var match = text.match(/hcaptcha\.render\([^,]*,\s*\{[^}]*sitekey['":\s]+['"]([0-9a-f-]+)['"]/);
			if (match && match[1]) {
				return match[1];
			}
		}

		// Check for hCaptcha in iframe src
		var iframes = document.querySelectorAll('iframe');
		for (var i = 0; i < iframes.length; i++) {
			var src = iframes[i].src || '';
			if (src.indexOf('hcaptcha.com') !== -1) {
				var match = src.match(/sitekey=([0-9a-f-]+)/);
				if (match && match[1]) {
					return match[1];
				}
			}
		}

		return '';
	})()
	`

	result, err := proto.RuntimeEvaluate{
		Expression:    js,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		return "", fmt.Errorf("hCaptcha js evaluation failed: %w", err)
	}

	if result == nil || result.Result == nil {
		return "", fmt.Errorf("empty result from hCaptcha js evaluation")
	}

	if result.ExceptionDetails != nil {
		return "", fmt.Errorf("js exception: %s", result.ExceptionDetails.Text)
	}

	sitekey := result.Result.Value.Str()
	if sitekey == "" {
		return "", types.ErrCaptchaSitekeyNotFound
	}

	return sitekey, nil
}
